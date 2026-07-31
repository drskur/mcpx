const std = @import("std");

const Allocator = std.mem.Allocator;
const Io = std.Io;
const Value = std.json.Value;

const toml = @import("toml");
const client_module = @import("client.zig");
const cli = @import("cli.zig");
const oauth = @import("oauth.zig");
const rpc = @import("rpc.zig");
const skills = @import("skills.zig");
const protocol = @import("protocol.zig");
const diagnostics_out = @import("diagnostics.zig");
const McpClient = client_module.McpClient;
const Server = client_module.Server;
const Tool = client_module.Tool;

const Config = struct {
    http: []const Server = &.{},
};

pub fn main(init: std.process.Init) void {
    run(init) catch |err| {
        diagnostics_out.report("error: {s}\n", .{@errorName(err)});
        std.process.exit(exitCode(err));
    };
}

/// Distinct exit codes let scripts react to the failure class without parsing
/// the diagnostics on stderr.
fn exitCode(err: anyerror) u8 {
    const name = @errorName(err);
    if (std.mem.startsWith(u8, name, "Oauth")) return 3;
    if (std.mem.startsWith(u8, name, "Server") and !std.mem.eql(u8, name, "ServerDoesNotSupportTools")) return 2;
    return switch (err) {
        error.ConfigReadFailed,
        error.ConfigParseFailed,
        error.ConfigDuplicateServer,
        error.HomeNotSet,
        error.MissingConfigPath,
        error.UnknownCommand,
        error.UnknownOption,
        error.MissingArgument,
        error.TooManyArguments,
        error.ArgsNotValidJson,
        error.ArgsMustBeObject,
        error.ToolNotFound,
        => 2,
        error.HttpUnauthorized, error.HttpForbidden => 3,
        error.RequestTimedOut => 5,
        error.ToolExecutionFailed => 6,
        error.InputRequired => 7,
        error.JsonRpcError,
        error.MethodNotFound,
        error.InvalidJsonRpcResponse,
        error.InvalidJsonRpcVersion,
        error.InvalidJsonRpcError,
        error.ResponseIdMismatch,
        error.UnsupportedProtocolVersion,
        error.UnsupportedProtocolVersionError,
        error.ServerDoesNotSupportTools,
        => 4,
        else => 1,
    };
}

fn run(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);
    const parsed = try cli.parseArgs(args);
    if (parsed.help) {
        try cli.writeUsage(init.io);
        return;
    }
    const config_home = configHome(allocator, init.minimal.environ) catch return error.HomeNotSet;
    const path = if (parsed.config) |p| p else try std.fs.path.join(allocator, &.{ config_home, "mcpx/config.toml" });
    const raw = std.Io.Dir.cwd().readFileAlloc(init.io, path, allocator, .limited(16 * 1024 * 1024)) catch {
        diagnostics_out.report("cannot read config file: {s}\n", .{path});
        return error.ConfigReadFailed;
    };
    var parser = toml.Parser(Config).init(allocator);
    defer parser.deinit();
    var parsed_config = parser.parseString(raw) catch |err| {
        diagnostics_out.report("failed to parse config {s}: {s}\n", .{ path, @errorName(err) });
        return error.ConfigParseFailed;
    };
    defer parsed_config.deinit();
    const config = parsed_config.value;
    try validateConfig(config);
    const token_path = try std.fs.path.join(allocator, &.{ config_home, "mcpx/tokens.toml" });
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_file: Io.File.Writer = .init(.stdout(), init.io, &stdout_buffer);
    const out = &stdout_file.interface;
    const command_result = runCommand(allocator, init.io, parsed, config, token_path, out);
    out.flush() catch |err| {
        diagnostics_out.report("failed to flush stdout: {s}\n", .{@errorName(err)});
        return err;
    };
    return command_result;
}

/// Honors `XDG_CONFIG_HOME` and falls back to `$HOME/.config`.
fn configHome(allocator: Allocator, environ: anytype) ![]const u8 {
    if (environ.getAlloc(allocator, "XDG_CONFIG_HOME")) |value| {
        if (value.len != 0 and std.fs.path.isAbsolute(value)) return value;
    } else |_| {}
    const home = try environ.getAlloc(allocator, "HOME");
    return std.fs.path.join(allocator, &.{ home, ".config" });
}

fn validateConfig(config: Config) !void {
    for (config.http, 0..) |server, index| {
        server.validate() catch |err| {
            diagnostics_out.report("invalid server entry #{d} ('{s}'): {s}\n", .{ index + 1, server.name, @errorName(err) });
            return err;
        };
        for (config.http[0..index]) |earlier| if (std.mem.eql(u8, earlier.name, server.name)) {
            diagnostics_out.report("duplicate server name '{s}' in configuration\n", .{server.name});
            return error.ConfigDuplicateServer;
        };
    }
}

fn runCommand(allocator: Allocator, io: Io, parsed: cli.ParsedArgs, config: Config, token_path: []const u8, out: *Io.Writer) !void {
    if (std.mem.eql(u8, parsed.command, "servers")) {
        if (config.http.len == 0) return out.writeAll("no servers configured.\n");
        for (config.http) |s| try out.print("{s}\t{s}{s}\n", .{ s.name, s.endpoint, if (s.oauth != null) " [oauth]" else "" });
        return;
    }
    const server_name = parsed.positionals[0];
    const server = findServer(config, server_name) orelse {
        try printMissingServer(config, server_name);
        return error.ServerNotFound;
    };
    var client = McpClient.init(allocator, io, server, token_path);
    defer client.deinit();
    if (std.mem.eql(u8, parsed.command, "auth")) {
        try client.authenticate();
        try out.print("authenticated {s}\n", .{server.name});
        return;
    }
    // Arguments are validated before a connection is opened so that a typo in
    // the JSON fails immediately and without any network traffic.
    const call_args: ?Value = if (std.mem.eql(u8, parsed.command, "call")) blk: {
        const args_text = if (parsed.positionals_len > 2) parsed.positionals[2] else "{}";
        const value = std.json.parseFromSliceLeaky(Value, allocator, args_text, .{}) catch return error.ArgsNotValidJson;
        if (value != .object) return error.ArgsMustBeObject;
        break :blk value;
    } else null;
    try client.connect();

    if (call_args) |arguments| {
        var params = Value{ .object = .empty };
        try params.object.put(allocator, "name", .{ .string = parsed.positionals[1] });
        try params.object.put(allocator, "arguments", arguments);
        const outcome = client.rpcOutcome("tools/call", params) catch |err| return reportRpcFailure(&client, err);
        const result = switch (outcome) {
            .complete => |value| value,
            .input_required => |value| value,
        };
        try skills.prettyPrint(out, result);
        try out.flush();
        // A tool that reports failure must not look successful to a script.
        if (isToolError(result)) return error.ToolExecutionFailed;
        if (outcome == .input_required) return error.InputRequired;
        return;
    }
    const tools = client.listTools() catch |err| return reportRpcFailure(&client, err);
    if (std.mem.eql(u8, parsed.command, "list")) {
        if (tools.len == 0) return out.writeAll("no tools available.\n");
        for (tools) |tool| {
            const name = tool.name() orelse return error.ToolMissingName;
            const desc = tool.description() orelse "";
            try out.print("{s}\t{s}\n", .{ name, firstLine(desc) });
        }
    } else if (std.mem.eql(u8, parsed.command, "skills")) {
        if (parsed.positionals_len > 1) {
            const tool = findTool(tools, parsed.positionals[1]) orelse return toolNotFound(parsed.positionals[1]);
            try skills.renderTool(out, allocator, tool);
        } else for (tools) |tool| try skills.renderTool(out, allocator, tool);
    } else unreachable; // cli.parseArgs rejects every other command
}

fn isToolError(result: Value) bool {
    const flag = rpc.get(result, "isError") orelse return false;
    return flag == .bool and flag.bool;
}

/// Prints the structured JSON-RPC error recorded by the transport, which
/// carries far more than the propagated Zig error name.
fn reportRpcFailure(client: *McpClient, err: anyerror) anyerror {
    if (client.last_rpc_error) |failure| {
        diagnostics_out.report("RPC error {d}: {s}\n", .{ failure.code, failure.message });
        if (failure.data) |data| if (rpc.jsonString(client.allocator, data)) |text|
            diagnostics_out.report("RPC error data: {s}\n", .{text})
        else |_| {};
    }
    return err;
}

fn findServer(config: Config, name: []const u8) ?Server {
    for (config.http) |s| if (std.mem.eql(u8, s.name, name)) return s;
    return null;
}
fn printMissingServer(config: Config, name: []const u8) !void {
    diagnostics_out.report("server '{s}' not found. available: ", .{name});
    for (config.http, 0..) |s, i| diagnostics_out.report("{s}{s}", .{ if (i == 0) "" else ", ", s.name });
    diagnostics_out.report("\n", .{});
}
fn findTool(tools: []const Tool, name: []const u8) ?Tool {
    for (tools) |t| if (t.name()) |n| if (std.mem.eql(u8, n, name)) return t;
    return null;
}
fn toolNotFound(name: []const u8) error{ToolNotFound} {
    diagnostics_out.report("tool '{s}' not found\n", .{name});
    return error.ToolNotFound;
}
fn firstLine(s: []const u8) []const u8 {
    return s[0 .. std.mem.indexOfScalar(u8, s, '\n') orelse s.len];
}

test "config parses servers via toml library" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser = toml.Parser(Config).init(arena.allocator());
    defer parser.deinit();
    var parsed_config = try parser.parseString(
        \\# mcpx test configuration
        \\[[http]]
        \\name = "one"
        \\endpoint = "http://127.0.0.1:3000/mcp"
        \\
        \\[http.headers]
        \\Authorization = "Bearer token"
        \\X-Label = "a,b"
        \\
        \\[[http]]
        \\name = "two"
        \\endpoint = "https://example.test/mcp"
        \\timeout_secs = 60
        \\[http.oauth]
        \\client_id = "client"
        \\scopes = "read write"
        \\register = false
        \\
    );
    defer parsed_config.deinit();
    const config = parsed_config.value;
    try std.testing.expectEqual(@as(usize, 2), config.http.len);
    try std.testing.expectEqual(@as(u64, 30), config.http[0].timeoutSecs());
    try std.testing.expectEqual(@as(u64, 60), config.http[1].timeoutSecs());
    try std.testing.expectEqualStrings("client", config.http[1].oauth.?.client_id.?);
    try std.testing.expectEqualStrings("read write", config.http[1].oauth.?.scopes.?);
    const headers = config.http[0].headers.?;
    try std.testing.expectEqualStrings("a,b", headers.map.get("X-Label").?);
}

test {
    std.testing.refAllDecls(cli);
    std.testing.refAllDecls(client_module);
    std.testing.refAllDecls(skills);
    std.testing.refAllDecls(oauth);
    std.testing.refAllDecls(protocol);
}

test "configuration rejects duplicate and malformed servers" {
    try validateConfig(.{ .http = &.{
        .{ .name = "one", .endpoint = "https://one.example/mcp" },
        .{ .name = "two", .endpoint = "https://two.example/mcp" },
    } });
    try std.testing.expectError(error.ConfigDuplicateServer, validateConfig(.{ .http = &.{
        .{ .name = "one", .endpoint = "https://one.example/mcp" },
        .{ .name = "one", .endpoint = "https://other.example/mcp" },
    } }));
    try std.testing.expectError(error.ServerEndpointSchemeUnsupported, validateConfig(.{ .http = &.{
        .{ .name = "one", .endpoint = "file:///etc/passwd" },
    } }));
}

test "failure classes map to distinct exit codes" {
    try std.testing.expectEqual(@as(u8, 2), exitCode(error.ConfigReadFailed));
    try std.testing.expectEqual(@as(u8, 2), exitCode(error.UnknownOption));
    try std.testing.expectEqual(@as(u8, 2), exitCode(error.ServerNotFound));
    try std.testing.expectEqual(@as(u8, 3), exitCode(error.HttpUnauthorized));
    try std.testing.expectEqual(@as(u8, 3), exitCode(error.OauthCallbackTimeout));
    try std.testing.expectEqual(@as(u8, 4), exitCode(error.JsonRpcError));
    try std.testing.expectEqual(@as(u8, 4), exitCode(error.ServerDoesNotSupportTools));
    try std.testing.expectEqual(@as(u8, 5), exitCode(error.RequestTimedOut));
    try std.testing.expectEqual(@as(u8, 6), exitCode(error.ToolExecutionFailed));
    try std.testing.expectEqual(@as(u8, 7), exitCode(error.InputRequired));
    try std.testing.expectEqual(@as(u8, 1), exitCode(error.OutOfMemory));
}

test "tool results that report failure are detected" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const failed = try std.json.parseFromSliceLeaky(Value, arena.allocator(), "{\"isError\":true,\"content\":[]}", .{});
    const ok = try std.json.parseFromSliceLeaky(Value, arena.allocator(), "{\"content\":[]}", .{});
    const not_a_bool = try std.json.parseFromSliceLeaky(Value, arena.allocator(), "{\"isError\":\"yes\"}", .{});
    try std.testing.expect(isToolError(failed));
    try std.testing.expect(!isToolError(ok));
    try std.testing.expect(!isToolError(not_a_bool));
}

fn runCommandForTest(allocator: Allocator, io: Io, args: []const []const u8, config: Config, out: *Io.Writer) !void {
    const parsed = try cli.parseArgs(args);
    return runCommand(allocator, io, parsed, config, "unused", out);
}

test "the servers command lists configured entries and marks OAuth" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var output: Io.Writer.Allocating = .init(arena.allocator());
    try runCommandForTest(arena.allocator(), std.testing.io, &.{ "mcpx", "servers" }, .{ .http = &.{
        .{ .name = "plain", .endpoint = "https://one.example/mcp" },
        .{ .name = "secured", .endpoint = "https://two.example/mcp", .oauth = .{ .client_id = "id" } },
    } }, &output.writer);
    try std.testing.expectEqualStrings(
        "plain\thttps://one.example/mcp\nsecured\thttps://two.example/mcp [oauth]\n",
        output.written(),
    );
}

test "the servers command reports an empty configuration" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var output: Io.Writer.Allocating = .init(arena.allocator());
    try runCommandForTest(arena.allocator(), std.testing.io, &.{ "mcpx", "servers" }, .{}, &output.writer);
    try std.testing.expectEqualStrings("no servers configured.\n", output.written());
}

test "an unknown server name fails before any request" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var output: Io.Writer.Allocating = .init(arena.allocator());
    try std.testing.expectError(error.ServerNotFound, runCommandForTest(
        arena.allocator(),
        std.testing.io,
        &.{ "mcpx", "list", "missing" },
        .{ .http = &.{.{ .name = "present", .endpoint = "https://one.example/mcp" }} },
        &output.writer,
    ));
}

test "the list and skills commands render a live server" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    const test_http = @import("test_http.zig");
    const tools_body =
        \\{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"search","description":"Find things\nsecond line","inputSchema":{"type":"object","properties":{"query":{"type":"string","description":"text"}},"required":["query"]}}]}}
    ;
    const discovery = test_http.Response{
        .status = "200 OK",
        .body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2026-07-28\",\"capabilities\":{\"tools\":{}}}}",
    };

    for ([_][]const u8{ "list", "skills" }) |command| {
        var server = try test_http.listenLoopback(io);
        defer server.deinit(io);
        const endpoint = try test_http.endpointFor(allocator, &server);
        var script = test_http.Script{ .responses = &.{ discovery, .{ .status = "200 OK", .body = tools_body } } };
        var serving = try io.concurrent(test_http.Script.serve, .{ &script, io, &server });
        var output: Io.Writer.Allocating = .init(allocator);
        try runCommandForTest(
            allocator,
            io,
            &.{ "mcpx", command, "demo" },
            .{ .http = &.{.{ .name = "demo", .endpoint = endpoint }} },
            &output.writer,
        );
        try serving.await(io);
        if (std.mem.eql(u8, command, "list")) {
            // Only the first line of a description belongs in the listing.
            try std.testing.expectEqualStrings("search\tFind things\n", output.written());
        } else {
            try std.testing.expect(std.mem.startsWith(u8, output.written(), "## search\n"));
            try std.testing.expect(std.mem.indexOf(u8, output.written(), "**(required)**") != null);
        }
    }
}

test "a failing tool call prints the result and reports a tool error" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    const test_http = @import("test_http.zig");
    var server = try test_http.listenLoopback(io);
    defer server.deinit(io);
    const endpoint = try test_http.endpointFor(allocator, &server);
    var script = test_http.Script{ .responses = &.{
        .{
            .status = "200 OK",
            .body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2026-07-28\",\"capabilities\":{\"tools\":{}}}}",
        },
        .{
            .status = "200 OK",
            .body =
            \\{"jsonrpc":"2.0","id":2,"result":{"isError":true,"content":[{"type":"text","text":"boom"}]}}
            ,
        },
    } };
    var serving = try io.concurrent(test_http.Script.serve, .{ &script, io, &server });
    var output: Io.Writer.Allocating = .init(allocator);
    try std.testing.expectError(error.ToolExecutionFailed, runCommandForTest(
        allocator,
        io,
        &.{ "mcpx", "call", "demo", "search", "{\"query\":\"x\"}" },
        .{ .http = &.{.{ .name = "demo", .endpoint = endpoint }} },
        &output.writer,
    ));
    try serving.await(io);
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "\"boom\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, script.request(1), "Mcp-Method: tools/call") != null);
}

test "call arguments must be a JSON object" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var output: Io.Writer.Allocating = .init(arena.allocator());
    const config: Config = .{ .http = &.{.{ .name = "demo", .endpoint = "https://one.example/mcp" }} };
    try std.testing.expectError(error.ArgsNotValidJson, runCommandForTest(
        arena.allocator(),
        std.testing.io,
        &.{ "mcpx", "call", "demo", "search", "not json" },
        config,
        &output.writer,
    ));
    try std.testing.expectError(error.ArgsMustBeObject, runCommandForTest(
        arena.allocator(),
        std.testing.io,
        &.{ "mcpx", "call", "demo", "search", "[1,2]" },
        config,
        &output.writer,
    ));
}
