const std = @import("std");

const Allocator = std.mem.Allocator;
const Io = std.Io;
const Value = std.json.Value;

const version = "0.1.0";

const toml = @import("toml");
const client_module = @import("client.zig");
const cli = @import("cli.zig");
const skills = @import("skills.zig");
const McpClient = client_module.McpClient;
const Server = client_module.Server;
const Tool = client_module.Tool;

const Config = struct {
    http: []const Server = &.{},
};

pub fn main(init: std.process.Init) void {
    run(init) catch |err| {
        std.debug.print("error: {s}\n", .{@errorName(err)});
        std.process.exit(1);
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
    const path = if (parsed.config) |p| p else blk: {
        const home = init.minimal.environ.getAlloc(allocator, "HOME") catch return error.HomeNotSet;
        break :blk try std.fs.path.join(allocator, &.{ home, ".config/mcpx/config.toml" });
    };
    const raw = std.Io.Dir.cwd().readFileAlloc(init.io, path, allocator, .limited(16 * 1024 * 1024)) catch {
        std.debug.print("cannot read config file: {s}\n", .{path});
        return error.ConfigReadFailed;
    };
    var parser = toml.Parser(Config).init(allocator);
    defer parser.deinit();
    var parsed_config = parser.parseString(raw) catch |err| {
        std.debug.print("failed to parse config {s}: {s}\n", .{ path, @errorName(err) });
        return error.ConfigParseFailed;
    };
    defer parsed_config.deinit();
    const config = parsed_config.value;
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_file: Io.File.Writer = .init(.stdout(), init.io, &stdout_buffer);
    const out = &stdout_file.interface;
    defer out.flush() catch |err| std.debug.print("failed to flush stdout: {s}\n", .{@errorName(err)});

    if (std.mem.eql(u8, parsed.command, "servers")) {
        if (config.http.len == 0) return out.writeAll("no servers configured.\n");
        for (config.http) |s| try out.print("{s}\t{s}\n", .{ s.name, s.endpoint });
        return;
    }
    const server_name = parsed.positionals[0];
    const server = findServer(config, server_name) orelse {
        try printMissingServer(config, server_name);
        return error.ServerNotFound;
    };
    var client = McpClient.init(allocator, init.io, server);
    defer client.deinit();
    try client.connect();

    if (std.mem.eql(u8, parsed.command, "call")) {
        const args_text = if (parsed.positionals_len > 2) parsed.positionals[2] else "{}";
        const call_args = std.json.parseFromSliceLeaky(Value, allocator, args_text, .{}) catch return error.ArgsNotValidJson;
        if (call_args != .object) return error.ArgsMustBeObject;
        var params = Value{ .object = .empty };
        try params.object.put(allocator, "name", .{ .string = parsed.positionals[1] });
        try params.object.put(allocator, "arguments", call_args);
        const result = try client.rpc("tools/call", params);
        try skills.prettyPrint(out, result);
        return;
    }
    const tools = try client.listTools();
    if (std.mem.eql(u8, parsed.command, "list")) {
        if (tools.len == 0) return out.writeAll("no tools available.\n");
        for (tools) |tool| {
            const name = tool.name() orelse return error.ToolMissingName;
            const desc = tool.description() orelse "";
            try out.print("{s}\t{s}\n", .{ name, firstLine(desc) });
        }
    } else if (std.mem.eql(u8, parsed.command, "schema")) {
        const tool = findTool(tools, parsed.positionals[1]) orelse return toolNotFound(parsed.positionals[1]);
        try skills.prettyPrint(out, tool.value);
    } else if (std.mem.eql(u8, parsed.command, "skills")) {
        if (parsed.positionals_len > 1) {
            const tool = findTool(tools, parsed.positionals[1]) orelse return toolNotFound(parsed.positionals[1]);
            try skills.renderTool(out, allocator, tool);
        } else for (tools) |tool| try skills.renderTool(out, allocator, tool);
    }
}

fn findServer(config: Config, name: []const u8) ?Server {
    for (config.http) |s| if (std.mem.eql(u8, s.name, name)) return s;
    return null;
}
fn printMissingServer(config: Config, name: []const u8) !void {
    std.debug.print("server '{s}' not found. available: ", .{name});
    for (config.http, 0..) |s, i| std.debug.print("{s}{s}", .{ if (i == 0) "" else ", ", s.name });
    std.debug.print("\n", .{});
}
fn findTool(tools: []const Tool, name: []const u8) ?Tool {
    for (tools) |t| if (t.name()) |n| if (std.mem.eql(u8, n, name)) return t;
    return null;
}
fn toolNotFound(name: []const u8) error{ToolNotFound} {
    std.debug.print("tool '{s}' not found\n", .{name});
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
        \\
    );
    defer parsed_config.deinit();
    const config = parsed_config.value;
    try std.testing.expectEqual(@as(usize, 2), config.http.len);
    try std.testing.expectEqual(@as(u64, 30), config.http[0].timeoutSecs());
    try std.testing.expectEqual(@as(u64, 60), config.http[1].timeoutSecs());
    const headers = config.http[0].headers.?;
    try std.testing.expectEqualStrings("a,b", headers.map.get("X-Label").?);
}
