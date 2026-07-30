const std = @import("std");

const Allocator = std.mem.Allocator;
const Io = std.Io;
const Value = std.json.Value;

const version = "0.1.0";

const toml = @import("toml");
const client_module = @import("client.zig");
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
    const parsed = try parseArgs(args);
    if (parsed.help) {
        try writeUsage(init.io);
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
    defer out.flush() catch {};

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
        try prettyPrint(out, result);
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
        try prettyPrint(out, tool.value);
    } else if (std.mem.eql(u8, parsed.command, "skills")) {
        if (parsed.positionals_len > 1) {
            const tool = findTool(tools, parsed.positionals[1]) orelse return toolNotFound(parsed.positionals[1]);
            try renderTool(out, allocator, tool);
        } else for (tools) |tool| try renderTool(out, allocator, tool);
    }
}

const ParsedArgs = struct {
    config: ?[]const u8,
    command: []const u8,
    positionals: [3][]const u8,
    positionals_len: usize,
    help: bool = false,
};
fn parseArgs(args: []const []const u8) !ParsedArgs {
    var config: ?[]const u8 = null;
    var command: ?[]const u8 = null;
    var positions: [3][]const u8 = undefined;
    var count: usize = 0;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) return .{
            .config = config,
            .command = "",
            .positionals = undefined,
            .positionals_len = 0,
            .help = true,
        };
        if (std.mem.eql(u8, arg, "-c") or std.mem.eql(u8, arg, "--config")) {
            i += 1;
            if (i == args.len) return error.MissingConfigPath;
            config = args[i];
        } else if (command == null) command = arg else {
            if (count == positions.len) return error.TooManyArguments;
            positions[count] = arg;
            count += 1;
        }
    }
    const cmd = command orelse return error.MissingCommand;
    const needed: usize = if (std.mem.eql(u8, cmd, "servers")) 0 else if (std.mem.eql(u8, cmd, "list")) 1 else if (std.mem.eql(u8, cmd, "schema") or std.mem.eql(u8, cmd, "call")) 2 else if (std.mem.eql(u8, cmd, "skills")) 1 else return error.UnknownCommand;
    if (count < needed) return error.MissingArgument;
    return .{ .config = config, .command = cmd, .positionals = positions, .positionals_len = count };
}

fn writeUsage(io: Io) !void {
    var buffer: [2048]u8 = undefined;
    var file: Io.File.Writer = .init(.stdout(), io, &buffer);
    try file.interface.writeAll(
        \\mcpx 0.1.0 - CLI bridge for MCP HTTP servers
        \\
        \\Usage: mcpx [-c PATH] <COMMAND>
        \\
        \\Commands:
        \\  servers
        \\  list <server>
        \\  schema <server> <tool>
        \\  call <server> <tool> [json_args]
        \\  skills <server> [tool]
        \\
    );
    try file.interface.flush();
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
fn get(value: Value, key: []const u8) ?Value {
    return if (value == .object) value.object.get(key) else null;
}
fn getString(value: Value, key: []const u8) ?[]const u8 {
    const v = get(value, key) orelse return null;
    return if (v == .string) v.string else null;
}

fn jsonString(allocator: Allocator, value: Value) ![]u8 {
    var output: Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    try std.json.Stringify.value(value, .{}, &output.writer);
    return output.toOwnedSlice();
}
fn prettyPrint(out: *Io.Writer, value: Value) !void {
    try std.json.Stringify.value(value, .{ .whitespace = .indent_2 }, out);
    try out.writeByte('\n');
}
fn displayScalar(allocator: Allocator, value: Value) ![]const u8 {
    return if (value == .string) value.string else jsonString(allocator, value);
}

fn renderTool(out: *Io.Writer, allocator: Allocator, tool: Tool) !void {
    try out.print("## {s}\n", .{tool.name() orelse return error.ToolMissingName});
    if (tool.description()) |desc| try out.print("\n{s}\n", .{desc});
    if (get(tool.value, "inputSchema")) |schema| {
        try out.writeAll("\n### Parameters\n\n");
        try renderSchema(out, allocator, schema, 0);
    }
    if (get(tool.value, "outputSchema")) |schema| {
        try out.writeAll("\n### Returns\n\n");
        try renderSchema(out, allocator, schema, 0);
    }
    try out.writeByte('\n');
}

fn renderSchema(out: *Io.Writer, allocator: Allocator, schema: Value, indent: usize) !void {
    if (getString(schema, "$ref")) |ref| {
        try spaces(out, indent);
        try out.print("- Reference: `{s}`\n", .{ref});
        return;
    }
    const props = get(schema, "properties") orelse {
        try out.writeAll("```json\n");
        try prettyPrint(out, schema);
        try out.writeAll("```\n");
        return;
    };
    if (props != .object) return error.InvalidSchemaProperties;
    var it = props.object.iterator();
    while (it.next()) |entry| {
        const prop = entry.value_ptr.*;
        try spaces(out, indent);
        try out.print("- `{s}` ({s})", .{ entry.key_ptr.*, try schemaType(allocator, prop) });
        if (isRequired(schema, entry.key_ptr.*)) try out.writeAll(" **(required)**");
        try schemaDetails(out, allocator, prop);
        if (getString(prop, "description")) |desc| if (desc.len != 0) try out.print(": {s}", .{desc});
        try out.writeByte('\n');
        if (get(prop, "properties") != null) try renderSchema(out, allocator, prop, indent + 1) else if (get(prop, "items")) |items| if (get(items, "properties") != null or get(items, "$ref") != null) try renderSchema(out, allocator, items, indent + 1);
    }
}
fn spaces(out: *Io.Writer, indent: usize) !void {
    for (0..indent) |_| try out.writeAll("  ");
}
fn isRequired(schema: Value, name: []const u8) bool {
    const req = get(schema, "required") orelse return false;
    if (req != .array) return false;
    for (req.array.items) |v| if (v == .string and std.mem.eql(u8, v.string, name)) return true;
    return false;
}
fn schemaType(allocator: Allocator, schema: Value) ![]const u8 {
    if (getString(schema, "$ref")) |ref| return std.fmt.allocPrint(allocator, "ref: {s}", .{ref});
    const kind = getString(schema, "type") orelse return "any";
    if (!std.mem.eql(u8, kind, "array")) return kind;
    return std.fmt.allocPrint(allocator, "array of {s}", .{if (get(schema, "items")) |items| try schemaType(allocator, items) else "any"});
}
fn schemaDetails(out: *Io.Writer, allocator: Allocator, schema: Value) !void {
    var first = true;
    if (get(schema, "enum")) |values| if (values == .array) {
        try out.writeAll(" (enum: ");
        for (values.array.items, 0..) |v, i| {
            if (i != 0) try out.writeAll(" | ");
            try out.writeAll(try displayScalar(allocator, v));
        }
        first = false;
    };
    const fields = [_][]const u8{ "minLength", "maxLength", "minimum", "maximum", "pattern", "default" };
    for (fields) |field| if (get(schema, field)) |v| {
        try out.print("{s}{s}: {s}", .{ if (first) " (" else ", ", field, try displayScalar(allocator, v) });
        first = false;
    };
    if (!first) try out.writeByte(')');
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

test "argument parser accepts global config flag" {
    const parsed = try parseArgs(&.{ "mcpx", "skills", "demo", "search", "-c", "test.toml" });
    try std.testing.expectEqualStrings("skills", parsed.command);
    try std.testing.expectEqualStrings("test.toml", parsed.config.?);
    try std.testing.expectEqualStrings("search", parsed.positionals[1]);
}
