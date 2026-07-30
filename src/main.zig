const std = @import("std");

const Allocator = std.mem.Allocator;
const Io = std.Io;
const Value = std.json.Value;

const version = "0.1.0";
const protocol_version = "2025-03-26";

const Header = struct { name: []const u8, value: []const u8 };
const Server = struct {
    name: []const u8 = "",
    endpoint: []const u8 = "",
    headers: []const Header = &.{},
    timeout_secs: u64 = 30,
};

const Config = struct {
    servers: []const Server,

    fn parse(allocator: Allocator, raw: []const u8) !Config {
        var servers: std.ArrayList(Server) = .empty;
        var current: ?Server = null;
        var headers: std.ArrayList(Header) = .empty;

        var lines = std.mem.splitScalar(u8, raw, '\n');
        var line_no: usize = 0;
        while (lines.next()) |untrimmed| {
            line_no += 1;
            const line = std.mem.trim(u8, stripComment(untrimmed), " \t\r");
            if (line.len == 0) continue;
            if (std.mem.eql(u8, line, "[[http]]")) {
                if (current) |*server| {
                    server.headers = try headers.toOwnedSlice(allocator);
                    try validateServer(server.*, line_no - 1);
                    try servers.append(allocator, server.*);
                }
                current = .{};
                headers = .empty;
                continue;
            }
            if (current == null) return error.ConfigKeyOutsideHttpSection;
            const equal = findUnquoted(line, '=') orelse return error.InvalidConfigAssignment;
            const key = std.mem.trim(u8, line[0..equal], " \t");
            const val = std.mem.trim(u8, line[equal + 1 ..], " \t");
            if (std.mem.eql(u8, key, "name")) {
                current.?.name = try parseString(allocator, val);
            } else if (std.mem.eql(u8, key, "endpoint")) {
                current.?.endpoint = try parseString(allocator, val);
            } else if (std.mem.eql(u8, key, "timeout_secs")) {
                current.?.timeout_secs = std.fmt.parseInt(u64, val, 10) catch return error.InvalidTimeout;
            } else if (std.mem.eql(u8, key, "headers")) {
                try parseHeaders(allocator, val, &headers);
            } else {
                return error.UnknownConfigKey;
            }
        }
        if (current) |*server| {
            server.headers = try headers.toOwnedSlice(allocator);
            try validateServer(server.*, line_no);
            try servers.append(allocator, server.*);
        }
        return .{ .servers = try servers.toOwnedSlice(allocator) };
    }
};

fn validateServer(server: Server, line: usize) !void {
    _ = line;
    if (server.name.len == 0) return error.ServerMissingName;
    if (server.endpoint.len == 0) return error.ServerMissingEndpoint;
    if (server.timeout_secs == 0) return error.InvalidTimeout;
    for (server.headers) |header| {
        if (header.name.len == 0 or std.mem.indexOfAny(u8, header.name, "\r\n") != null) return error.InvalidHeaderName;
        if (std.mem.indexOfAny(u8, header.value, "\r\n") != null) return error.InvalidHeaderValue;
    }
}

fn stripComment(line: []const u8) []const u8 {
    var quoted = false;
    var escaped = false;
    for (line, 0..) |c, i| {
        if (escaped) {
            escaped = false;
        } else if (c == '\\' and quoted) {
            escaped = true;
        } else if (c == '"') {
            quoted = !quoted;
        } else if (c == '#' and !quoted) {
            return line[0..i];
        }
    }
    return line;
}

fn findUnquoted(s: []const u8, needle: u8) ?usize {
    var quoted = false;
    var escaped = false;
    for (s, 0..) |c, i| {
        if (escaped) escaped = false else if (c == '\\' and quoted) escaped = true else if (c == '"') quoted = !quoted else if (c == needle and !quoted) return i;
    }
    return null;
}

fn parseString(allocator: Allocator, text: []const u8) ![]const u8 {
    if (text.len < 2 or text[0] != '"' or text[text.len - 1] != '"') return error.ExpectedQuotedString;
    var out: Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    var i: usize = 1;
    while (i + 1 < text.len) : (i += 1) {
        if (text[i] != '\\') {
            try out.writer.writeByte(text[i]);
            continue;
        }
        i += 1;
        if (i + 1 > text.len) return error.InvalidStringEscape;
        try out.writer.writeByte(switch (text[i]) {
            '"', '\\' => text[i],
            'n' => '\n',
            'r' => '\r',
            't' => '\t',
            else => return error.InvalidStringEscape,
        });
    }
    return out.toOwnedSlice();
}

fn parseHeaders(allocator: Allocator, text: []const u8, headers: *std.ArrayList(Header)) !void {
    if (text.len < 2 or text[0] != '{' or text[text.len - 1] != '}') return error.InvalidHeadersMap;
    var rest = std.mem.trim(u8, text[1 .. text.len - 1], " \t");
    while (rest.len != 0) {
        const equal = findUnquoted(rest, '=') orelse return error.InvalidHeadersMap;
        const key_text = std.mem.trim(u8, rest[0..equal], " \t");
        const comma = findUnquoted(rest[equal + 1 ..], ',');
        const value_end = if (comma) |n| equal + 1 + n else rest.len;
        const value_text = std.mem.trim(u8, rest[equal + 1 .. value_end], " \t");
        const key = if (key_text.len > 0 and key_text[0] == '"') try parseString(allocator, key_text) else try allocator.dupe(u8, key_text);
        try headers.append(allocator, .{ .name = key, .value = try parseString(allocator, value_text) });
        rest = if (comma != null) std.mem.trim(u8, rest[value_end + 1 ..], " \t") else "";
    }
}

const Tool = struct {
    value: Value,
    fn name(self: Tool) ?[]const u8 {
        return getString(self.value, "name");
    }
    fn description(self: Tool) ?[]const u8 {
        return getString(self.value, "description");
    }
};

const McpClient = struct {
    allocator: Allocator,
    io: Io,
    http: std.http.Client,
    server: Server,
    session_id: ?[]const u8 = null,
    negotiated_version: []const u8 = protocol_version,
    next_id: u64 = 1,

    fn init(allocator: Allocator, io: Io, server: Server) McpClient {
        return .{ .allocator = allocator, .io = io, .http = .{ .allocator = allocator, .io = io }, .server = server };
    }

    fn deinit(self: *McpClient) void {
        self.http.deinit();
    }

    fn connect(self: *McpClient) !void {
        var params = Value{ .object = .empty };
        try params.object.put(self.allocator, "protocolVersion", .{ .string = protocol_version });
        try params.object.put(self.allocator, "capabilities", .{ .object = .empty });
        var info = Value{ .object = .empty };
        try info.object.put(self.allocator, "name", .{ .string = "mcpx" });
        try info.object.put(self.allocator, "version", .{ .string = version });
        try params.object.put(self.allocator, "clientInfo", info);
        const initialized = try self.rpc("initialize", params);
        self.negotiated_version = getString(initialized, "protocolVersion") orelse return error.InitializeMissingProtocolVersion;
        try self.notifyInitialized();
    }

    fn request(self: *McpClient, body: []const u8, notification: bool) !?Value {
        const Result = union(enum) {
            response: anyerror!?Value,
            timeout: void,
        };
        var completions: [2]Result = undefined;
        var select: Io.Select(Result) = .init(self.io, &completions);
        try select.concurrent(.response, requestInner, .{ self, body, notification });
        try select.concurrent(.timeout, waitForTimeout, .{ self.io, self.server.timeout_secs });
        const result = try select.await();
        select.cancelDiscard();
        return switch (result) {
            .response => |response| response,
            .timeout => {
                std.debug.print("request to {s} timed out after {d} seconds\n", .{ self.server.endpoint, self.server.timeout_secs });
                return error.RequestTimedOut;
            },
        };
    }

    fn requestInner(self: *McpClient, body: []const u8, notification: bool) anyerror!?Value {
        const uri = try std.Uri.parse(self.server.endpoint);
        var extra: std.ArrayList(std.http.Header) = .empty;
        defer extra.deinit(self.allocator);
        try extra.append(self.allocator, .{ .name = "Accept", .value = "application/json, text/event-stream" });
        try extra.append(self.allocator, .{ .name = "MCP-Protocol-Version", .value = self.negotiated_version });
        if (self.session_id) |sid| try extra.append(self.allocator, .{ .name = "Mcp-Session-Id", .value = sid });
        for (self.server.headers) |h| try extra.append(self.allocator, .{ .name = h.name, .value = h.value });

        var req = try self.http.request(.POST, uri, .{
            .headers = .{
                .accept_encoding = .omit,
                .content_type = .{ .override = "application/json" },
            },
            .extra_headers = extra.items,
        });
        defer req.deinit();
        req.transfer_encoding = .{ .content_length = body.len };
        var request_body = try req.sendBodyUnflushed(&.{});
        try request_body.writer.writeAll(body);
        try request_body.end();
        try req.connection.?.flush();
        var response = try req.receiveHead(&.{});
        const status = response.head.status;
        const content_type = try self.allocator.dupe(u8, response.head.content_type orelse "");
        const reason = try self.allocator.dupe(u8, response.head.reason);
        if (self.session_id == null) {
            var it = response.head.iterateHeaders();
            while (it.next()) |h| if (std.ascii.eqlIgnoreCase(h.name, "Mcp-Session-Id")) {
                self.session_id = try self.allocator.dupe(u8, h.value);
                break;
            };
        }
        var output: Io.Writer.Allocating = .init(self.allocator);
        defer output.deinit();
        var transfer_buffer: [64]u8 = undefined;
        var decompress: std.http.Decompress = undefined;
        const reader = response.readerDecompressing(&transfer_buffer, &decompress, &.{});
        _ = try reader.streamRemaining(&output.writer);
        const text = output.written();
        if (status.class() != .success) {
            std.debug.print("HTTP {d} {s}: {s}\n", .{ @intFromEnum(status), reason, text });
            return error.HttpRequestFailed;
        }
        if (notification) return null;
        const base_type = std.mem.trim(u8, std.mem.sliceTo(content_type, ';'), " \t");
        if (std.ascii.eqlIgnoreCase(base_type, "application/json")) return try parseRpc(self.allocator, text);
        if (std.ascii.eqlIgnoreCase(base_type, "text/event-stream")) return try parseSse(self.allocator, text);
        std.debug.print("unsupported response Content-Type: {s}\n", .{base_type});
        return error.UnsupportedContentType;
    }

    fn rpc(self: *McpClient, method: []const u8, params: ?Value) !Value {
        var request_value = Value{ .object = .empty };
        try request_value.object.put(self.allocator, "jsonrpc", .{ .string = "2.0" });
        try request_value.object.put(self.allocator, "id", .{ .integer = @intCast(self.next_id) });
        try request_value.object.put(self.allocator, "method", .{ .string = method });
        if (params) |p| try request_value.object.put(self.allocator, "params", p);
        self.next_id += 1;
        const body = try jsonString(self.allocator, request_value);
        return (try self.request(body, false)).?;
    }

    fn notifyInitialized(self: *McpClient) !void {
        var note = Value{ .object = .empty };
        try note.object.put(self.allocator, "jsonrpc", .{ .string = "2.0" });
        try note.object.put(self.allocator, "method", .{ .string = "notifications/initialized" });
        const body = try jsonString(self.allocator, note);
        _ = try self.request(body, true);
    }

    fn listTools(self: *McpClient) ![]const Tool {
        var tools: std.ArrayList(Tool) = .empty;
        var cursor: ?[]const u8 = null;
        while (true) {
            var params: ?Value = null;
            if (cursor) |c| {
                var object = Value{ .object = .empty };
                try object.object.put(self.allocator, "cursor", .{ .string = c });
                params = object;
            }
            const result = try self.rpc("tools/list", params);
            const list = get(result, "tools") orelse return error.ToolsListMissingTools;
            if (list != .array) return error.ToolsListMissingTools;
            for (list.array.items) |tool| try tools.append(self.allocator, .{ .value = tool });
            cursor = getString(result, "nextCursor");
            if (cursor == null or cursor.?.len == 0) break;
        }
        return tools.toOwnedSlice(self.allocator);
    }
};

fn waitForTimeout(io: Io, seconds: u64) void {
    const limited_seconds = @min(seconds, @as(u64, std.math.maxInt(i64)));
    Io.Timeout.sleep(.{ .duration = .{
        .clock = .awake,
        .raw = .fromSeconds(@intCast(limited_seconds)),
    } }, io) catch {};
}

fn parseRpc(allocator: Allocator, text: []const u8) !Value {
    const rpc = try std.json.parseFromSliceLeaky(Value, allocator, text, .{});
    if (get(rpc, "error")) |rpc_error| {
        const code = if (get(rpc_error, "code")) |v| displayScalar(allocator, v) catch "?" else "?";
        const message = getString(rpc_error, "message") orelse "unknown error";
        std.debug.print("RPC error [{s}]: {s}\n", .{ code, message });
        return error.JsonRpcError;
    }
    return get(rpc, "result") orelse error.ResponseMissingResult;
}

fn parseSse(allocator: Allocator, body: []const u8) !Value {
    var last: ?Value = null;
    var data: Io.Writer.Allocating = .init(allocator);
    defer data.deinit();
    var lines = std.mem.splitScalar(u8, body, '\n');
    while (true) {
        const maybe_line = lines.next();
        const line = if (maybe_line) |l| std.mem.trimEnd(u8, l, "\r") else "";
        if (line.len == 0) {
            if (data.written().len != 0) {
                if (std.json.parseFromSliceLeaky(Value, allocator, data.written(), .{})) |rpc| {
                    if (get(rpc, "result") != null or get(rpc, "error") != null) last = rpc;
                } else |_| {}
                data.clearRetainingCapacity();
            }
        } else if (std.mem.startsWith(u8, line, "data:")) {
            if (data.written().len != 0) try data.writer.writeByte('\n');
            try data.writer.writeAll(std.mem.trimStart(u8, line[5..], " "));
        }
        if (maybe_line == null) break;
    }
    const rpc = last orelse return error.SseMissingResponse;
    const encoded = try jsonString(allocator, rpc);
    return parseRpc(allocator, encoded);
}

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
    const config = Config.parse(allocator, raw) catch |err| {
        std.debug.print("failed to parse config {s}: {s}\n", .{ path, @errorName(err) });
        return err;
    };
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_file: Io.File.Writer = .init(.stdout(), init.io, &stdout_buffer);
    const out = &stdout_file.interface;
    defer out.flush() catch {};

    if (std.mem.eql(u8, parsed.command, "servers")) {
        if (config.servers.len == 0) return out.writeAll("no servers configured.\n");
        for (config.servers) |s| try out.print("{s}\t{s}\n", .{ s.name, s.endpoint });
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
    for (config.servers) |s| if (std.mem.eql(u8, s.name, name)) return s;
    return null;
}
fn printMissingServer(config: Config, name: []const u8) !void {
    std.debug.print("server '{s}' not found. available: ", .{name});
    for (config.servers, 0..) |s, i| std.debug.print("{s}{s}", .{ if (i == 0) "" else ", ", s.name });
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

test "SSE returns last response" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const value = try parseSse(arena.allocator(), "data: nope\n\ndata: {\"result\":{\"page\":1}}\n\ndata: {\"result\":{\"page\":2}}\n\n");
    try std.testing.expectEqual(@as(i64, 2), get(value, "page").?.integer);
}

test "config parses servers, headers, escapes, and defaults" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const config = try Config.parse(arena.allocator(),
        \\# mcpx test configuration
        \\[[http]]
        \\name = "one"
        \\endpoint = "http://127.0.0.1:3000/mcp"
        \\headers = { Authorization = "Bearer token", "X-Label" = "a,b" }
        \\
        \\[[http]]
        \\name = "two"
        \\endpoint = "https://example.test/mcp"
        \\timeout_secs = 60
        \\
    );
    try std.testing.expectEqual(@as(usize, 2), config.servers.len);
    try std.testing.expectEqual(@as(u64, 30), config.servers[0].timeout_secs);
    try std.testing.expectEqualStrings("a,b", config.servers[0].headers[1].value);
    try std.testing.expectEqual(@as(u64, 60), config.servers[1].timeout_secs);
}

test "argument parser accepts global config flag" {
    const parsed = try parseArgs(&.{ "mcpx", "skills", "demo", "search", "-c", "test.toml" });
    try std.testing.expectEqualStrings("skills", parsed.command);
    try std.testing.expectEqualStrings("test.toml", parsed.config.?);
    try std.testing.expectEqualStrings("search", parsed.positionals[1]);
}
