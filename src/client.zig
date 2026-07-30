const std = @import("std");

const Allocator = std.mem.Allocator;
const Io = std.Io;
const Value = std.json.Value;

const toml = @import("toml");

const version = "0.1.0";
const protocol_version = "2025-03-26";

pub const Server = struct {
    name: []const u8,
    endpoint: []const u8,
    headers: ?toml.HashMap([]const u8) = null,
    timeout_secs: ?u64 = null,

    pub fn timeoutSecs(self: Server) u64 {
        return self.timeout_secs orelse 30;
    }
};

pub const Tool = struct {
    value: Value,

    pub fn name(self: Tool) ?[]const u8 {
        return getString(self.value, "name");
    }

    pub fn description(self: Tool) ?[]const u8 {
        return getString(self.value, "description");
    }
};

pub const McpClient = struct {
    allocator: Allocator,
    io: Io,
    http: std.http.Client,
    server: Server,
    session_id: ?[]const u8 = null,
    negotiated_version: []const u8 = protocol_version,
    next_id: u64 = 1,

    pub fn init(allocator: Allocator, io: Io, server: Server) McpClient {
        return .{ .allocator = allocator, .io = io, .http = .{ .allocator = allocator, .io = io }, .server = server };
    }

    pub fn deinit(self: *McpClient) void {
        self.http.deinit();
    }

    pub fn connect(self: *McpClient) !void {
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

    pub fn request(self: *McpClient, body: []const u8, notification: bool) !?Value {
        const Result = union(enum) {
            response: anyerror!?Value,
            timeout: void,
        };
        var completions: [2]Result = undefined;
        var select: Io.Select(Result) = .init(self.io, &completions);
        try select.concurrent(.response, requestInner, .{ self, body, notification });
        try select.concurrent(.timeout, waitForTimeout, .{ self.io, self.server.timeoutSecs() });
        const result = try select.await();
        select.cancelDiscard();
        return switch (result) {
            .response => |response| response,
            .timeout => {
                std.debug.print("request to {s} timed out after {d} seconds\n", .{ self.server.endpoint, self.server.timeoutSecs() });
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
        if (self.server.headers) |headers| {
            var it = headers.map.iterator();
            while (it.next()) |entry| try extra.append(self.allocator, .{ .name = entry.key_ptr.*, .value = entry.value_ptr.* });
        }

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

    pub fn rpc(self: *McpClient, method: []const u8, params: ?Value) !Value {
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

    pub fn listTools(self: *McpClient) ![]const Tool {
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

fn get(value: Value, key: []const u8) ?Value {
    return if (value == .object) value.object.get(key) else null;
}

fn getString(value: Value, key: []const u8) ?[]const u8 {
    const value_at_key = get(value, key) orelse return null;
    return if (value_at_key == .string) value_at_key.string else null;
}

fn jsonString(allocator: Allocator, value: Value) ![]u8 {
    var output: Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    try std.json.Stringify.value(value, .{}, &output.writer);
    return output.toOwnedSlice();
}

fn displayScalar(allocator: Allocator, value: Value) ![]const u8 {
    return if (value == .string) value.string else jsonString(allocator, value);
}

test "SSE returns last response" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const value = try parseSse(arena.allocator(), "data: nope\n\ndata: {\"result\":{\"page\":1}}\n\ndata: {\"result\":{\"page\":2}}\n\n");
    try std.testing.expectEqual(@as(i64, 2), get(value, "page").?.integer);
}
