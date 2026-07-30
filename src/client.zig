const std = @import("std");

const Allocator = std.mem.Allocator;
const Io = std.Io;
const Value = std.json.Value;

const toml = @import("toml");

const version = "0.1.0";
const protocol_version = "2025-03-26";
const max_response_size = 16 * 1024 * 1024;

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
    supports_tools: bool = false,
    next_id: u64 = 1,
    test_server_responses: ?*std.ArrayList([]u8) = null,

    pub fn init(allocator: Allocator, io: Io, server: Server) McpClient {
        return .{ .allocator = allocator, .io = io, .http = .{ .allocator = allocator, .io = io }, .server = server };
    }

    pub fn deinit(self: *McpClient) void {
        self.http.deinit();
    }

    pub fn connect(self: *McpClient) anyerror!void {
        var params = Value{ .object = .empty };
        try params.object.put(self.allocator, "protocolVersion", .{ .string = protocol_version });
        try params.object.put(self.allocator, "capabilities", .{ .object = .empty });
        var info = Value{ .object = .empty };
        try info.object.put(self.allocator, "name", .{ .string = "mcpx" });
        try info.object.put(self.allocator, "version", .{ .string = version });
        try params.object.put(self.allocator, "clientInfo", info);
        const initialized = try self.rpc("initialize", params);
        const negotiated = getString(initialized, "protocolVersion") orelse return error.InitializeMissingProtocolVersion;
        if (!std.mem.eql(u8, negotiated, protocol_version)) return error.UnsupportedProtocolVersion;
        self.negotiated_version = negotiated;
        const capabilities = get(initialized, "capabilities");
        self.supports_tools = if (capabilities) |c| get(c, "tools") != null else false;
        try self.notifyInitialized();
    }

    pub fn request(self: *McpClient, body: []const u8, notification: bool) !?Value {
        return self.requestExpected(body, notification, null, true, false);
    }

    fn requestExpected(
        self: *McpClient,
        body: []const u8,
        notification: bool,
        expected_id: ?i64,
        allow_session_recovery: bool,
        cancellable: bool,
    ) anyerror!?Value {
        const Result = union(enum) {
            response: anyerror!?Value,
            timeout: void,
        };
        var completions: [2]Result = undefined;
        var select: Io.Select(Result) = .init(self.io, &completions);
        try select.concurrent(.response, requestInner, .{ self, body, notification, expected_id });
        try select.concurrent(.timeout, waitForTimeout, .{ self.io, self.server.timeoutSecs() });
        const result = try select.await();
        select.cancelDiscard();
        return switch (result) {
            .response => |response| response catch |err| {
                if (err == error.SessionExpired and allow_session_recovery) {
                    self.session_id = null;
                    self.negotiated_version = protocol_version;
                    self.supports_tools = false;
                    try self.connect();
                    return self.requestExpected(body, notification, expected_id, false, cancellable);
                }
                return err;
            },
            .timeout => {
                std.debug.print("request to {s} timed out after {d} seconds\n", .{ self.server.endpoint, self.server.timeoutSecs() });
                if (cancellable) if (expected_id) |id| self.notifyCancelled(id) catch {};
                return error.RequestTimedOut;
            },
        };
    }

    fn requestInner(self: *McpClient, body: []const u8, notification: bool, expected_id: ?i64) anyerror!?Value {
        const uri = try std.Uri.parse(self.server.endpoint);
        var extra: std.ArrayList(std.http.Header) = .empty;
        defer extra.deinit(self.allocator);
        try extra.append(self.allocator, .{ .name = "Accept", .value = "application/json, text/event-stream" });
        try extra.append(self.allocator, .{ .name = "MCP-Protocol-Version", .value = self.negotiated_version });
        const sent_session = self.session_id != null;
        if (self.session_id) |sid| try extra.append(self.allocator, .{ .name = "Mcp-Session-Id", .value = sid });
        if (self.server.headers) |headers| {
            var it = headers.map.iterator();
            while (it.next()) |entry| {
                if (isReservedHeader(entry.key_ptr.*)) {
                    std.debug.print("warning: skipping reserved configured header '{s}'\n", .{entry.key_ptr.*});
                    continue;
                }
                try extra.append(self.allocator, .{ .name = entry.key_ptr.*, .value = entry.value_ptr.* });
            }
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
        if (sent_session and status == .not_found) return error.SessionExpired;
        var transfer_buffer: [64]u8 = undefined;
        var decompress: std.http.Decompress = undefined;
        const reader = response.readerDecompressing(&transfer_buffer, &decompress, &.{});
        const base_type = std.mem.trim(u8, std.mem.sliceTo(content_type, ';'), " \t");
        if (status.class() == .success and !notification and std.ascii.eqlIgnoreCase(base_type, "text/event-stream"))
            return try parseSseReader(self, reader, expected_id orelse return error.MissingExpectedResponseId);

        var output: Io.Writer.Allocating = .init(self.allocator);
        defer output.deinit();
        while (output.written().len <= max_response_size) {
            const remaining = max_response_size + 1 - output.written().len;
            _ = reader.stream(&output.writer, .limited(remaining)) catch |err| switch (err) {
                error.EndOfStream => break,
                else => return err,
            };
        }
        if (output.written().len > max_response_size) return error.ResponseTooLarge;
        const text = output.written();
        // In particular, notification POSTs commonly return 202 Accepted.
        const accepted_status = status.class() == .success;
        if (!accepted_status) {
            std.debug.print("HTTP {d} {s}: {s}\n", .{ @intFromEnum(status), reason, text });
            return error.HttpRequestFailed;
        }
        if (notification) return null;
        if (std.ascii.eqlIgnoreCase(base_type, "application/json"))
            return try parseRpc(self.allocator, text, expected_id orelse return error.MissingExpectedResponseId);
        std.debug.print("unsupported response Content-Type: {s}\n", .{base_type});
        return error.UnsupportedContentType;
    }

    pub fn rpc(self: *McpClient, method: []const u8, params: ?Value) anyerror!Value {
        if ((std.mem.eql(u8, method, "tools/list") or std.mem.eql(u8, method, "tools/call")) and
            !self.supports_tools)
            return error.ServerDoesNotSupportTools;
        var request_value = Value{ .object = .empty };
        try request_value.object.put(self.allocator, "jsonrpc", .{ .string = "2.0" });
        const request_id: i64 = @intCast(self.next_id);
        try request_value.object.put(self.allocator, "id", .{ .integer = request_id });
        try request_value.object.put(self.allocator, "method", .{ .string = method });
        if (params) |p| try request_value.object.put(self.allocator, "params", p);
        self.next_id += 1;
        const body = try jsonString(self.allocator, request_value);
        return (try self.requestExpected(body, false, request_id, true, !std.mem.eql(u8, method, "initialize"))).?;
    }

    fn notifyInitialized(self: *McpClient) !void {
        var note = Value{ .object = .empty };
        try note.object.put(self.allocator, "jsonrpc", .{ .string = "2.0" });
        try note.object.put(self.allocator, "method", .{ .string = "notifications/initialized" });
        const body = try jsonString(self.allocator, note);
        _ = try self.request(body, true);
    }

    fn notifyCancelled(self: *McpClient, id: i64) !void {
        var params = Value{ .object = .empty };
        try params.object.put(self.allocator, "requestId", .{ .integer = id });
        var note = Value{ .object = .empty };
        try note.object.put(self.allocator, "jsonrpc", .{ .string = "2.0" });
        try note.object.put(self.allocator, "method", .{ .string = "notifications/cancelled" });
        try note.object.put(self.allocator, "params", params);
        const body = try jsonString(self.allocator, note);
        _ = try self.requestExpected(body, true, null, false, false);
    }

    fn respondServerRequest(self: *McpClient, id: Value, method: []const u8) !void {
        var response = Value{ .object = .empty };
        try response.object.put(self.allocator, "jsonrpc", .{ .string = "2.0" });
        try response.object.put(self.allocator, "id", id);
        if (std.mem.eql(u8, method, "ping")) {
            try response.object.put(self.allocator, "result", .{ .object = .empty });
        } else {
            var rpc_error = Value{ .object = .empty };
            try rpc_error.object.put(self.allocator, "code", .{ .integer = -32601 });
            try rpc_error.object.put(self.allocator, "message", .{ .string = "Method not found" });
            try response.object.put(self.allocator, "error", rpc_error);
        }
        const body = try jsonString(self.allocator, response);
        if (self.test_server_responses) |responses| {
            try responses.append(self.allocator, body);
            return;
        }
        _ = try self.requestExpected(body, true, null, false, false);
    }

    pub fn listTools(self: *McpClient) ![]const Tool {
        if (!self.supports_tools) return error.ServerDoesNotSupportTools;
        var tools: std.ArrayList(Tool) = .empty;
        var seen_cursors: std.StringHashMapUnmanaged(void) = .empty;
        defer seen_cursors.deinit(self.allocator);
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
            const entry = try seen_cursors.getOrPut(self.allocator, cursor.?);
            if (entry.found_existing) return error.RepeatedPaginationCursor;
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

fn parseRpc(allocator: Allocator, text: []const u8, expected_id: i64) !Value {
    const rpc = try std.json.parseFromSliceLeaky(Value, allocator, text, .{});
    if (rpc == .array) {
        for (rpc.array.items) |item| {
            if (responseIdMatches(item, expected_id)) return validateRpcResponse(allocator, item, expected_id);
        }
        return error.ResponseIdMismatch;
    }
    return validateRpcResponse(allocator, rpc, expected_id);
}

fn responseIdMatches(rpc: Value, expected_id: i64) bool {
    const id = get(rpc, "id") orelse return false;
    return id == .integer and id.integer == expected_id;
}

fn validateRpcResponse(allocator: Allocator, rpc: Value, expected_id: i64) !Value {
    const jsonrpc = getString(rpc, "jsonrpc") orelse return error.InvalidJsonRpcVersion;
    if (!std.mem.eql(u8, jsonrpc, "2.0")) return error.InvalidJsonRpcVersion;
    if (!responseIdMatches(rpc, expected_id)) return error.ResponseIdMismatch;
    const result = get(rpc, "result");
    const rpc_error = get(rpc, "error");
    if ((result == null) == (rpc_error == null)) return error.InvalidJsonRpcResponse;
    if (rpc_error) |err_value| {
        const code_value = get(err_value, "code") orelse return error.InvalidJsonRpcError;
        if (code_value != .integer) return error.InvalidJsonRpcError;
        const message = getString(err_value, "message") orelse return error.InvalidJsonRpcError;
        const code = displayScalar(allocator, code_value) catch "?";
        std.debug.print("RPC error [{s}]: {s}\n", .{ code, message });
        return error.JsonRpcError;
    }
    return result.?;
}

fn parseSse(self: *McpClient, body: []const u8, expected_id: i64) !Value {
    var reader = Io.Reader.fixed(body);
    return parseSseReader(self, &reader, expected_id);
}

fn parseSseReader(self: *McpClient, reader: *Io.Reader, expected_id: i64) !Value {
    const allocator = self.allocator;
    var last_parse_error: ?anyerror = null;
    var data: Io.Writer.Allocating = .init(allocator);
    defer data.deinit();
    var line: Io.Writer.Allocating = .init(allocator);
    defer line.deinit();
    var accumulated: usize = 0;
    while (true) {
        line.clearRetainingCapacity();
        const remaining = max_response_size + 1 - accumulated;
        const line_len = reader.streamDelimiterLimit(&line.writer, '\n', .limited(remaining)) catch |err| switch (err) {
            error.StreamTooLong => return error.ResponseTooLarge,
            else => return err,
        };
        accumulated = std.math.add(usize, accumulated, line_len) catch return error.ResponseTooLarge;
        if (accumulated > max_response_size) return error.ResponseTooLarge;
        const end_of_stream = blk: {
            const delimiter = reader.takeByte() catch |err| switch (err) {
                error.EndOfStream => break :blk true,
                else => return err,
            };
            std.debug.assert(delimiter == '\n');
            break :blk false;
        };
        if (!end_of_stream) {
            accumulated = std.math.add(usize, accumulated, 1) catch return error.ResponseTooLarge;
            if (accumulated > max_response_size) return error.ResponseTooLarge;
        }
        const text = std.mem.trimEnd(u8, line.written(), "\r");
        if (text.len == 0) {
            if (data.written().len != 0) {
                if (try processSseEvent(self, data.written(), expected_id, &last_parse_error)) |result| return result;
                data.clearRetainingCapacity();
            }
        } else if (std.mem.startsWith(u8, text, "data:")) {
            if (data.written().len != 0) try data.writer.writeByte('\n');
            try data.writer.writeAll(std.mem.trimStart(u8, text[5..], " "));
        }
        if (end_of_stream) {
            if (data.written().len != 0)
                if (try processSseEvent(self, data.written(), expected_id, &last_parse_error)) |result| return result;
            break;
        }
    }
    if (last_parse_error) |err| {
        std.debug.print("SSE contained no valid matching response; last JSON parse error: {s}\n", .{@errorName(err)});
        return err;
    }
    return error.SseMissingResponse;
}

fn processSseEvent(self: *McpClient, data: []const u8, expected_id: i64, last_parse_error: *?anyerror) !?Value {
    const rpc = std.json.parseFromSliceLeaky(Value, self.allocator, data, .{}) catch |err| {
        last_parse_error.* = err;
        return null;
    };
    const events = if (rpc == .array) rpc.array.items else &[_]Value{rpc};
    for (events) |event| {
        if (getString(event, "method")) |method| {
            if (get(event, "id")) |id| self.respondServerRequest(id, method) catch |err|
                std.debug.print("failed to respond to server request '{s}': {s}\n", .{ method, @errorName(err) });
            // Notifications have no id and require no response.
        } else if (responseIdMatches(event, expected_id)) {
            const encoded = try jsonString(self.allocator, event);
            return try parseRpc(self.allocator, encoded, expected_id);
        }
    }
    return null;
}

fn isReservedHeader(name: []const u8) bool {
    const reserved = [_][]const u8{ "accept", "content-type", "mcp-protocol-version", "mcp-session-id" };
    for (reserved) |candidate| if (std.ascii.eqlIgnoreCase(name, candidate)) return true;
    return false;
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

test "parseRpc rejects mismatched id" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(error.ResponseIdMismatch, parseRpc(arena.allocator(), "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{}}", 1));
}

test "parseRpc rejects missing jsonrpc field" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(error.InvalidJsonRpcVersion, parseRpc(arena.allocator(), "{\"id\":1,\"result\":{}}", 1));
}

test "parseRpc handles batch array" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const value = try parseRpc(arena.allocator(), "[{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{}},{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}]", 1);
    try std.testing.expect(get(value, "ok").?.bool);
}

test "parseRpc rejects result and error together" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(error.InvalidJsonRpcResponse, parseRpc(arena.allocator(), "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{},\"error\":{\"code\":-1,\"message\":\"bad\"}}", 1));
}

test "validateRpcResponse rejects non-2.0 jsonrpc" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const rpc = try std.json.parseFromSliceLeaky(Value, arena.allocator(), "{\"jsonrpc\":\"1.0\",\"id\":1,\"result\":{}}", .{});
    try std.testing.expectError(error.InvalidJsonRpcVersion, validateRpcResponse(arena.allocator(), rpc, 1));
}

test "parseSse matches by id not last event" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var client = McpClient.init(arena.allocator(), std.testing.io, .{ .name = "test", .endpoint = "http://example.test" });
    defer client.deinit();
    const value = try parseSse(&client, "data: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"wrong\":true}}\n\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"page\":1}}\n\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"page\":2}}\n\n", 1);
    try std.testing.expectEqual(@as(i64, 1), get(value, "page").?.integer);
}

test "parseSse handles server ping request" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var responses: std.ArrayList([]u8) = .empty;
    var client = McpClient.init(arena.allocator(), std.testing.io, .{ .name = "test", .endpoint = "http://example.test" });
    defer client.deinit();
    client.test_server_responses = &responses;
    _ = try parseSse(&client, "data: {\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"ping\"}\n\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n", 1);
    try std.testing.expectEqual(@as(usize, 1), responses.items.len);
    const response = try std.json.parseFromSliceLeaky(Value, arena.allocator(), responses.items[0], .{});
    try std.testing.expect(get(response, "result").? == .object);
    try std.testing.expectEqual(@as(usize, 0), get(response, "result").?.object.count());
}

test "parseSse handles server notification without response" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var responses: std.ArrayList([]u8) = .empty;
    var client = McpClient.init(arena.allocator(), std.testing.io, .{ .name = "test", .endpoint = "http://example.test" });
    defer client.deinit();
    client.test_server_responses = &responses;
    _ = try parseSse(&client, "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n", 1);
    try std.testing.expectEqual(@as(usize, 0), responses.items.len);
}
