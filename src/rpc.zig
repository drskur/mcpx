const std = @import("std");

const Allocator = std.mem.Allocator;
const Io = std.Io;
const Value = std.json.Value;

const max_response_size = 16 * 1024 * 1024;

pub fn parseRpc(allocator: Allocator, text: []const u8, expected_id: i64) !Value {
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

pub const PendingServerRequest = struct {
    id: Value,
    method: []const u8,
};

pub const SseResult = struct {
    response: Value,
    pending_server_requests: []const PendingServerRequest,
};

fn parseSse(self: anytype, body: []const u8, expected_id: i64) !SseResult {
    var reader = Io.Reader.fixed(body);
    return parseSseReader(self, &reader, expected_id);
}

pub fn parseSseReader(self: anytype, reader: *Io.Reader, expected_id: i64) !SseResult {
    const allocator = self.allocator;
    var last_parse_error: ?anyerror = null;
    var pending_server_requests: std.ArrayList(PendingServerRequest) = .empty;
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
                if (try processSseEvent(self, data.written(), expected_id, &last_parse_error, &pending_server_requests)) |response|
                    return .{ .response = response, .pending_server_requests = try pending_server_requests.toOwnedSlice(allocator) };
                data.clearRetainingCapacity();
            }
        } else if (std.mem.startsWith(u8, text, "data:")) {
            if (data.written().len != 0) try data.writer.writeByte('\n');
            try data.writer.writeAll(std.mem.trimStart(u8, text[5..], " "));
        }
        if (end_of_stream) {
            if (data.written().len != 0)
                if (try processSseEvent(self, data.written(), expected_id, &last_parse_error, &pending_server_requests)) |response|
                    return .{ .response = response, .pending_server_requests = try pending_server_requests.toOwnedSlice(allocator) };
            break;
        }
    }
    if (last_parse_error) |err| {
        std.debug.print("SSE contained no valid matching response; last JSON parse error: {s}\n", .{@errorName(err)});
        return err;
    }
    return error.SseMissingResponse;
}

fn processSseEvent(
    self: anytype,
    data: []const u8,
    expected_id: i64,
    last_parse_error: *?anyerror,
    pending_server_requests: *std.ArrayList(PendingServerRequest),
) !?Value {
    const rpc = std.json.parseFromSliceLeaky(Value, self.allocator, data, .{}) catch |err| {
        last_parse_error.* = err;
        return null;
    };
    const events = if (rpc == .array) rpc.array.items else &[_]Value{rpc};
    for (events) |event| {
        const jsonrpc = getString(event, "jsonrpc");
        const valid_jsonrpc = jsonrpc != null and std.mem.eql(u8, jsonrpc.?, "2.0");
        if (valid_jsonrpc and getString(event, "method") != null) {
            const method = getString(event, "method").?;
            if (get(event, "id")) |id|
                try pending_server_requests.append(self.allocator, .{ .id = id, .method = method });
        } else if (responseIdMatches(event, expected_id)) {
            const encoded = try jsonString(self.allocator, event);
            return try parseRpc(self.allocator, encoded, expected_id);
        }
    }
    return null;
}

pub fn get(value: Value, key: []const u8) ?Value {
    return if (value == .object) value.object.get(key) else null;
}

pub fn getString(value: Value, key: []const u8) ?[]const u8 {
    const value_at_key = get(value, key) orelse return null;
    return if (value_at_key == .string) value_at_key.string else null;
}

pub fn jsonString(allocator: Allocator, value: Value) ![]u8 {
    var output: Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    try std.json.Stringify.value(value, .{}, &output.writer);
    return output.toOwnedSlice();
}

fn displayScalar(allocator: Allocator, value: Value) ![]const u8 {
    return if (value == .string) value.string else jsonString(allocator, value);
}

const TestClient = struct { allocator: Allocator };

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
    const value = try std.json.parseFromSliceLeaky(Value, arena.allocator(), "{\"jsonrpc\":\"1.0\",\"id\":1,\"result\":{}}", .{});
    try std.testing.expectError(error.InvalidJsonRpcVersion, validateRpcResponse(arena.allocator(), value, 1));
}

test "parseSse matches by id not last event" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var client = TestClient{ .allocator = arena.allocator() };
    const result = try parseSse(&client, "data: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"wrong\":true}}\n\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"page\":1}}\n\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"page\":2}}\n\n", 1);
    try std.testing.expectEqual(@as(i64, 1), get(result.response, "page").?.integer);
}

test "parseSse handles server ping request" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var client = TestClient{ .allocator = arena.allocator() };
    const result = try parseSse(&client, "data: {\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"ping\"}\n\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n", 1);
    try std.testing.expectEqual(@as(usize, 1), result.pending_server_requests.len);
    try std.testing.expectEqual(@as(i64, 9), result.pending_server_requests[0].id.integer);
    try std.testing.expectEqualStrings("ping", result.pending_server_requests[0].method);
}

test "parseSse handles server notification without response" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var client = TestClient{ .allocator = arena.allocator() };
    const result = try parseSse(&client, "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n", 1);
    try std.testing.expectEqual(@as(usize, 0), result.pending_server_requests.len);
}

test "parseSse ignores method-bearing messages without JSON-RPC 2.0" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var client = TestClient{ .allocator = arena.allocator() };
    const result = try parseSse(&client, "data: {\"jsonrpc\":\"1.0\",\"id\":9,\"method\":\"ping\"}\n\ndata: {\"id\":10,\"method\":\"ping\"}\n\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n", 1);
    try std.testing.expectEqual(@as(usize, 0), result.pending_server_requests.len);
}
