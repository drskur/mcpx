const std = @import("std");

const Io = std.Io;
const Value = std.json.Value;
const rpc = @import("rpc.zig");

const max_response_size = 16 * 1024 * 1024;

pub const RequestContext = struct {
    method: ?[]const u8 = null,
    name: ?[]const u8 = null,
    initialize: bool = false,
};

pub fn requestHeaders(
    allocator: std.mem.Allocator,
    version: []const u8,
    caps: anytype,
    context: RequestContext,
) ![]const std.http.Header {
    var headers: std.ArrayList(std.http.Header) = .empty;
    try headers.append(allocator, .{ .name = "Accept", .value = "application/json, text/event-stream" });
    try headers.append(allocator, .{ .name = "MCP-Protocol-Version", .value = version });
    if (caps.has_mcp_method_header) if (context.method) |method|
        try headers.append(allocator, .{ .name = "Mcp-Method", .value = method });
    if (caps.has_mcp_name_header) if (context.name) |name|
        try headers.append(allocator, .{ .name = "Mcp-Name", .value = name });
    return headers.toOwnedSlice(allocator);
}

pub fn requestInner(self: anytype, body: []const u8, notification: bool, expected_id: ?i64, context: RequestContext) anyerror!?Value {
    const uri = try std.Uri.parse(self.server.endpoint);
    var extra: std.ArrayList(std.http.Header) = .empty;
    defer extra.deinit(self.allocator);
    const protocol_headers = try requestHeaders(self.allocator, self.negotiated_version, self.capabilities, context);
    try extra.appendSlice(self.allocator, protocol_headers);
    const sent_session = self.capabilities.has_sessions and self.session_id != null;
    if (self.capabilities.has_sessions) if (self.session_id) |sid|
        try extra.append(self.allocator, .{ .name = "Mcp-Session-Id", .value = sid });
    if (self.authorization_header) |authorization|
        try extra.append(self.allocator, .{ .name = "Authorization", .value = authorization });
    if (self.server.headers) |headers| {
        var it = headers.map.iterator();
        while (it.next()) |entry| {
            if (isReservedHeader(entry.key_ptr.*, self.server.oauth != null)) {
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
    const connection = req.connection orelse return error.TransportConnectionMissing;
    try connection.flush();
    var response = try req.receiveHead(&.{});
    const status = response.head.status;
    const content_type = try self.allocator.dupe(u8, response.head.content_type orelse "");
    const reason = try self.allocator.dupe(u8, response.head.reason);
    if (self.capabilities.has_sessions and context.initialize and self.session_id == null) {
        var it = response.head.iterateHeaders();
        while (it.next()) |h| if (std.ascii.eqlIgnoreCase(h.name, "Mcp-Session-Id")) {
            if (!isValidSessionId(h.value)) return error.InvalidSessionId;
            self.session_id = try self.allocator.dupe(u8, h.value);
            break;
        };
    }
    if (sent_session and status == .not_found) return error.SessionExpired;
    var transfer_buffer: [64]u8 = undefined;
    var decompress: std.http.Decompress = undefined;
    const reader = response.readerDecompressing(&transfer_buffer, &decompress, &.{});
    const base_type = std.mem.trim(u8, std.mem.sliceTo(content_type, ';'), " \t");
    if (status.class() == .success and !notification and std.ascii.eqlIgnoreCase(base_type, "text/event-stream")) {
        const result = try rpc.parseSseReader(self, reader, expected_id orelse return error.MissingExpectedResponseId);
        return result.response;
    }

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
    if (status.class() != .success) {
        const log_limit = 1024;
        const displayed = text[0..@min(text.len, log_limit)];
        if (text.len > log_limit)
            std.debug.print("HTTP {d} {s}: {s}... (truncated)\n", .{ @intFromEnum(status), reason, displayed })
        else
            std.debug.print("HTTP {d} {s}: {s}\n", .{ @intFromEnum(status), reason, displayed });
        return if (status == .unauthorized) error.HttpUnauthorized else error.HttpRequestFailed;
    }
    if (notification) return null;
    if (std.ascii.eqlIgnoreCase(base_type, "application/json")) {
        if (expected_id) |id| {
            self.server_supported_versions = try rpc.supportedVersionsFromError(self.allocator, text, id);
        }
    }
    if (std.ascii.eqlIgnoreCase(base_type, "application/json"))
        return try rpc.parseRpc(self.allocator, text, expected_id orelse return error.MissingExpectedResponseId);
    std.debug.print("unsupported response Content-Type: {s}\n", .{base_type});
    return error.UnsupportedContentType;
}

pub fn waitForTimeout(io: Io, seconds: u64) void {
    const limited_seconds = @min(seconds, @as(u64, std.math.maxInt(i64)));
    Io.Timeout.sleep(.{ .duration = .{
        .clock = .awake,
        .raw = .fromSeconds(@intCast(limited_seconds)),
    } }, io) catch {};
}

pub fn notifyCancelled(self: anytype, id: i64) !void {
    var params = Value{ .object = .empty };
    try params.object.put(self.allocator, "requestId", .{ .integer = id });
    var note = Value{ .object = .empty };
    try note.object.put(self.allocator, "jsonrpc", .{ .string = "2.0" });
    try note.object.put(self.allocator, "method", .{ .string = "notifications/cancelled" });
    try note.object.put(self.allocator, "params", params);
    const body = try rpc.jsonString(self.allocator, note);
    _ = try self.requestExpectedWithTimeout(body, true, null, false, false, .{ .method = "notifications/cancelled" }, 5);
}

pub fn respondPing(self: anytype, id: Value) !void {
    var response = Value{ .object = .empty };
    try response.object.put(self.allocator, "jsonrpc", .{ .string = "2.0" });
    try response.object.put(self.allocator, "id", id);
    try response.object.put(self.allocator, "result", .{ .object = .empty });
    try sendServerResponse(self, response);
}

pub fn respondMethodNotFound(self: anytype, id: Value) !void {
    var response = Value{ .object = .empty };
    try response.object.put(self.allocator, "jsonrpc", .{ .string = "2.0" });
    try response.object.put(self.allocator, "id", id);
    var rpc_error = Value{ .object = .empty };
    try rpc_error.object.put(self.allocator, "code", .{ .integer = -32601 });
    try rpc_error.object.put(self.allocator, "message", .{ .string = "Method not found" });
    try response.object.put(self.allocator, "error", rpc_error);
    try sendServerResponse(self, response);
}

fn sendServerResponse(self: anytype, response: Value) !void {
    const body = try rpc.jsonString(self.allocator, response);
    if (self.test_server_responses) |responses| {
        try responses.append(self.allocator, body);
        return;
    }
    _ = try self.requestExpected(body, true, null, false, false, .{});
}

fn isReservedHeader(name: []const u8, oauth_active: bool) bool {
    if (oauth_active and std.ascii.eqlIgnoreCase(name, "authorization")) return true;
    const reserved = [_][]const u8{
        "accept",
        "content-type",
        "mcp-protocol-version",
        "mcp-session-id",
        "mcp-method",
        "mcp-name",
        "content-length",
        "transfer-encoding",
        "host",
        "connection",
        "keep-alive",
        "upgrade",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
    };
    for (reserved) |candidate| if (std.ascii.eqlIgnoreCase(name, candidate)) return true;
    return false;
}

fn isValidSessionId(value: []const u8) bool {
    if (value.len == 0) return false;
    for (value) |byte| if (byte < 0x21 or byte > 0x7e) return false;
    return true;
}

test "reserved headers include framing and hop-by-hop headers" {
    try std.testing.expect(isReservedHeader("Content-Length", false));
    try std.testing.expect(isReservedHeader("transfer-encoding", false));
    try std.testing.expect(isReservedHeader("HOST", false));
    try std.testing.expect(isReservedHeader("connection", false));
    try std.testing.expect(isReservedHeader("keep-alive", false));
    try std.testing.expect(isReservedHeader("upgrade", false));
    try std.testing.expect(isReservedHeader("proxy-authorization", false));
    try std.testing.expect(isReservedHeader("proxy-connection", false));
    try std.testing.expect(isReservedHeader("te", false));
    try std.testing.expect(isReservedHeader("trailer", false));
    try std.testing.expect(!isReservedHeader("authorization", false));
    try std.testing.expect(isReservedHeader("Authorization", true));
}

test "session IDs contain visible ASCII only" {
    try std.testing.expect(isValidSessionId("abc-123_~"));
    try std.testing.expect(!isValidSessionId(""));
    try std.testing.expect(!isValidSessionId("has space"));
    try std.testing.expect(!isValidSessionId("has\nnewline"));
    try std.testing.expect(!isValidSessionId(&[_]u8{0x7f}));
}

test "modern request headers derive method and name from structured context" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const headers = try requestHeaders(arena.allocator(), "2026-07-28", .{
        .has_mcp_method_header = true,
        .has_mcp_name_header = true,
    }, .{ .method = "tools/call", .name = "search" });
    try std.testing.expectEqualStrings("Mcp-Method", headers[2].name);
    try std.testing.expectEqualStrings("tools/call", headers[2].value);
    try std.testing.expectEqualStrings("Mcp-Name", headers[3].name);
    try std.testing.expectEqualStrings("search", headers[3].value);
}
