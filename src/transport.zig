const std = @import("std");

const Io = std.Io;
const Value = std.json.Value;
const rpc = @import("rpc.zig");
const clock = @import("clock.zig");
const diagnostics_out = @import("diagnostics.zig");

const max_response_size = rpc.max_response_size;

pub const RequestContext = struct {
    pub const ParamHeader = struct {
        name: []const u8,
        value: []const u8,
    };

    method: ?[]const u8 = null,
    name: ?[]const u8 = null,
    param_headers: []const ParamHeader = &.{},
    initialize: bool = false,
    /// Set for the modern discovery probe only. A 404 or 405 then means "this
    /// server predates server/discover", while for every other request those
    /// statuses stay ordinary HTTP failures.
    probe: bool = false,
};

pub fn encodeHeaderValue(allocator: std.mem.Allocator, value: []const u8) ![]const u8 {
    var encode = value.len > 0 and (value[0] == ' ' or value[0] == '\t' or
        value[value.len - 1] == ' ' or value[value.len - 1] == '\t');
    if (std.mem.startsWith(u8, value, "=?base64?") and std.mem.endsWith(u8, value, "?="))
        encode = true;
    for (value) |byte| {
        if (byte < 0x20 or byte > 0x7e) {
            encode = true;
            break;
        }
    }
    if (!encode) return value;
    const encoded_len = std.base64.standard.Encoder.calcSize(value.len);
    const output = try allocator.alloc(u8, "=?base64?".len + encoded_len + "?=".len);
    @memcpy(output[0.."=?base64?".len], "=?base64?");
    _ = std.base64.standard.Encoder.encode(output["=?base64?".len..][0..encoded_len], value);
    @memcpy(output["=?base64?".len + encoded_len ..], "?=");
    return output;
}

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
        try headers.append(allocator, .{ .name = "Mcp-Name", .value = try encodeHeaderValue(allocator, name) });
    for (context.param_headers) |header|
        try headers.append(allocator, .{
            .name = try std.fmt.allocPrint(allocator, "Mcp-Param-{s}", .{header.name}),
            .value = try encodeHeaderValue(allocator, header.value),
        });
    return headers.toOwnedSlice(allocator);
}

/// `requestInner` and the SSE parser take the client as `anytype` so tests can
/// supply a light stand-in. This check replaces the silent duck typing with a
/// comptime contract, so changing `McpClient` fails the build instead of
/// quietly diverging from the test doubles.
pub fn assertClient(comptime Client: type) void {
    comptime {
        const required_fields = .{
            .{ "allocator", std.mem.Allocator },
            .{ "io", Io },
            .{ "http", std.http.Client },
            .{ "negotiated_version", []const u8 },
            .{ "session_id", ?[]const u8 },
            .{ "authorization_header", ?[]const u8 },
            .{ "server_supported_versions", ?[]const []const u8 },
        };
        for (required_fields) |field| {
            if (!@hasField(Client, field[0]))
                @compileError(@typeName(Client) ++ " is missing the client field '" ++ field[0] ++ "'");
            if (@FieldType(Client, field[0]) != field[1])
                @compileError(@typeName(Client) ++ "." ++ field[0] ++ " must be " ++ @typeName(field[1]));
        }
        for (.{ "server", "capabilities", "oauth_challenge" }) |name| {
            if (!@hasField(Client, name))
                @compileError(@typeName(Client) ++ " is missing the client field '" ++ name ++ "'");
        }
        for (.{ "allowsServerRequests", "respondServerRequest" }) |name| {
            if (!@hasDecl(Client, name))
                @compileError(@typeName(Client) ++ " is missing the client method '" ++ name ++ "'");
        }
    }
}

pub fn requestInner(self: anytype, body: []const u8, notification: bool, expected_id: ?i64, context: RequestContext) anyerror!?Value {
    assertClient(@TypeOf(self.*));
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
                diagnostics_out.warn("skipping reserved configured header '{s}'\n", .{entry.key_ptr.*});
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
    if (status == .unauthorized) {
        var challenge_headers = response.head.iterateHeaders();
        while (challenge_headers.next()) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, "WWW-Authenticate")) {
                self.oauth_challenge = try @import("oauth.zig").parseWwwAuthenticate(self.allocator, header.value);
                break;
            }
        }
    }
    if (self.capabilities.has_sessions and context.initialize and self.session_id == null) {
        var it = response.head.iterateHeaders();
        while (it.next()) |h| if (std.ascii.eqlIgnoreCase(h.name, "Mcp-Session-Id")) {
            if (!isValidSessionId(h.value)) return error.InvalidSessionId;
            self.session_id = try self.allocator.dupe(u8, h.value);
            break;
        };
    }
    var transfer_buffer: [64]u8 = undefined;
    var decompress: std.http.Decompress = undefined;
    const reader = response.readerDecompressing(&transfer_buffer, &decompress, &.{});
    const base_type = std.mem.trim(u8, std.mem.sliceTo(content_type, ';'), " \t");
    if (status.class() == .success and !notification and std.ascii.eqlIgnoreCase(base_type, "text/event-stream")) {
        const result = try rpc.parseSseReader(self, reader, expected_id orelse return error.MissingExpectedResponseId);
        return result.response;
    }

    // The buffer must outlive this function: `std.json.Value` strings can
    // reference the parsed input, and the parsed response is returned to the
    // caller. `self.allocator` is documented to be arena or process scoped.
    var output: Io.Writer.Allocating = .init(self.allocator);
    while (output.written().len <= max_response_size) {
        const remaining = max_response_size + 1 - output.written().len;
        _ = reader.stream(&output.writer, .limited(remaining)) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
    }
    if (output.written().len > max_response_size) return error.ResponseTooLarge;
    const text = try output.toOwnedSlice();
    const is_json = std.ascii.eqlIgnoreCase(base_type, "application/json");
    if (status.class() != .success) {
        // HTTP status controls failures except for the protocol negotiation
        // response. In particular, arbitrary JSON-RPC errors and malformed
        // JSON must not turn 401/403/429/5xx responses into RPC errors.
        if (is_json) if (expected_id) |id| {
            const supported = rpc.supportedVersionsFromError(self.allocator, text, id) catch null;
            if (supported) |versions| {
                _ = rpc.parseRpc(self.allocator, text, id) catch |err| {
                    if (err == error.UnsupportedProtocolVersionError) {
                        self.server_supported_versions = versions;
                        return err;
                    }
                };
            }
        };
        // A valid negotiation response above also wins over session expiry.
        // Every other session-bearing 404 means that the session expired.
        if (sent_session and status == .not_found) return error.SessionExpired;
        const safe_message = try diagnostics_out.safeRemoteMessage(self.allocator, "HTTP", @intFromEnum(status));
        diagnostics_out.report("{s}\n", .{safe_message});
        if (diagnostics_out.isDebug()) {
            const log_limit = 1024;
            const displayed = text[0..@min(text.len, log_limit)];
            diagnostics_out.report("HTTP debug response ({s}): {s}{s}\n", .{ reason, displayed, if (text.len > log_limit) "... (truncated)" else "" });
        }
        return classifyHttpFailure(status, context.probe);
    }
    if (notification) return null;
    if (is_json)
        return try rpc.parseRpcDiagnosed(
            self.allocator,
            text,
            expected_id orelse return error.MissingExpectedResponseId,
            diagnosticsSlot(self),
        );
    diagnostics_out.report("unsupported response Content-Type: {s}\n", .{base_type});
    return error.UnsupportedContentType;
}

fn diagnosticsSlot(self: anytype) ?*?rpc.RpcError {
    if (!@hasField(@TypeOf(self.*), "last_rpc_error")) return null;
    return &self.last_rpc_error;
}

fn classifyHttpFailure(status: std.http.Status, probe: bool) anyerror {
    return switch (status) {
        .unauthorized => error.HttpUnauthorized,
        .forbidden => error.HttpForbidden,
        .too_many_requests => error.HttpRateLimited,
        .not_found, .method_not_allowed => if (probe)
            error.LegacyProbeRejected
        else if (status == .not_found)
            error.HttpNotFound
        else
            error.HttpMethodNotAllowed,
        else => if (status.class() == .server_error)
            error.HttpServerError
        else
            error.HttpRequestFailed,
    };
}

pub const waitForTimeout = clock.waitForTimeout;

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

const TestClient = struct {
    allocator: std.mem.Allocator,
    io: Io,
    http: std.http.Client,
    server: struct {
        endpoint: []const u8,
        headers: ?@import("toml").HashMap([]const u8) = null,
        oauth: ?void = null,
    },
    negotiated_version: []const u8 = "2026-07-28",
    capabilities: struct {
        has_sessions: bool = false,
        has_mcp_method_header: bool = true,
        has_mcp_name_header: bool = true,
    } = .{},
    session_id: ?[]const u8 = null,
    authorization_header: ?[]const u8 = null,
    oauth_challenge: ?@import("oauth.zig").OauthChallenge = null,
    server_supported_versions: ?[]const []const u8 = null,

    pub fn allowsServerRequests(_: *@This()) bool {
        return false;
    }

    pub fn respondServerRequest(_: *@This(), _: Value, _: []const u8) !void {
        return error.UnexpectedServerRequest;
    }
};

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

test "modern request headers include encoded tool parameters" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const headers = try requestHeaders(arena.allocator(), "2026-07-28", .{
        .has_mcp_method_header = true,
        .has_mcp_name_header = true,
    }, .{
        .method = "tools/call",
        .name = "search",
        .param_headers = &.{.{ .name = "Greeting", .value = "Hello, 世界" }},
    });
    try std.testing.expectEqualStrings("Mcp-Param-Greeting", headers[4].name);
    try std.testing.expectEqualStrings("=?base64?SGVsbG8sIOS4lueVjA==?=", headers[4].value);
}

test "header values use the base64 sentinel only when required" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    try std.testing.expectEqualStrings("plain ASCII", try encodeHeaderValue(allocator, "plain ASCII"));
    try std.testing.expectEqualStrings("=?base64?SGVsbG8sIOS4lueVjA==?=", try encodeHeaderValue(allocator, "Hello, 世界"));
    try std.testing.expectEqualStrings("=?base64?IHBhZGRlZCA=?=", try encodeHeaderValue(allocator, " padded "));
    try std.testing.expectEqualStrings("=?base64?bGluZTEKbGluZTI=?=", try encodeHeaderValue(allocator, "line1\nline2"));
    try std.testing.expectEqualStrings(
        "=?base64?PT9iYXNlNjQ/U0dWc2JHOD0/PQ==?=",
        try encodeHeaderValue(allocator, "=?base64?SGVsbG8=?="),
    );
}

test "HTTP 400 unsupported-version response reaches JSON-RPC negotiation" {
    const test_http = @import("test_http.zig");
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const io = std.testing.io;
    const address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var server = try address.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    const endpoint = try std.fmt.allocPrint(
        arena.allocator(),
        "http://127.0.0.1:{d}/mcp",
        .{server.socket.address.getPort()},
    );
    const body =
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32022,\"message\":\"unsupported\",\"data\":{\"supported\":[\"2025-06-18\",\"2026-07-28\"]}}}";
    var script = test_http.Script{ .responses = &.{
        .{ .status = "400 Bad Request", .body = body },
    } };
    var serving = try io.concurrent(test_http.Script.serve, .{ &script, io, &server });
    var client = TestClient{
        .allocator = arena.allocator(),
        .io = io,
        .http = .{ .allocator = arena.allocator(), .io = io },
        .server = .{ .endpoint = endpoint },
    };
    defer client.http.deinit();

    try std.testing.expectError(
        error.UnsupportedProtocolVersionError,
        requestInner(&client, "{}", false, 1, .{ .method = "server/discover" }),
    );
    try serving.await(io);
    const supported = client.server_supported_versions.?;
    try std.testing.expectEqual(@as(usize, 2), supported.len);
    try std.testing.expectEqualStrings("2025-06-18", supported[0]);
    try std.testing.expectEqualStrings("2026-07-28", supported[1]);
}

test "JSON 401 captures OAuth challenge and remains an HTTP failure" {
    const test_http = @import("test_http.zig");
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const io = std.testing.io;
    const address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var server = try address.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    const endpoint = try std.fmt.allocPrint(arena.allocator(), "http://127.0.0.1:{d}/mcp", .{server.socket.address.getPort()});
    var script = test_http.Script{ .responses = &.{
        .{
            .status = "401 Unauthorized",
            .extra_headers = "WWW-Authenticate: Bearer scope=\"tools:read\"\r\n",
            .body = "{\"error\":\"invalid_token\"}",
        },
    } };
    var serving = try io.concurrent(test_http.Script.serve, .{ &script, io, &server });
    var client = TestClient{
        .allocator = arena.allocator(),
        .io = io,
        .http = .{ .allocator = arena.allocator(), .io = io },
        .server = .{ .endpoint = endpoint },
    };
    defer client.http.deinit();

    try std.testing.expectError(error.HttpUnauthorized, requestInner(&client, "{}", false, 1, .{}));
    try serving.await(io);
    try std.testing.expectEqualStrings("tools:read", client.oauth_challenge.?.scope.?);
}

test "negotiation error takes precedence over session-bearing 404" {
    const test_http = @import("test_http.zig");
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const io = std.testing.io;
    const address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var server = try address.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    const endpoint = try std.fmt.allocPrint(arena.allocator(), "http://127.0.0.1:{d}/mcp", .{server.socket.address.getPort()});
    var script = test_http.Script{ .responses = &.{
        .{
            .status = "404 Not Found",
            .body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32022,\"message\":\"unsupported\",\"data\":{\"supported\":[\"2025-06-18\"]}}}",
        },
    } };
    var serving = try io.concurrent(test_http.Script.serve, .{ &script, io, &server });
    var client = TestClient{
        .allocator = arena.allocator(),
        .io = io,
        .http = .{ .allocator = arena.allocator(), .io = io },
        .server = .{ .endpoint = endpoint },
        .capabilities = .{ .has_sessions = true },
        .session_id = "expired",
    };
    defer client.http.deinit();

    try std.testing.expectError(error.UnsupportedProtocolVersionError, requestInner(&client, "{}", false, 1, .{}));
    try serving.await(io);
    try std.testing.expectEqualStrings("2025-06-18", client.server_supported_versions.?[0]);
}

test "404 and 405 stay HTTP failures outside the discovery probe" {
    try std.testing.expectEqual(error.LegacyProbeRejected, classifyHttpFailure(.not_found, true));
    try std.testing.expectEqual(error.LegacyProbeRejected, classifyHttpFailure(.method_not_allowed, true));
    try std.testing.expectEqual(error.HttpNotFound, classifyHttpFailure(.not_found, false));
    try std.testing.expectEqual(error.HttpMethodNotAllowed, classifyHttpFailure(.method_not_allowed, false));
    try std.testing.expectEqual(error.HttpUnauthorized, classifyHttpFailure(.unauthorized, true));
    try std.testing.expectEqual(error.HttpServerError, classifyHttpFailure(.internal_server_error, true));
}

test "the client contract is enforced at comptime for the real client" {
    assertClient(@import("client.zig").McpClient);
    assertClient(TestClient);
}
