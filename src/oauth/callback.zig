const std = @import("std");

const Allocator = std.mem.Allocator;
const Io = std.Io;
const clock = @import("../clock.zig");
const diagnostics_out = @import("../diagnostics.zig");

/// A browser opens several connections to a loopback redirect URI (preconnect,
/// `/favicon.ico`, retries). Non-callback requests are answered and ignored
/// instead of consuming the single authorization response.
pub const default_timeout_secs: u64 = 300;
const max_ignored_requests: usize = 32;

pub const Callback = struct {
    code: []const u8,
    state: []const u8,
    issuer: ?[]const u8 = null,
};

pub const AuthorizationError = struct {
    code: []const u8,
    description: ?[]const u8 = null,
    uri: ?[]const u8 = null,
};

pub const CallbackRequest = union(enum) {
    /// Not an authorization response: answered with 404 and ignored.
    ignored,
    /// The authorization server reported a failure (RFC 6749 section 4.1.2.1).
    denied: AuthorizationError,
    granted: Callback,
};

pub fn parseCallbackRequestLine(allocator: Allocator, line: []const u8) !CallbackRequest {
    var pieces = std.mem.splitScalar(u8, line, ' ');
    if (!std.mem.eql(u8, pieces.next() orelse return error.InvalidCallbackRequest, "GET"))
        return error.InvalidCallbackRequest;
    const target = pieces.next() orelse return error.InvalidCallbackRequest;
    const query_start = std.mem.indexOfScalar(u8, target, '?') orelse target.len;
    if (!std.mem.eql(u8, target[0..query_start], "/callback")) return .ignored;
    if (query_start == target.len) return .ignored;
    const query_end = std.mem.indexOfScalarPos(u8, target, query_start, '#') orelse target.len;
    var code: ?[]const u8 = null;
    var state: ?[]const u8 = null;
    var issuer: ?[]const u8 = null;
    var failure: ?[]const u8 = null;
    var description: ?[]const u8 = null;
    var uri: ?[]const u8 = null;
    var fields = std.mem.splitScalar(u8, target[query_start + 1 .. query_end], '&');
    while (fields.next()) |field| {
        const equals = std.mem.indexOfScalar(u8, field, '=') orelse continue;
        const name = field[0..equals];
        const decoded = try percentDecode(allocator, field[equals + 1 ..]);
        if (std.mem.eql(u8, name, "code")) code = decoded;
        if (std.mem.eql(u8, name, "state")) state = decoded;
        if (std.mem.eql(u8, name, "iss")) issuer = decoded;
        if (std.mem.eql(u8, name, "error")) failure = decoded;
        if (std.mem.eql(u8, name, "error_description")) description = decoded;
        if (std.mem.eql(u8, name, "error_uri")) uri = decoded;
    }
    if (failure) |value| return .{ .denied = .{ .code = value, .description = description, .uri = uri } };
    if (code == null and state == null) return .ignored;
    return .{ .granted = .{
        .code = code orelse return error.CallbackMissingCode,
        .state = state orelse return error.CallbackMissingState,
        .issuer = issuer,
    } };
}

pub fn percentDecode(allocator: Allocator, value: []const u8) ![]const u8 {
    var output: Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    var i: usize = 0;
    while (i < value.len) {
        if (value[i] == '%' and i + 2 < value.len) {
            try output.writer.writeByte(try std.fmt.parseInt(u8, value[i + 1 .. i + 3], 16));
            i += 3;
        } else {
            try output.writer.writeByte(if (value[i] == '+') ' ' else value[i]);
            i += 1;
        }
    }
    return output.toOwnedSlice();
}

pub fn bindCallback(io: Io) !std.Io.net.Server {
    const address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    return address.listen(io, .{ .reuse_address = true });
}

/// Waits up to `timeout_secs` for one authorization response on `server`.
pub fn acceptCallback(allocator: Allocator, io: Io, server: *std.Io.net.Server, timeout_secs: u64) !Callback {
    const Result = union(enum) { callback: anyerror!Callback, timeout: void };
    var completions: [2]Result = undefined;
    var select: Io.Select(Result) = .init(io, &completions);
    try select.concurrent(.callback, acceptCallbackLoop, .{ allocator, io, server });
    try select.concurrent(.timeout, clock.waitForTimeout, .{ io, timeout_secs });
    const result = try select.await();
    select.cancelDiscard();
    return switch (result) {
        .callback => |callback| callback,
        .timeout => {
            diagnostics_out.report("timed out after {d} seconds waiting for the OAuth redirect\n", .{timeout_secs});
            return error.OauthCallbackTimeout;
        },
    };
}

fn acceptCallbackLoop(allocator: Allocator, io: Io, server: *std.Io.net.Server) anyerror!Callback {
    var ignored: usize = 0;
    while (ignored <= max_ignored_requests) {
        const stream = try server.accept(io);
        defer stream.close(io);
        const request = readCallbackRequest(allocator, io, stream) catch |err| {
            diagnostics_out.warn("ignoring malformed request on the OAuth redirect port: {s}\n", .{@errorName(err)});
            ignored += 1;
            continue;
        };
        switch (request) {
            .granted => |callback| {
                try respond(io, stream, "200 OK", success_html);
                return callback;
            },
            .denied => |failure| {
                try respond(io, stream, "400 Bad Request", failure_html);
                diagnostics_out.report("authorization failed: {s}{s}{s}\n", .{
                    failure.code,
                    if (failure.description != null) ": " else "",
                    failure.description orelse "",
                });
                return error.OauthAuthorizationDenied;
            },
            .ignored => {
                try respond(io, stream, "404 Not Found", "not found");
                ignored += 1;
            },
        }
    }
    return error.OauthCallbackNoise;
}

fn readCallbackRequest(allocator: Allocator, io: Io, stream: std.Io.net.Stream) !CallbackRequest {
    var read_buffer: [16 * 1024]u8 = undefined;
    var reader = stream.reader(io, &read_buffer);
    const line = try reader.interface.takeDelimiterExclusive('\n');
    const request = try parseCallbackRequestLine(allocator, std.mem.trimEnd(u8, line, "\r"));
    while (true) {
        const header = reader.interface.takeDelimiterExclusive('\n') catch break;
        if (std.mem.trim(u8, header, "\r").len == 0) break;
    }
    return request;
}

const success_html = "<!doctype html><title>mcpx OAuth complete</title><p>Authorization complete. You may close this window.</p>";
const failure_html = "<!doctype html><title>mcpx OAuth failed</title><p>Authorization failed. See the mcpx output for details.</p>";

fn respond(io: Io, stream: std.Io.net.Stream, status: []const u8, body: []const u8) !void {
    var write_buffer: [1024]u8 = undefined;
    var writer = stream.writer(io, &write_buffer);
    try writer.interface.print(
        "HTTP/1.1 {s}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}",
        .{ status, body.len, body },
    );
    try writer.interface.flush();
}

test "callback parses authorization response issuer" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const result = try parseCallbackRequestLine(arena.allocator(), "GET /callback?code=x&state=y&iss=https%3A%2F%2Fissuer.example HTTP/1.1");
    try std.testing.expectEqualStrings("https://issuer.example", result.granted.issuer.?);
}

test "callback request line extracts and decodes code and state" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const request = try parseCallbackRequestLine(arena.allocator(), "GET /callback?code=a%2Fb&state=hello%20world HTTP/1.1");
    try std.testing.expectEqualStrings("a/b", request.granted.code);
    try std.testing.expectEqualStrings("hello world", request.granted.state);
}

test "browser noise on the redirect port is ignored" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    try std.testing.expect(try parseCallbackRequestLine(allocator, "GET /favicon.ico HTTP/1.1") == .ignored);
    try std.testing.expect(try parseCallbackRequestLine(allocator, "GET /callback HTTP/1.1") == .ignored);
    try std.testing.expect(try parseCallbackRequestLine(allocator, "GET /callback?utm=1 HTTP/1.1") == .ignored);
    try std.testing.expectError(
        error.InvalidCallbackRequest,
        parseCallbackRequestLine(allocator, "POST /callback?code=x&state=y HTTP/1.1"),
    );
}

test "authorization errors are reported instead of looking like a missing code" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const request = try parseCallbackRequestLine(
        arena.allocator(),
        "GET /callback?error=access_denied&error_description=user%20refused&state=y HTTP/1.1",
    );
    try std.testing.expectEqualStrings("access_denied", request.denied.code);
    try std.testing.expectEqualStrings("user refused", request.denied.description.?);
}

test "callback listener binds an ephemeral loopback port" {
    var server = try bindCallback(std.testing.io);
    defer server.deinit(std.testing.io);
    try std.testing.expect(server.socket.address.getPort() != 0);
}

test "callback waiting stops at the configured timeout" {
    var server = try bindCallback(std.testing.io);
    defer server.deinit(std.testing.io);
    try std.testing.expectError(
        error.OauthCallbackTimeout,
        acceptCallback(std.testing.allocator, std.testing.io, &server, 0),
    );
}
