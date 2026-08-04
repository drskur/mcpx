const std = @import("std");
const rpc = @import("../rpc.zig");
const clock = @import("../clock.zig");
const diagnostics_out = @import("../diagnostics.zig");
const token_store = @import("token_store.zig");
const oauth_url = @import("url.zig");

const Allocator = std.mem.Allocator;
const Io = std.Io;
const Value = std.json.Value;
const Token = token_store.Token;
const validateToken = token_store.validateToken;
const unixNow = clock.unixNow;
const formField = oauth_url.formField;
const canonicalResourceUri = oauth_url.canonicalResourceUri;
const max_metadata_size = 1024 * 1024;

pub const TokenResponse = struct {
    access_token: []const u8,
    refresh_token: ?[]const u8,
    token_type: []const u8,
    expires_in: ?i64,
};

pub fn exchangeCode(allocator: Allocator, http: *std.http.Client, token_endpoint: []const u8, code: []const u8, verifier: []const u8, redirect_uri: []const u8, client_id: []const u8, client_secret: ?[]const u8, resource: []const u8) !TokenResponse {
    var form: Io.Writer.Allocating = .init(allocator);
    defer form.deinit();
    try formField(&form.writer, "grant_type", "authorization_code", false);
    try formField(&form.writer, "code", code, true);
    try formField(&form.writer, "code_verifier", verifier, true);
    try formField(&form.writer, "redirect_uri", redirect_uri, true);
    try formField(&form.writer, "client_id", client_id, true);
    try formField(&form.writer, "resource", resource, true);
    if (client_secret) |secret| try formField(&form.writer, "client_secret", secret, true);
    return parseTokenResponse(try fetchJson(allocator, http, .POST, token_endpoint, form.written(), &.{.{ .name = "Content-Type", .value = "application/x-www-form-urlencoded" }}));
}

pub fn refreshToken(allocator: Allocator, http: *std.http.Client, token_endpoint: []const u8, issuer: []const u8, endpoint: []const u8, old: Token) !Token {
    const resource = try canonicalResourceUri(allocator, endpoint);
    var form: Io.Writer.Allocating = .init(allocator);
    defer form.deinit();
    try formField(&form.writer, "grant_type", "refresh_token", false);
    try formField(&form.writer, "refresh_token", old.refresh_token.?, true);
    try formField(&form.writer, "client_id", old.client_id orelse return error.OauthClientIdRequired, true);
    try formField(&form.writer, "resource", resource, true);
    if (old.client_secret) |secret| try formField(&form.writer, "client_secret", secret, true);
    const parsed = try parseTokenResponse(try fetchJson(allocator, http, .POST, token_endpoint, form.written(), &.{.{ .name = "Content-Type", .value = "application/x-www-form-urlencoded" }}));
    return .{
        .issuer = issuer,
        .resource = resource,
        .access_token = parsed.access_token,
        .refresh_token = parsed.refresh_token orelse old.refresh_token,
        .token_type = parsed.token_type,
        .expires_at = if (parsed.expires_in) |seconds| unixNow(http.io) + seconds else null,
        .client_id = old.client_id,
        .client_secret = old.client_secret,
    };
}

pub fn parseTokenResponse(value: Value) !TokenResponse {
    const response: TokenResponse = .{
        .access_token = rpc.getString(value, "access_token") orelse return error.OauthTokenMissingAccessToken,
        .refresh_token = rpc.getString(value, "refresh_token"),
        .token_type = rpc.getString(value, "token_type") orelse "Bearer",
        .expires_in = rpc.getInteger(value, "expires_in"),
    };
    try validateToken(.{ .issuer = "", .access_token = response.access_token, .token_type = response.token_type });
    return response;
}

pub fn tokenFromResponse(response: TokenResponse, issuer: []const u8, resource: []const u8, client_id: []const u8, client_secret: ?[]const u8, now: i64) Token {
    return .{
        .issuer = issuer,
        .resource = resource,
        .access_token = response.access_token,
        .refresh_token = response.refresh_token,
        .token_type = response.token_type,
        .expires_at = if (response.expires_in) |seconds| now + seconds else null,
        .client_id = client_id,
        .client_secret = client_secret,
    };
}

pub fn fetchJson(allocator: Allocator, http: *std.http.Client, method: std.http.Method, url: []const u8, payload: ?[]const u8, headers: []const std.http.Header) !Value {
    // A fixed buffer caps what a remote server can make mcpx allocate; OAuth
    // metadata and token responses are far smaller than this.
    const buffer = try allocator.alloc(u8, max_metadata_size);
    var output: Io.Writer = .fixed(buffer);
    const response = http.fetch(.{
        .location = .{ .url = url },
        .method = method,
        .payload = payload,
        .response_writer = &output,
        .extra_headers = headers,
    }) catch |err| switch (err) {
        error.WriteFailed => return error.OauthResponseTooLarge,
        else => return err,
    };
    const body = output.buffered();
    if (response.status.class() != .success) {
        reportOauthFailure(allocator, url, response.status, body);
        return error.OauthHttpRequestFailed;
    }
    return rpc.parseJson(allocator, body);
}

pub fn reportOauthFailure(allocator: Allocator, url: []const u8, status: std.http.Status, body: []const u8) void {
    diagnostics_out.report("OAuth request to {s} failed: HTTP {d}: remote request failed\n", .{ url, @intFromEnum(status) });
    if (!diagnostics_out.isDebug()) return;
    const displayed = body[0..@min(body.len, 512)];
    if (rpc.parseJson(allocator, body)) |value| {
        if (rpc.getString(value, "error")) |code| {
            diagnostics_out.report("OAuth request to {s} failed: HTTP {d}: {s}{s}{s}\n", .{
                url,
                @intFromEnum(status),
                code,
                if (rpc.getString(value, "error_description") != null) ": " else "",
                rpc.getString(value, "error_description") orelse "",
            });
            return;
        }
    } else |_| {}
    diagnostics_out.report("OAuth request to {s} failed: HTTP {d}: {s}\n", .{ url, @intFromEnum(status), displayed });
}

test "authorization and refresh token forms include resource" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var code_form: Io.Writer.Allocating = .init(arena.allocator());
    try formField(&code_form.writer, "grant_type", "authorization_code", false);
    try formField(&code_form.writer, "resource", "https://mcp.example/mcp", true);
    try std.testing.expect(std.mem.indexOf(u8, code_form.written(), "resource=https%3A%2F%2Fmcp.example%2Fmcp") != null);
    var refresh_form: Io.Writer.Allocating = .init(arena.allocator());
    try formField(&refresh_form.writer, "grant_type", "refresh_token", false);
    try formField(&refresh_form.writer, "resource", "https://mcp.example/mcp", true);
    try std.testing.expect(std.mem.indexOf(u8, refresh_form.written(), "resource=https%3A%2F%2Fmcp.example%2Fmcp") != null);
}
