const std = @import("std");
const rpc = @import("rpc.zig");
const pkce = @import("oauth/pkce.zig");
const token_store = @import("oauth/token_store.zig");
const callback = @import("oauth/callback.zig");

const Allocator = std.mem.Allocator;
const Io = std.Io;
const Value = std.json.Value;

pub const generateVerifier = pkce.generateVerifier;
pub const codeChallenge = pkce.codeChallenge;
pub const generateState = pkce.generateState;
const fixedState = pkce.fixedState;

pub const Token = token_store.Token;
pub const TokenStore = token_store.TokenStore;
pub const serializeTokens = token_store.serializeTokens;
pub const parseTokens = token_store.parseTokens;
pub const loadTokens = token_store.loadTokens;
pub const saveTokens = token_store.saveTokens;
pub const tokenNeedsRefresh = token_store.tokenNeedsRefresh;

pub const Callback = callback.Callback;
pub const parseCallbackRequestLine = callback.parseCallbackRequestLine;
const percentDecode = callback.percentDecode;
const bindCallback = callback.bindCallback;
const acceptCallback = callback.acceptCallback;

pub const OauthConfig = struct {
    client_id: ?[]const u8 = null,
    scopes: ?[]const u8 = null,
    register: bool = false,
};

const Metadata = struct {
    authorization_endpoint: []const u8,
    token_endpoint: []const u8,
    registration_endpoint: ?[]const u8 = null,
};

const TokenResponse = struct {
    access_token: []const u8,
    refresh_token: ?[]const u8,
    token_type: []const u8,
    expires_in: ?i64,
};

const Registration = struct { client_id: []const u8, client_secret: ?[]const u8 };

pub fn ensureToken(
    allocator: Allocator,
    io: Io,
    http: *std.http.Client,
    server_name: []const u8,
    endpoint: []const u8,
    config: OauthConfig,
    token_path: []const u8,
) !Token {
    var tokens = try loadTokens(io, allocator, token_path);
    defer tokens.deinit(allocator);
    if (tokens.get(server_name)) |stored| {
        if (!tokenNeedsRefresh(stored, unixNow(io))) return stored;
        if (stored.refresh_token != null) {
            const refreshed = refreshToken(allocator, http, endpoint, stored) catch null;
            if (refreshed) |token| {
                try tokens.put(allocator, server_name, token);
                try saveTokens(io, allocator, token_path, tokens);
                return token;
            }
        }
    }
    return authenticateAndStore(allocator, io, http, server_name, endpoint, config, token_path, &tokens);
}

pub fn forceAuthenticate(
    allocator: Allocator,
    io: Io,
    http: *std.http.Client,
    server_name: []const u8,
    endpoint: []const u8,
    config: OauthConfig,
    token_path: []const u8,
) !Token {
    var tokens = try loadTokens(io, allocator, token_path);
    defer tokens.deinit(allocator);
    return authenticateAndStore(allocator, io, http, server_name, endpoint, config, token_path, &tokens);
}

pub fn recoverUnauthorized(
    allocator: Allocator,
    io: Io,
    http: *std.http.Client,
    server_name: []const u8,
    endpoint: []const u8,
    config: OauthConfig,
    token_path: []const u8,
) !Token {
    var tokens = try loadTokens(io, allocator, token_path);
    defer tokens.deinit(allocator);
    if (tokens.get(server_name)) |stored| if (stored.refresh_token != null) {
        if (refreshToken(allocator, http, endpoint, stored)) |token| {
            try tokens.put(allocator, server_name, token);
            try saveTokens(io, allocator, token_path, tokens);
            return token;
        } else |_| {}
    };
    return authenticateAndStore(allocator, io, http, server_name, endpoint, config, token_path, &tokens);
}

fn authenticateAndStore(
    allocator: Allocator,
    io: Io,
    http: *std.http.Client,
    server_name: []const u8,
    endpoint: []const u8,
    config: OauthConfig,
    token_path: []const u8,
    tokens: *TokenStore,
) !Token {
    const metadata = try discoverMetadata(allocator, http, endpoint);
    var client_id = config.client_id;
    var client_secret: ?[]const u8 = null;

    var callback_server = try bindCallback(io);
    defer callback_server.deinit(io);
    const port = callback_server.socket.address.getPort();
    const redirect_uri = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/callback", .{port});

    if (config.register and client_id == null) {
        if (tokens.get(server_name)) |stored| {
            client_id = stored.client_id;
            client_secret = stored.client_secret;
        }
    }
    if (config.register and client_id == null) {
        const registered = try registerClient(allocator, http, metadata, redirect_uri);
        client_id = registered.client_id;
        client_secret = registered.client_secret;
    } else if (client_id == null) {
        if (tokens.get(server_name)) |stored| {
            client_id = stored.client_id;
            client_secret = stored.client_secret;
        }
    }
    const actual_client_id = client_id orelse return error.OauthClientIdRequired;
    const verifier = try generateVerifier(io, allocator);
    const challenge = try codeChallenge(allocator, verifier);
    const state = try generateState(io, allocator);
    const auth_url = try buildAuthorizationUrl(allocator, metadata.authorization_endpoint, actual_client_id, redirect_uri, config.scopes, challenge, state, endpoint);
    openBrowser(io, auth_url);
    const received = try acceptCallback(allocator, io, &callback_server);
    if (state.len != received.state.len or !std.crypto.timing_safe.eql([32]u8, fixedState(state), fixedState(received.state)))
        return error.OauthStateMismatch;
    const response = try exchangeCode(allocator, http, metadata.token_endpoint, received.code, verifier, redirect_uri, actual_client_id, client_secret);
    const token = tokenFromResponse(response, actual_client_id, client_secret, unixNow(io));
    try tokens.put(allocator, server_name, token);
    try saveTokens(io, allocator, token_path, tokens.*);
    return token;
}

fn discoverMetadata(allocator: Allocator, http: *std.http.Client, endpoint: []const u8) !Metadata {
    const uri = try std.Uri.parse(endpoint);
    const origin = try originUrl(allocator, uri);
    const endpoint_path = try componentText(allocator, uri.path);
    const candidates = [_][]const u8{
        try std.fmt.allocPrint(allocator, "{s}/.well-known/oauth-protected-resource{s}", .{ origin, endpoint_path }),
        try std.fmt.allocPrint(allocator, "{s}/.well-known/oauth-protected-resource", .{origin}),
    };
    const discovery_headers = &.{std.http.Header{ .name = "MCP-Protocol-Version", .value = "2025-03-26" }};
    var authorization_server: ?[]const u8 = null;
    for (candidates) |url| {
        const value = fetchJson(allocator, http, .GET, url, null, discovery_headers) catch continue;
        if (rpc.getString(value, "authorization_endpoint") != null and rpc.getString(value, "token_endpoint") != null)
            return metadataFromJson(value);
        if (rpc.getString(value, "authorization_server")) |server| authorization_server = server;
        if (value == .object) if (value.object.get("authorization_servers")) |servers| {
            if (servers == .array and servers.array.items.len > 0 and servers.array.items[0] == .string)
                authorization_server = servers.array.items[0].string;
        };
    }
    const issuer = authorization_server orelse origin;
    const metadata_url = try std.fmt.allocPrint(allocator, "{s}/.well-known/oauth-authorization-server", .{std.mem.trimEnd(u8, issuer, "/")});
    // Discovery failure means the server cannot be authenticated against; do
    // not guess endpoint paths. Surface the error so the caller aborts.
    const value = try fetchJson(allocator, http, .GET, metadata_url, null, discovery_headers);
    return metadataFromJson(value);
}

fn metadataFromJson(value: Value) !Metadata {
    return .{
        .authorization_endpoint = rpc.getString(value, "authorization_endpoint") orelse return error.OauthMetadataMissingAuthorizationEndpoint,
        .token_endpoint = rpc.getString(value, "token_endpoint") orelse return error.OauthMetadataMissingTokenEndpoint,
        .registration_endpoint = rpc.getString(value, "registration_endpoint"),
    };
}

fn registerClient(allocator: Allocator, http: *std.http.Client, metadata: Metadata, redirect_uri: []const u8) !Registration {
    const url = metadata.registration_endpoint orelse return error.OauthRegistrationUnsupported;
    var payload = Value{ .object = .empty };
    try payload.object.put(allocator, "client_name", .{ .string = "mcpx" });
    try payload.object.put(allocator, "redirect_uris", try stringArray(allocator, &.{redirect_uri}));
    try payload.object.put(allocator, "grant_types", try stringArray(allocator, &.{ "authorization_code", "refresh_token" }));
    try payload.object.put(allocator, "response_types", try stringArray(allocator, &.{"code"}));
    try payload.object.put(allocator, "token_endpoint_auth_method", .{ .string = "client_secret_post" });
    const body = try rpc.jsonString(allocator, payload);
    const value = try fetchJson(allocator, http, .POST, url, body, &.{.{ .name = "Content-Type", .value = "application/json" }});
    return .{
        .client_id = rpc.getString(value, "client_id") orelse return error.OauthRegistrationMissingClientId,
        .client_secret = rpc.getString(value, "client_secret"),
    };
}

fn exchangeCode(allocator: Allocator, http: *std.http.Client, token_endpoint: []const u8, code: []const u8, verifier: []const u8, redirect_uri: []const u8, client_id: []const u8, client_secret: ?[]const u8) !TokenResponse {
    var form: Io.Writer.Allocating = .init(allocator);
    defer form.deinit();
    try formField(&form.writer, "grant_type", "authorization_code", false);
    try formField(&form.writer, "code", code, true);
    try formField(&form.writer, "code_verifier", verifier, true);
    try formField(&form.writer, "redirect_uri", redirect_uri, true);
    try formField(&form.writer, "client_id", client_id, true);
    if (client_secret) |secret| try formField(&form.writer, "client_secret", secret, true);
    return parseTokenResponse(try fetchJson(allocator, http, .POST, token_endpoint, form.written(), &.{.{ .name = "Content-Type", .value = "application/x-www-form-urlencoded" }}));
}

fn refreshToken(allocator: Allocator, http: *std.http.Client, endpoint: []const u8, old: Token) !Token {
    const metadata = try discoverMetadata(allocator, http, endpoint);
    var form: Io.Writer.Allocating = .init(allocator);
    defer form.deinit();
    try formField(&form.writer, "grant_type", "refresh_token", false);
    try formField(&form.writer, "refresh_token", old.refresh_token.?, true);
    try formField(&form.writer, "client_id", old.client_id orelse return error.OauthClientIdRequired, true);
    if (old.client_secret) |secret| try formField(&form.writer, "client_secret", secret, true);
    const parsed = try parseTokenResponse(try fetchJson(allocator, http, .POST, metadata.token_endpoint, form.written(), &.{.{ .name = "Content-Type", .value = "application/x-www-form-urlencoded" }}));
    return .{
        .access_token = parsed.access_token,
        .refresh_token = parsed.refresh_token orelse old.refresh_token,
        .token_type = parsed.token_type,
        .expires_at = if (parsed.expires_in) |seconds| unixNow(http.io) + seconds else null,
        .client_id = old.client_id,
        .client_secret = old.client_secret,
    };
}

fn parseTokenResponse(value: Value) !TokenResponse {
    return .{
        .access_token = rpc.getString(value, "access_token") orelse return error.OauthTokenMissingAccessToken,
        .refresh_token = rpc.getString(value, "refresh_token"),
        .token_type = rpc.getString(value, "token_type") orelse "Bearer",
        .expires_in = rpc.getInteger(value, "expires_in"),
    };
}

fn tokenFromResponse(response: TokenResponse, client_id: []const u8, client_secret: ?[]const u8, now: i64) Token {
    return .{
        .access_token = response.access_token,
        .refresh_token = response.refresh_token,
        .token_type = response.token_type,
        .expires_at = if (response.expires_in) |seconds| now + seconds else null,
        .client_id = client_id,
        .client_secret = client_secret,
    };
}

fn openBrowser(io: Io, url: []const u8) void {
    std.debug.print("Open this URL to authorize mcpx:\n{s}\n", .{url});
    if (@import("builtin").os.tag == .linux) {
        var child = std.process.spawn(io, .{ .argv = &.{ "xdg-open", url }, .stdin = .ignore, .stdout = .ignore, .stderr = .ignore }) catch return;
        _ = child.wait(io) catch return;
    }
}

fn buildAuthorizationUrl(allocator: Allocator, endpoint: []const u8, client_id: []const u8, redirect_uri: []const u8, scopes: ?[]const u8, challenge: []const u8, state: []const u8, resource: []const u8) ![]const u8 {
    var output: Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    try output.writer.writeAll(endpoint);
    try output.writer.writeByte(if (std.mem.indexOfScalar(u8, endpoint, '?') == null) '?' else '&');
    try formField(&output.writer, "response_type", "code", false);
    try formField(&output.writer, "client_id", client_id, true);
    try formField(&output.writer, "redirect_uri", redirect_uri, true);
    if (scopes) |value| try formField(&output.writer, "scope", value, true);
    try formField(&output.writer, "code_challenge", challenge, true);
    try formField(&output.writer, "code_challenge_method", "S256", true);
    try formField(&output.writer, "state", state, true);
    try formField(&output.writer, "resource", resource, true);
    return output.toOwnedSlice();
}

fn fetchJson(allocator: Allocator, http: *std.http.Client, method: std.http.Method, url: []const u8, payload: ?[]const u8, headers: []const std.http.Header) !Value {
    var output: Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    const response = try http.fetch(.{
        .location = .{ .url = url },
        .method = method,
        .payload = payload,
        .response_writer = &output.writer,
        .extra_headers = headers,
    });
    if (response.status.class() != .success) return error.OauthHttpRequestFailed;
    return std.json.parseFromSliceLeaky(Value, allocator, output.written(), .{});
}

fn originUrl(allocator: Allocator, uri: std.Uri) ![]const u8 {
    const scheme = uri.scheme;
    const host = try componentText(allocator, uri.host orelse return error.OauthEndpointMissingHost);
    const port = if (uri.port) |value| try std.fmt.allocPrint(allocator, ":{d}", .{value}) else "";
    return std.fmt.allocPrint(allocator, "{s}://{s}{s}", .{ scheme, host, port });
}

fn componentText(allocator: Allocator, component: std.Uri.Component) ![]const u8 {
    return switch (component) {
        .raw => |value| value,
        .percent_encoded => |value| percentDecode(allocator, value),
    };
}

fn formField(writer: *Io.Writer, name: []const u8, value: []const u8, separator: bool) !void {
    if (separator) try writer.writeByte('&');
    try writer.writeAll(name);
    try writer.writeByte('=');
    for (value) |byte| {
        if (std.ascii.isAlphanumeric(byte) or byte == '-' or byte == '.' or byte == '_' or byte == '~')
            try writer.writeByte(byte)
        else
            try writer.print("%{X:0>2}", .{byte});
    }
}

fn stringArray(allocator: Allocator, values: []const []const u8) !Value {
    var array = Value{ .array = .init(allocator) };
    for (values) |value| try array.array.append(.{ .string = value });
    return array;
}

fn unixNow(io: Io) i64 {
    return @intCast(@divFloor(Io.Clock.real.now(io).nanoseconds, std.time.ns_per_s));
}
