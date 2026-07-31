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
    issuer: []const u8,
    resource: []const u8,
    authorization_endpoint: []const u8,
    token_endpoint: []const u8,
    registration_endpoint: ?[]const u8 = null,
    authorization_response_iss_parameter_supported: bool = false,
};

pub const OauthChallenge = struct {
    resource_metadata: ?[]const u8 = null,
    scope: ?[]const u8 = null,
};

pub fn parseWwwAuthenticate(allocator: Allocator, header: []const u8) !OauthChallenge {
    const first_space = std.mem.indexOfScalar(u8, header, ' ') orelse return .{};
    if (!std.ascii.eqlIgnoreCase(std.mem.trim(u8, header[0..first_space], " \t"), "Bearer")) return .{};
    var result: OauthChallenge = .{};
    var fields = std.mem.splitScalar(u8, header[first_space + 1 ..], ',');
    while (fields.next()) |raw| {
        const field = std.mem.trim(u8, raw, " \t");
        const equals = std.mem.indexOfScalar(u8, field, '=') orelse continue;
        const name = std.mem.trim(u8, field[0..equals], " \t");
        const encoded = std.mem.trim(u8, field[equals + 1 ..], " \t");
        const value = if (encoded.len >= 2 and encoded[0] == '"' and encoded[encoded.len - 1] == '"')
            encoded[1 .. encoded.len - 1]
        else
            encoded;
        if (std.ascii.eqlIgnoreCase(name, "resource_metadata"))
            result.resource_metadata = try allocator.dupe(u8, value)
        else if (std.ascii.eqlIgnoreCase(name, "scope"))
            result.scope = try allocator.dupe(u8, value);
    }
    return result;
}

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
    const metadata = try discoverMetadata(allocator, http, endpoint, null);
    const resource = try canonicalResourceUri(allocator, endpoint);
    const key = try tokenKey(allocator, metadata.issuer, resource);
    if (tokens.get(key)) |stored| {
        if (!tokenMatches(stored, metadata.issuer, resource)) return error.OauthTokenBindingMismatch;
        if (!tokenNeedsRefresh(stored, unixNow(io))) return stored;
        if (stored.refresh_token != null) {
            const refreshed = refreshToken(allocator, http, metadata, endpoint, stored) catch null;
            if (refreshed) |token| {
                try tokens.put(allocator, key, token);
                try saveTokens(io, allocator, token_path, tokens);
                return token;
            }
        }
    }
    _ = server_name;
    return authenticateAndStore(allocator, io, http, metadata, endpoint, config, token_path, &tokens);
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
    const metadata = try discoverMetadata(allocator, http, endpoint, null);
    _ = server_name;
    return authenticateAndStore(allocator, io, http, metadata, endpoint, config, token_path, &tokens);
}

pub fn recoverUnauthorized(
    allocator: Allocator,
    io: Io,
    http: *std.http.Client,
    server_name: []const u8,
    endpoint: []const u8,
    config: OauthConfig,
    token_path: []const u8,
    challenge: ?OauthChallenge,
) !Token {
    var tokens = try loadTokens(io, allocator, token_path);
    defer tokens.deinit(allocator);
    const metadata = try discoverMetadata(allocator, http, endpoint, challenge);
    const resource = try canonicalResourceUri(allocator, endpoint);
    const key = try tokenKey(allocator, metadata.issuer, resource);
    if (tokens.get(key)) |stored| if (tokenMatches(stored, metadata.issuer, resource) and stored.refresh_token != null) {
        if (refreshToken(allocator, http, metadata, endpoint, stored)) |token| {
            try tokens.put(allocator, key, token);
            try saveTokens(io, allocator, token_path, tokens);
            return token;
        } else |_| {}
    };
    _ = server_name;
    var effective = config;
    if (effective.scopes == null) {
        if (challenge) |value| effective.scopes = value.scope;
    }
    return authenticateAndStore(allocator, io, http, metadata, endpoint, effective, token_path, &tokens);
}

fn authenticateAndStore(
    allocator: Allocator,
    io: Io,
    http: *std.http.Client,
    metadata: Metadata,
    endpoint: []const u8,
    config: OauthConfig,
    token_path: []const u8,
    tokens: *TokenStore,
) !Token {
    var client_id = config.client_id;
    var client_secret: ?[]const u8 = null;

    var callback_server = try bindCallback(io);
    defer callback_server.deinit(io);
    const port = callback_server.socket.address.getPort();
    const redirect_uri = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/callback", .{port});

    if (config.register and client_id == null) {
        if (findIssuerCredentials(tokens.*, metadata.issuer)) |stored| {
            client_id = stored.client_id;
            client_secret = stored.client_secret;
        }
    }
    if (config.register and client_id == null) {
        const registered = try registerClient(allocator, http, metadata, redirect_uri);
        client_id = registered.client_id;
        client_secret = registered.client_secret;
    } else if (client_id == null) {
        if (findIssuerCredentials(tokens.*, metadata.issuer)) |stored| {
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
    try validateAuthorizationIssuer(metadata.issuer, metadata.authorization_response_iss_parameter_supported, received.issuer);
    const response = try exchangeCode(allocator, http, metadata.token_endpoint, received.code, verifier, redirect_uri, actual_client_id, client_secret, endpoint);
    const resource = try canonicalResourceUri(allocator, endpoint);
    const token = tokenFromResponse(response, metadata.issuer, resource, actual_client_id, client_secret, unixNow(io));
    try tokens.put(allocator, try tokenKey(allocator, metadata.issuer, resource), token);
    try saveTokens(io, allocator, token_path, tokens.*);
    return token;
}

fn discoverMetadata(allocator: Allocator, http: *std.http.Client, endpoint: []const u8, challenge: ?OauthChallenge) !Metadata {
    const uri = try std.Uri.parse(endpoint);
    const origin = try originUrl(allocator, uri);
    const endpoint_path = try componentText(allocator, uri.path);
    const fallback_candidates = [_][]const u8{
        try std.fmt.allocPrint(allocator, "{s}/.well-known/oauth-protected-resource{s}", .{ origin, endpoint_path }),
        try std.fmt.allocPrint(allocator, "{s}/.well-known/oauth-protected-resource", .{origin}),
    };
    const discovery_headers = &.{std.http.Header{ .name = "MCP-Protocol-Version", .value = "2026-07-28" }};
    var authorization_server: ?[]const u8 = null;
    const challenge_candidate = if (challenge) |value| value.resource_metadata else null;
    var candidates: std.ArrayList([]const u8) = .empty;
    if (challenge_candidate) |url| try candidates.append(allocator, url);
    try candidates.appendSlice(allocator, &fallback_candidates);
    for (candidates.items) |url| {
        const value = fetchJson(allocator, http, .GET, url, null, discovery_headers) catch continue;
        if (rpc.getString(value, "resource")) |resource|
            if (!std.mem.eql(u8, resource, endpoint)) return error.OauthResourceMismatch;
        if (rpc.getString(value, "authorization_server")) |server| authorization_server = server;
        if (value == .object) if (value.object.get("authorization_servers")) |servers| {
            if (servers == .array and servers.array.items.len > 0 and servers.array.items[0] == .string)
                authorization_server = servers.array.items[0].string;
        };
    }
    const issuer = authorization_server orelse origin;
    const metadata_urls = try authorizationMetadataUrls(allocator, issuer);
    for (metadata_urls) |metadata_url| {
        const value = fetchJson(allocator, http, .GET, metadata_url, null, discovery_headers) catch continue;
        return metadataFromJson(value, issuer, endpoint);
    }
    return error.OauthMetadataDiscoveryFailed;
}

fn metadataFromJson(value: Value, expected_issuer: []const u8, resource: []const u8) !Metadata {
    const issuer = rpc.getString(value, "issuer") orelse return error.OauthMetadataMissingIssuer;
    if (!std.mem.eql(u8, issuer, expected_issuer)) return error.OauthIssuerMismatch;
    return .{
        .issuer = issuer,
        .resource = resource,
        .authorization_endpoint = rpc.getString(value, "authorization_endpoint") orelse return error.OauthMetadataMissingAuthorizationEndpoint,
        .token_endpoint = rpc.getString(value, "token_endpoint") orelse return error.OauthMetadataMissingTokenEndpoint,
        .registration_endpoint = rpc.getString(value, "registration_endpoint"),
        .authorization_response_iss_parameter_supported = getBool(value, "authorization_response_iss_parameter_supported") orelse false,
    };
}

fn registerClient(allocator: Allocator, http: *std.http.Client, metadata: Metadata, redirect_uri: []const u8) !Registration {
    const url = metadata.registration_endpoint orelse return error.OauthRegistrationUnsupported;
    var payload = Value{ .object = .empty };
    try payload.object.put(allocator, "client_name", .{ .string = "mcpx" });
    try payload.object.put(allocator, "application_type", .{ .string = "native" });
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

fn exchangeCode(allocator: Allocator, http: *std.http.Client, token_endpoint: []const u8, code: []const u8, verifier: []const u8, redirect_uri: []const u8, client_id: []const u8, client_secret: ?[]const u8, resource: []const u8) !TokenResponse {
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

fn refreshToken(allocator: Allocator, http: *std.http.Client, metadata: Metadata, endpoint: []const u8, old: Token) !Token {
    var form: Io.Writer.Allocating = .init(allocator);
    defer form.deinit();
    try formField(&form.writer, "grant_type", "refresh_token", false);
    try formField(&form.writer, "refresh_token", old.refresh_token.?, true);
    try formField(&form.writer, "client_id", old.client_id orelse return error.OauthClientIdRequired, true);
    try formField(&form.writer, "resource", endpoint, true);
    if (old.client_secret) |secret| try formField(&form.writer, "client_secret", secret, true);
    const parsed = try parseTokenResponse(try fetchJson(allocator, http, .POST, metadata.token_endpoint, form.written(), &.{.{ .name = "Content-Type", .value = "application/x-www-form-urlencoded" }}));
    return .{
        .issuer = metadata.issuer,
        .resource = try canonicalResourceUri(allocator, endpoint),
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

fn tokenFromResponse(response: TokenResponse, issuer: []const u8, resource: []const u8, client_id: []const u8, client_secret: ?[]const u8, now: i64) Token {
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

fn tokenKey(allocator: Allocator, issuer: []const u8, resource: []const u8) ![]const u8 {
    const raw = try std.fmt.allocPrint(allocator, "{s}\x00{s}", .{ issuer, resource });
    const encoded_len = std.base64.url_safe_no_pad.Encoder.calcSize(raw.len);
    const result = try allocator.alloc(u8, "token-".len + encoded_len);
    @memcpy(result[0.."token-".len], "token-");
    _ = std.base64.url_safe_no_pad.Encoder.encode(result["token-".len..], raw);
    return result;
}

fn tokenMatches(token: Token, issuer: []const u8, resource: []const u8) bool {
    return std.mem.eql(u8, token.issuer, issuer) and
        token.resource != null and std.mem.eql(u8, token.resource.?, resource);
}

fn findIssuerCredentials(tokens: TokenStore, issuer: []const u8) ?Token {
    var iterator = tokens.iterator();
    while (iterator.next()) |entry|
        if (std.mem.eql(u8, entry.value_ptr.issuer, issuer) and entry.value_ptr.client_id != null)
            return entry.value_ptr.*;
    return null;
}

fn canonicalResourceUri(allocator: Allocator, input: []const u8) ![]const u8 {
    var uri = try std.Uri.parse(input);
    if (uri.host == null or uri.fragment != null) return error.OauthInvalidResourceUri;
    uri.scheme = try std.ascii.allocLowerString(allocator, uri.scheme);
    const host = try componentText(allocator, uri.host.?);
    uri.host = .{ .raw = try std.ascii.allocLowerString(allocator, host) };
    if ((std.mem.eql(u8, uri.scheme, "https") and uri.port == 443) or
        (std.mem.eql(u8, uri.scheme, "http") and uri.port == 80))
        uri.port = null;
    var output: Io.Writer.Allocating = .init(allocator);
    try uri.writeToStream(&output.writer, .{
        .scheme = true,
        .authentication = true,
        .authority = true,
        .path = true,
        .query = true,
        .fragment = false,
        .port = true,
    });
    return output.toOwnedSlice();
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

fn authorizationMetadataUrls(allocator: Allocator, issuer: []const u8) ![]const []const u8 {
    const uri = try std.Uri.parse(issuer);
    const origin = try originUrl(allocator, uri);
    const path = std.mem.trim(u8, try componentText(allocator, uri.path), "/");
    var urls: std.ArrayList([]const u8) = .empty;
    try urls.append(allocator, if (path.len == 0)
        try std.fmt.allocPrint(allocator, "{s}/.well-known/oauth-authorization-server", .{origin})
    else
        try std.fmt.allocPrint(allocator, "{s}/.well-known/oauth-authorization-server/{s}", .{ origin, path }));
    try urls.append(allocator, if (path.len == 0)
        try std.fmt.allocPrint(allocator, "{s}/.well-known/openid-configuration", .{origin})
    else
        try std.fmt.allocPrint(allocator, "{s}/{s}/.well-known/openid-configuration", .{ origin, path }));
    return urls.toOwnedSlice(allocator);
}

pub fn validateAuthorizationIssuer(expected: []const u8, required: bool, received: ?[]const u8) !void {
    if (received) |issuer| {
        if (!std.mem.eql(u8, expected, issuer)) return error.OauthAuthorizationIssuerMismatch;
    } else if (required) return error.OauthAuthorizationIssuerMissing;
}

fn getBool(value: Value, key: []const u8) ?bool {
    const field = rpc.get(value, key) orelse return null;
    return if (field == .bool) field.bool else null;
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

test "authorization response issuer is exact and required when advertised" {
    try validateAuthorizationIssuer("https://issuer.example", true, "https://issuer.example");
    try std.testing.expectError(error.OauthAuthorizationIssuerMismatch, validateAuthorizationIssuer("https://issuer.example", false, "https://other.example"));
    try std.testing.expectError(error.OauthAuthorizationIssuerMissing, validateAuthorizationIssuer("https://issuer.example", true, null));
    try validateAuthorizationIssuer("https://issuer.example", false, null);
}

test "WWW-Authenticate parser preserves resource metadata and scope" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const challenge = try parseWwwAuthenticate(arena.allocator(), "Bearer realm=\"mcp\", resource_metadata=\"https://mcp.example/.well-known/oauth-protected-resource\", scope=\"tools read\"");
    try std.testing.expectEqualStrings("https://mcp.example/.well-known/oauth-protected-resource", challenge.resource_metadata.?);
    try std.testing.expectEqualStrings("tools read", challenge.scope.?);
}

test "authorization metadata well-known URLs preserve issuer paths" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const urls = try authorizationMetadataUrls(arena.allocator(), "https://issuer.example/tenant/a");
    try std.testing.expectEqualStrings("https://issuer.example/.well-known/oauth-authorization-server/tenant/a", urls[0]);
    try std.testing.expectEqualStrings("https://issuer.example/tenant/a/.well-known/openid-configuration", urls[1]);
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

test "tokens are keyed and verified by issuer and canonical resource" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const issuer = "https://issuer.example";
    const first = try canonicalResourceUri(allocator, "HTTPS://MCP.EXAMPLE:443/mcp");
    const same = try canonicalResourceUri(allocator, "https://mcp.example/mcp");
    const different = try canonicalResourceUri(allocator, "https://mcp.example/other");
    try std.testing.expectEqualStrings(first, same);
    try std.testing.expectEqualStrings(
        try tokenKey(allocator, issuer, first),
        try tokenKey(allocator, issuer, same),
    );
    try std.testing.expect(!std.mem.eql(
        u8,
        try tokenKey(allocator, issuer, first),
        try tokenKey(allocator, issuer, different),
    ));
    const token: Token = .{ .issuer = issuer, .resource = first, .access_token = "bound" };
    try std.testing.expect(tokenMatches(token, issuer, same));
    try std.testing.expect(!tokenMatches(token, issuer, different));
    try std.testing.expect(!tokenMatches(.{ .issuer = issuer, .access_token = "legacy" }, issuer, same));
}
