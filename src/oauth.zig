const std = @import("std");
const rpc = @import("rpc.zig");
const pkce = @import("oauth/pkce.zig");
const token_store = @import("oauth/token_store.zig");
const callback = @import("oauth/callback.zig");

const Allocator = std.mem.Allocator;
const Io = std.Io;
const Value = std.json.Value;

const clock = @import("clock.zig");
const diagnostics_out = @import("diagnostics.zig");

const generateVerifier = pkce.generateVerifier;
const codeChallenge = pkce.codeChallenge;
const generateState = pkce.generateState;
const statesMatch = pkce.statesMatch;
const unixNow = clock.unixNow;

// `Token` is part of the client-facing API: the CLI turns it into a header.
pub const Token = token_store.Token;
const TokenStore = token_store.TokenStore;
const loadTokens = token_store.loadTokens;
const saveTokens = token_store.saveTokens;
const tokenNeedsRefresh = token_store.tokenNeedsRefresh;
const validateToken = token_store.validateToken;

const percentDecode = callback.percentDecode;
const bindCallback = callback.bindCallback;
const acceptCallback = callback.acceptCallback;

pub const OauthConfig = struct {
    client_id: ?[]const u8 = null,
    scopes: ?[]const u8 = null,
    register: bool = false,
};

const max_metadata_size = 1024 * 1024;

const Metadata = struct {
    issuer: []const u8,
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
    return authenticateAndStore(allocator, io, http, metadata, endpoint, config, token_path, &tokens);
}

pub fn forceAuthenticate(
    allocator: Allocator,
    io: Io,
    http: *std.http.Client,
    endpoint: []const u8,
    config: OauthConfig,
    token_path: []const u8,
) !Token {
    var tokens = try loadTokens(io, allocator, token_path);
    defer tokens.deinit(allocator);
    const metadata = try discoverMetadata(allocator, http, endpoint, null);
    return authenticateAndStore(allocator, io, http, metadata, endpoint, config, token_path, &tokens);
}

pub fn recoverUnauthorized(
    allocator: Allocator,
    io: Io,
    http: *std.http.Client,
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
    const resource = try canonicalResourceUri(allocator, endpoint);
    const verifier = try generateVerifier(io, allocator);
    const challenge = try codeChallenge(allocator, verifier);
    const state = try generateState(io, allocator);
    const auth_url = try buildAuthorizationUrl(allocator, metadata.authorization_endpoint, actual_client_id, redirect_uri, config.scopes, challenge, state, resource);
    openBrowser(io, auth_url);
    const received = try acceptCallback(allocator, io, &callback_server, callback.default_timeout_secs);
    if (!statesMatch(state, received.state)) return error.OauthStateMismatch;
    try validateAuthorizationIssuer(metadata.issuer, received.issuer, metadata.authorization_response_iss_parameter_supported);
    const response = try exchangeCode(allocator, http, metadata.token_endpoint, received.code, verifier, redirect_uri, actual_client_id, client_secret, resource);
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
    var issuers: []const []const u8 = &.{};
    var candidates: std.ArrayList([]const u8) = .empty;
    // A `WWW-Authenticate` challenge is server controlled, so its metadata URL
    // is only followed when it stays on the resource server itself (RFC 9728
    // section 3.3). Otherwise the server could aim discovery at any host.
    if (challenge) |value| if (value.resource_metadata) |url| {
        if (sameOrigin(allocator, url, endpoint)) |_|
            try candidates.append(allocator, url)
        else |err|
            diagnostics_out.warn("ignoring WWW-Authenticate resource_metadata '{s}': {s}\n", .{ url, @errorName(err) });
    };
    try candidates.appendSlice(allocator, &fallback_candidates);
    for (candidates.items) |url| {
        const value = fetchDiscoveryJson(allocator, http, url, discovery_headers, endpoint, .resource) catch continue;
        issuers = try validateProtectedResourceMetadata(allocator, value, endpoint);
        break;
    }
    if (issuers.len == 0) return error.OauthProtectedResourceMetadataDiscoveryFailed;
    // Every advertised authorization server is tried in order before failing.
    for (issuers) |issuer| {
        const metadata_urls = try authorizationMetadataUrls(allocator, issuer);
        for (metadata_urls) |metadata_url| {
            const value = fetchDiscoveryJson(allocator, http, metadata_url, discovery_headers, issuer, .authorization_server) catch continue;
            return metadataFromJson(allocator, value, issuer) catch |err| {
                diagnostics_out.warn("rejecting authorization server metadata at {s}: {s}\n", .{ metadata_url, @errorName(err) });
                continue;
            };
        }
    }
    return error.OauthMetadataDiscoveryFailed;
}

fn metadataFromJson(allocator: Allocator, value: Value, expected_issuer: []const u8) !Metadata {
    const issuer = rpc.getString(value, "issuer") orelse return error.OauthMetadataMissingIssuer;
    if (!std.mem.eql(u8, issuer, expected_issuer)) return error.OauthIssuerMismatch;
    const authorization_endpoint = rpc.getString(value, "authorization_endpoint") orelse return error.OauthMetadataMissingAuthorizationEndpoint;
    const token_endpoint = rpc.getString(value, "token_endpoint") orelse return error.OauthMetadataMissingTokenEndpoint;
    const registration_endpoint = rpc.getString(value, "registration_endpoint");
    const response_iss_supported = if (rpc.get(value, "authorization_response_iss_parameter_supported")) |supported| switch (supported) {
        .bool => supported.bool,
        else => return error.OauthMetadataInvalidAuthorizationResponseIssuerSupport,
    } else false;
    // Credentials and codes must never travel over cleartext HTTP.
    try requireSecureUrl(allocator, authorization_endpoint);
    try requireSecureUrl(allocator, token_endpoint);
    if (registration_endpoint) |url| try requireSecureUrl(allocator, url);
    return .{
        .issuer = issuer,
        .authorization_endpoint = authorization_endpoint,
        .token_endpoint = token_endpoint,
        .registration_endpoint = registration_endpoint,
        .authorization_response_iss_parameter_supported = response_iss_supported,
    };
}

/// Accepts `https` URLs, plus `http` on loopback hosts for local development.
fn requireSecureUrl(allocator: Allocator, url: []const u8) !void {
    const uri = std.Uri.parse(url) catch return error.OauthInsecureUrl;
    const host = try componentText(allocator, uri.host orelse return error.OauthInsecureUrl);
    if (std.ascii.eqlIgnoreCase(uri.scheme, "https")) return;
    if (!std.ascii.eqlIgnoreCase(uri.scheme, "http")) return error.OauthInsecureUrl;
    if (isLoopbackHost(host)) return;
    return error.OauthInsecureUrl;
}

fn isLoopbackHost(host: []const u8) bool {
    if (std.ascii.eqlIgnoreCase(host, "localhost")) return true;
    if (std.mem.eql(u8, host, "::1") or std.mem.eql(u8, host, "[::1]")) return true;
    return std.mem.startsWith(u8, host, "127.");
}

fn sameOrigin(allocator: Allocator, url: []const u8, endpoint: []const u8) !void {
    const candidate = std.Uri.parse(url) catch return error.OauthChallengeInvalidUrl;
    const expected = try std.Uri.parse(endpoint);
    if (!std.ascii.eqlIgnoreCase(candidate.scheme, expected.scheme)) return error.OauthChallengeOriginMismatch;
    const candidate_host = try componentText(allocator, candidate.host orelse return error.OauthChallengeInvalidUrl);
    const expected_host = try componentText(allocator, expected.host orelse return error.OauthEndpointMissingHost);
    if (!std.ascii.eqlIgnoreCase(candidate_host, expected_host)) return error.OauthChallengeOriginMismatch;
    if (defaultedPort(candidate) != defaultedPort(expected)) return error.OauthChallengeOriginMismatch;
}

fn defaultedPort(uri: std.Uri) u16 {
    return uri.port orelse if (std.ascii.eqlIgnoreCase(uri.scheme, "https")) 443 else 80;
}

fn registerClient(allocator: Allocator, http: *std.http.Client, metadata: Metadata, redirect_uri: []const u8) !Registration {
    const url = metadata.registration_endpoint orelse return error.OauthRegistrationUnsupported;
    var payload = Value{ .object = .empty };
    try payload.object.put(allocator, "client_name", .{ .string = "mcpx" });
    try payload.object.put(allocator, "application_type", .{ .string = "native" });
    try payload.object.put(allocator, "redirect_uris", try stringArray(allocator, &.{redirect_uri}));
    try payload.object.put(allocator, "grant_types", try stringArray(allocator, &.{ "authorization_code", "refresh_token" }));
    try payload.object.put(allocator, "response_types", try stringArray(allocator, &.{"code"}));
    // A CLI is a public client: PKCE replaces client authentication, so no
    // secret has to be stored on disk (RFC 8252 section 8.4, OAuth 2.1).
    try payload.object.put(allocator, "token_endpoint_auth_method", .{ .string = "none" });
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
    const resource = try canonicalResourceUri(allocator, endpoint);
    var form: Io.Writer.Allocating = .init(allocator);
    defer form.deinit();
    try formField(&form.writer, "grant_type", "refresh_token", false);
    try formField(&form.writer, "refresh_token", old.refresh_token.?, true);
    try formField(&form.writer, "client_id", old.client_id orelse return error.OauthClientIdRequired, true);
    try formField(&form.writer, "resource", resource, true);
    if (old.client_secret) |secret| try formField(&form.writer, "client_secret", secret, true);
    const parsed = try parseTokenResponse(try fetchJson(allocator, http, .POST, metadata.token_endpoint, form.written(), &.{.{ .name = "Content-Type", .value = "application/x-www-form-urlencoded" }}));
    return .{
        .issuer = metadata.issuer,
        .resource = resource,
        .access_token = parsed.access_token,
        .refresh_token = parsed.refresh_token orelse old.refresh_token,
        .token_type = parsed.token_type,
        .expires_at = if (parsed.expires_in) |seconds| unixNow(http.io) + seconds else null,
        .client_id = old.client_id,
        .client_secret = old.client_secret,
    };
}

fn parseTokenResponse(value: Value) !TokenResponse {
    const response: TokenResponse = .{
        .access_token = rpc.getString(value, "access_token") orelse return error.OauthTokenMissingAccessToken,
        .refresh_token = rpc.getString(value, "refresh_token"),
        .token_type = rpc.getString(value, "token_type") orelse "Bearer",
        .expires_in = rpc.getInteger(value, "expires_in"),
    };
    try validateToken(.{ .issuer = "", .access_token = response.access_token, .token_type = response.token_type });
    return response;
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
    const canonical = try output.toOwnedSlice();
    if (uri.path.isEmpty() and uri.query == null and canonical.len > 0 and canonical[canonical.len - 1] == '/')
        return canonical[0 .. canonical.len - 1];
    return canonical;
}

fn openBrowser(io: Io, url: []const u8) void {
    diagnostics_out.report("Open this URL to authorize mcpx:\n{s}\n", .{url});
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
        try std.fmt.allocPrint(allocator, "{s}/.well-known/openid-configuration/{s}", .{ origin, path }));
    if (path.len != 0) try urls.append(allocator, try std.fmt.allocPrint(allocator, "{s}/{s}/.well-known/openid-configuration", .{ origin, path }));
    return urls.toOwnedSlice(allocator);
}

pub fn validateAuthorizationIssuer(expected: []const u8, received: ?[]const u8, advertised: bool) !void {
    const issuer = received orelse {
        if (advertised) return error.OauthAuthorizationIssuerMissing;
        return;
    };
    if (!std.mem.eql(u8, expected, issuer)) return error.OauthAuthorizationIssuerMismatch;
}

fn validateProtectedResourceMetadata(allocator: Allocator, value: Value, endpoint: []const u8) ![]const []const u8 {
    if (value != .object) return error.OauthProtectedResourceMetadataMustBeObject;
    const resource = rpc.getString(value, "resource") orelse return error.OauthProtectedResourceMetadataMissingResource;
    const expected_resource = try canonicalResourceUri(allocator, endpoint);
    const actual_resource = try canonicalResourceUri(allocator, resource);
    if (!std.mem.eql(u8, expected_resource, actual_resource)) return error.OauthResourceMismatch;
    const servers = rpc.get(value, "authorization_servers") orelse
        return error.OauthProtectedResourceMetadataMissingAuthorizationServers;
    if (servers != .array or servers.array.items.len == 0)
        return error.OauthProtectedResourceMetadataMissingAuthorizationServers;
    var issuers: std.ArrayList([]const u8) = .empty;
    for (servers.array.items) |server| {
        if (server != .string or server.string.len == 0)
            return error.OauthProtectedResourceMetadataInvalidAuthorizationServer;
        const issuer = std.Uri.parse(server.string) catch
            return error.OauthProtectedResourceMetadataInvalidAuthorizationServer;
        if (issuer.host == null or issuer.fragment != null)
            return error.OauthProtectedResourceMetadataInvalidAuthorizationServer;
        requireSecureUrl(allocator, server.string) catch
            return error.OauthProtectedResourceMetadataInsecureAuthorizationServer;
        try issuers.append(allocator, server.string);
    }
    return issuers.toOwnedSlice(allocator);
}

fn fetchJson(allocator: Allocator, http: *std.http.Client, method: std.http.Method, url: []const u8, payload: ?[]const u8, headers: []const std.http.Header) !Value {
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

const DiscoveryPolicy = enum { resource, authorization_server };
const max_discovery_redirects = 8;

fn fetchDiscoveryJson(allocator: Allocator, http: *std.http.Client, initial_url: []const u8, headers: []const std.http.Header, policy_url: []const u8, policy: DiscoveryPolicy) !Value {
    var current = initial_url;
    var visited: std.StringHashMapUnmanaged(void) = .empty;
    defer visited.deinit(allocator);
    var redirects: usize = 0;
    while (true) {
        if (visited.contains(current)) return error.OauthDiscoveryRedirectLoop;
        try visited.put(allocator, try allocator.dupe(u8, current), {});
        try validateDiscoveryUrl(allocator, current, policy_url, policy);

        const uri = std.Uri.parse(current) catch return error.OauthDiscoveryRedirectInvalidUrl;
        var request = try http.request(.GET, uri, .{ .extra_headers = headers, .redirect_behavior = .unhandled });
        errdefer request.deinit();
        try request.sendBodiless();
        var response = try request.receiveHead(&.{});
        if (response.head.status.class() == .redirect) {
            const location = response.head.location orelse return error.OauthDiscoveryRedirectMissingLocation;
            if (redirects == max_discovery_redirects) return error.OauthDiscoveryTooManyRedirects;
            current = try resolveRedirectUrl(allocator, current, location);
            redirects += 1;
            request.deinit();
            continue;
        }
        var transfer_buffer: [64]u8 = undefined;
        var decompress: std.http.Decompress = undefined;
        const reader = response.readerDecompressing(&transfer_buffer, &decompress, &.{});
        const buffer = try allocator.alloc(u8, max_metadata_size + 1);
        var output: Io.Writer = .fixed(buffer);
        _ = reader.stream(&output, .limited(max_metadata_size + 1)) catch |err| switch (err) {
            error.EndOfStream => {},
            else => return err,
        };
        const body = output.buffered();
        if (body.len > max_metadata_size) return error.OauthResponseTooLarge;
        if (response.head.status.class() != .success) {
            reportOauthFailure(allocator, current, response.head.status, body);
            request.deinit();
            return error.OauthHttpRequestFailed;
        }
        const value = try rpc.parseJson(allocator, body);
        request.deinit();
        return value;
    }
}

fn validateDiscoveryUrl(allocator: Allocator, url: []const u8, policy_url: []const u8, policy: DiscoveryPolicy) !void {
    sameOrigin(allocator, url, policy_url) catch return error.OauthDiscoveryRedirectPolicyViolation;
    if (policy == .authorization_server) try requireSecureUrl(allocator, url);
}

fn resolveRedirectUrl(allocator: Allocator, base_url: []const u8, location: []const u8) ![]const u8 {
    if (location.len == 0) return error.OauthDiscoveryRedirectInvalidUrl;
    if (std.mem.startsWith(u8, location, "https://") or std.mem.startsWith(u8, location, "http://"))
        return allocator.dupe(u8, location);
    if (std.mem.indexOfScalar(u8, location, ':')) |colon| {
        const slash = std.mem.indexOfScalar(u8, location, '/') orelse location.len;
        if (colon < slash) return error.OauthDiscoveryRedirectInvalidUrl;
    }
    if (std.mem.startsWith(u8, location, "//")) return error.OauthDiscoveryRedirectInvalidUrl;
    const base = std.Uri.parse(base_url) catch return error.OauthDiscoveryRedirectInvalidUrl;
    const origin = try originUrl(allocator, base);
    if (location[0] == '/') return std.fmt.allocPrint(allocator, "{s}{s}", .{ origin, location });
    const path = try componentText(allocator, base.path);
    const slash = std.mem.lastIndexOfScalar(u8, path, '/') orelse return error.OauthDiscoveryRedirectInvalidUrl;
    return std.fmt.allocPrint(allocator, "{s}{s}{s}", .{ origin, path[0 .. slash + 1], location });
}

/// Surfaces the RFC 6749 section 5.2 error body instead of discarding it.
fn reportOauthFailure(allocator: Allocator, url: []const u8, status: std.http.Status, body: []const u8) void {
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

test "authorization response issuer follows metadata advertisement" {
    try validateAuthorizationIssuer("https://issuer.example", "https://issuer.example", true);
    try std.testing.expectError(error.OauthAuthorizationIssuerMismatch, validateAuthorizationIssuer("https://issuer.example", "https://other.example", true));
    try std.testing.expectError(error.OauthAuthorizationIssuerMissing, validateAuthorizationIssuer("https://issuer.example", null, true));
    try validateAuthorizationIssuer("https://issuer.example", null, false);
    try std.testing.expectError(error.OauthAuthorizationIssuerMismatch, validateAuthorizationIssuer("https://issuer.example", "https://other.example", false));
}

test "metadata and token response security fields are enforced" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const metadata_value = try std.json.parseFromSliceLeaky(Value, allocator,
        \\{"issuer":"https://issuer.example","authorization_endpoint":"https://issuer.example/auth","token_endpoint":"https://issuer.example/token","authorization_response_iss_parameter_supported":true}
    , .{});
    const metadata = try metadataFromJson(allocator, metadata_value, "https://issuer.example");
    try std.testing.expect(metadata.authorization_response_iss_parameter_supported);
    const injected = try std.json.parseFromSliceLeaky(Value, allocator,
        \\{"access_token":"safe\r\nInjected: yes","token_type":"Bearer"}
    , .{});
    try std.testing.expectError(error.InvalidTokenHeaderValue, parseTokenResponse(injected));
    const unsupported = try std.json.parseFromSliceLeaky(Value, allocator,
        \\{"access_token":"value","token_type":"Basic"}
    , .{});
    try std.testing.expectError(error.UnsupportedTokenType, parseTokenResponse(unsupported));
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
    try std.testing.expectEqualStrings("https://issuer.example/.well-known/openid-configuration/tenant/a", urls[1]);
    try std.testing.expectEqualStrings("https://issuer.example/tenant/a/.well-known/openid-configuration", urls[2]);
}

test "protected resource metadata requires resource binding and authorization servers" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const endpoint = "https://mcp.example/mcp";
    const non_object = try std.json.parseFromSliceLeaky(Value, allocator, "[]", .{});
    try std.testing.expectError(
        error.OauthProtectedResourceMetadataMustBeObject,
        validateProtectedResourceMetadata(allocator, non_object, endpoint),
    );
    const valid = try std.json.parseFromSliceLeaky(Value, allocator,
        \\{"resource":"HTTPS://MCP.EXAMPLE:443/mcp","authorization_servers":["https://issuer.example"]}
    , .{});
    try std.testing.expectEqualStrings(
        "https://issuer.example",
        (try validateProtectedResourceMetadata(allocator, valid, endpoint))[0],
    );
    const missing_resource = try std.json.parseFromSliceLeaky(Value, allocator,
        \\{"authorization_servers":["https://issuer.example"]}
    , .{});
    try std.testing.expectError(
        error.OauthProtectedResourceMetadataMissingResource,
        validateProtectedResourceMetadata(allocator, missing_resource, endpoint),
    );
    const mismatch = try std.json.parseFromSliceLeaky(Value, allocator,
        \\{"resource":"https://other.example/mcp","authorization_servers":["https://issuer.example"]}
    , .{});
    try std.testing.expectError(error.OauthResourceMismatch, validateProtectedResourceMetadata(allocator, mismatch, endpoint));
    const missing_servers = try std.json.parseFromSliceLeaky(Value, allocator,
        \\{"resource":"https://mcp.example/mcp"}
    , .{});
    try std.testing.expectError(
        error.OauthProtectedResourceMetadataMissingAuthorizationServers,
        validateProtectedResourceMetadata(allocator, missing_servers, endpoint),
    );
    const empty_servers = try std.json.parseFromSliceLeaky(Value, allocator,
        \\{"resource":"https://mcp.example/mcp","authorization_servers":[]}
    , .{});
    try std.testing.expectError(
        error.OauthProtectedResourceMetadataMissingAuthorizationServers,
        validateProtectedResourceMetadata(allocator, empty_servers, endpoint),
    );
    const invalid_server = try std.json.parseFromSliceLeaky(Value, allocator,
        \\{"resource":"https://mcp.example/mcp","authorization_servers":["relative"]}
    , .{});
    try std.testing.expectError(
        error.OauthProtectedResourceMetadataInvalidAuthorizationServer,
        validateProtectedResourceMetadata(allocator, invalid_server, endpoint),
    );
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

test "authorization server metadata must not use cleartext endpoints" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const insecure_token = try std.json.parseFromSliceLeaky(Value, allocator,
        \\{"issuer":"https://issuer.example","authorization_endpoint":"https://issuer.example/auth","token_endpoint":"http://issuer.example/token"}
    , .{});
    try std.testing.expectError(
        error.OauthInsecureUrl,
        metadataFromJson(allocator, insecure_token, "https://issuer.example"),
    );
    const loopback = try std.json.parseFromSliceLeaky(Value, allocator,
        \\{"issuer":"http://127.0.0.1:8080","authorization_endpoint":"http://127.0.0.1:8080/auth","token_endpoint":"http://127.0.0.1:8080/token"}
    , .{});
    const metadata = try metadataFromJson(allocator, loopback, "http://127.0.0.1:8080");
    try std.testing.expectEqualStrings("http://127.0.0.1:8080/token", metadata.token_endpoint);
}

test "protected resource metadata rejects cleartext authorization servers" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const insecure = try std.json.parseFromSliceLeaky(Value, allocator,
        \\{"resource":"https://mcp.example/mcp","authorization_servers":["http://issuer.example"]}
    , .{});
    try std.testing.expectError(
        error.OauthProtectedResourceMetadataInsecureAuthorizationServer,
        validateProtectedResourceMetadata(allocator, insecure, "https://mcp.example/mcp"),
    );
}

test "protected resource metadata keeps every authorization server candidate" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const value = try std.json.parseFromSliceLeaky(Value, allocator,
        \\{"resource":"https://mcp.example/mcp","authorization_servers":["https://one.example","https://two.example"]}
    , .{});
    const issuers = try validateProtectedResourceMetadata(allocator, value, "https://mcp.example/mcp");
    try std.testing.expectEqual(@as(usize, 2), issuers.len);
    try std.testing.expectEqualStrings("https://two.example", issuers[1]);
}

test "challenge metadata URLs are confined to the resource server origin" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const endpoint = "https://mcp.example/mcp";
    try sameOrigin(allocator, "https://mcp.example/.well-known/oauth-protected-resource/mcp", endpoint);
    try sameOrigin(allocator, "https://mcp.example:443/other", endpoint);
    try std.testing.expectError(
        error.OauthChallengeOriginMismatch,
        sameOrigin(allocator, "https://attacker.example/metadata", endpoint),
    );
    try std.testing.expectError(
        error.OauthChallengeOriginMismatch,
        sameOrigin(allocator, "http://mcp.example/metadata", endpoint),
    );
    try std.testing.expectError(
        error.OauthChallengeOriginMismatch,
        sameOrigin(allocator, "https://mcp.example:8443/metadata", endpoint),
    );
    try std.testing.expectError(
        error.OauthChallengeInvalidUrl,
        sameOrigin(allocator, "not-a-url", endpoint),
    );
}

test "discovery redirect policy rejects cross-origin and scheme changes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    try validateDiscoveryUrl(allocator, "https://mcp.example/next", "https://mcp.example/mcp", .resource);
    try std.testing.expectError(error.OauthDiscoveryRedirectPolicyViolation,
        validateDiscoveryUrl(allocator, "https://attacker.example/next", "https://mcp.example/mcp", .resource));
    try std.testing.expectError(error.OauthDiscoveryRedirectPolicyViolation,
        validateDiscoveryUrl(allocator, "http://mcp.example/next", "https://mcp.example/mcp", .resource));
    try std.testing.expectError(error.OauthDiscoveryRedirectPolicyViolation,
        validateDiscoveryUrl(allocator, "https://127.0.0.1/next", "https://issuer.example", .authorization_server));
    try std.testing.expectError(error.OauthDiscoveryRedirectPolicyViolation,
        validateDiscoveryUrl(allocator, "https://10.0.0.1/next", "https://issuer.example", .authorization_server));
}

test "discovery follows safe relative redirects and rejects loops" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    const test_http = @import("test_http.zig");

    var server = try test_http.listenLoopback(io);
    defer server.deinit(io);
    const origin = try test_http.originFor(allocator, &server);
    const start = try std.fmt.allocPrint(allocator, "{s}/metadata/start", .{origin});
    var script = test_http.Script{ .keep_alive = true, .responses = &.{
        .{ .status = "302 Found", .extra_headers = "Location: next\r\n", .body = "" },
        .{ .status = "200 OK", .body = "{\"ok\":true}" },
    } };
    var serving = try io.concurrent(test_http.Script.serve, .{ &script, io, &server });
    var http: std.http.Client = .{ .allocator = allocator, .io = io };
    defer http.deinit();
    const value = try fetchDiscoveryJson(allocator, &http, start, &.{}, origin, .resource);
    try serving.await(io);
    try std.testing.expect(rpc.get(value, "ok").?.bool);
    try std.testing.expect(std.mem.indexOf(u8, script.request(1), "/metadata/next") != null);

    var loop_server = try test_http.listenLoopback(io);
    defer loop_server.deinit(io);
    const loop_origin = try test_http.originFor(allocator, &loop_server);
    const loop_url = try std.fmt.allocPrint(allocator, "{s}/a", .{loop_origin});
    var loop_script = test_http.Script{ .keep_alive = true, .responses = &.{
        .{ .status = "302 Found", .extra_headers = "Location: /b\r\n", .body = "" },
        .{ .status = "302 Found", .extra_headers = "Location: /a\r\n", .body = "" },
    } };
    var loop_serving = try io.concurrent(test_http.Script.serve, .{ &loop_script, io, &loop_server });
    try std.testing.expectError(error.OauthDiscoveryRedirectLoop,
        fetchDiscoveryJson(allocator, &http, loop_url, &.{}, loop_origin, .resource));
    try loop_serving.await(io);
}

test "authorization URL and token forms carry the canonical resource" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const resource = try canonicalResourceUri(allocator, "HTTPS://MCP.EXAMPLE:443/mcp");
    try std.testing.expectEqualStrings("https://mcp.example/mcp", resource);
    const url = try buildAuthorizationUrl(allocator, "https://issuer.example/auth", "client", "http://127.0.0.1:1/callback", null, "challenge", "state", resource);
    try std.testing.expect(std.mem.indexOf(u8, url, "resource=https%3A%2F%2Fmcp.example%2Fmcp") != null);
    try std.testing.expect(std.mem.indexOf(u8, url, "MCP.EXAMPLE") == null);
}

test "a stored refresh token is exchanged over real HTTP and persisted" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    const test_http = @import("test_http.zig");

    var server = try test_http.listenLoopback(io);
    defer server.deinit(io);
    const origin = try test_http.originFor(allocator, &server);
    const endpoint = try test_http.endpointFor(allocator, &server);
    const resource = try canonicalResourceUri(allocator, endpoint);

    const responses = [_]test_http.Response{
        .{ .status = "200 OK", .body = try std.fmt.allocPrint(allocator,
            \\{{"resource":"{s}","authorization_servers":["{s}"]}}
        , .{ resource, origin }) },
        .{ .status = "200 OK", .body = try std.fmt.allocPrint(allocator,
            \\{{"issuer":"{s}","authorization_endpoint":"{s}/authorize","token_endpoint":"{s}/token"}}
        , .{ origin, origin, origin }) },
        .{ .status = "200 OK", .body =
        \\{"access_token":"fresh-access","refresh_token":"fresh-refresh","token_type":"Bearer","expires_in":3600}
        },
    };
    var script = test_http.Script{ .responses = &responses };
    var serving = try io.concurrent(test_http.Script.serve, .{ &script, io, &server });

    const token_path = try std.fmt.allocPrint(allocator, "/tmp/mcpx-token-test-{d}.toml", .{server.socket.address.getPort()});
    defer std.Io.Dir.cwd().deleteFile(io, token_path) catch {};
    var seeded: TokenStore = .empty;
    try seeded.put(allocator, try tokenKey(allocator, origin, resource), .{
        .issuer = origin,
        .resource = resource,
        .access_token = "stale-access",
        .refresh_token = "stored-refresh",
        .expires_at = unixNow(io) - 10,
        .client_id = "cli-client",
    });
    try saveTokens(io, allocator, token_path, seeded);

    var http: std.http.Client = .{ .allocator = allocator, .io = io };
    defer http.deinit();
    const token = try ensureToken(allocator, io, &http, endpoint, .{ .client_id = "cli-client" }, token_path);
    try serving.await(io);

    try std.testing.expectEqualStrings("fresh-access", token.access_token);
    try std.testing.expectEqualStrings("fresh-refresh", token.refresh_token.?);
    try std.testing.expectEqualStrings(resource, token.resource.?);
    try std.testing.expect(token.expires_at.? > unixNow(io));

    var reloaded = try loadTokens(io, allocator, token_path);
    defer reloaded.deinit(allocator);
    const stored = reloaded.get(try tokenKey(allocator, origin, resource)).?;
    try std.testing.expectEqualStrings("fresh-access", stored.access_token);
    try std.testing.expectEqualStrings("cli-client", stored.client_id.?);

    // The protected resource document is fetched from the endpoint path first.
    try std.testing.expect(std.mem.indexOf(u8, script.request(0), "/.well-known/oauth-protected-resource/mcp") != null);
    try std.testing.expect(std.mem.indexOf(u8, script.request(1), "/.well-known/oauth-authorization-server") != null);
    try std.testing.expect(std.mem.startsWith(u8, script.request(2), "POST /token"));
}

test "OAuth error bodies are surfaced instead of a bare HTTP failure" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    const test_http = @import("test_http.zig");

    var server = try test_http.listenLoopback(io);
    defer server.deinit(io);
    const url = try std.fmt.allocPrint(allocator, "{s}/token", .{try test_http.originFor(allocator, &server)});
    var script = test_http.Script{ .responses = &.{
        .{ .status = "400 Bad Request", .body =
        \\{"error":"invalid_grant","error_description":"refresh token expired"}
        },
    } };
    var serving = try io.concurrent(test_http.Script.serve, .{ &script, io, &server });
    var http: std.http.Client = .{ .allocator = allocator, .io = io };
    defer http.deinit();

    try std.testing.expectError(
        error.OauthHttpRequestFailed,
        fetchJson(allocator, &http, .POST, url, "grant_type=refresh_token", &.{}),
    );
    try serving.await(io);
}
