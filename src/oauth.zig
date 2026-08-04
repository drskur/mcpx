const std = @import("std");
const pkce = @import("oauth/pkce.zig");
const token_store = @import("oauth/token_store.zig");
const callback = @import("oauth/callback.zig");

const Allocator = std.mem.Allocator;
const Io = std.Io;
const Value = std.json.Value;

const clock = @import("clock.zig");
const diagnostics_out = @import("diagnostics.zig");
const metadata_mod = @import("oauth/metadata.zig");
const token_mod = @import("oauth/token.zig");
const registration = @import("oauth/registration.zig");
const oauth_url = @import("oauth/url.zig");
const keys = @import("oauth/keys.zig");

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

const bindCallback = callback.bindCallback;
const acceptCallback = callback.acceptCallback;

pub const OauthConfig = struct {
    client_id: ?[]const u8 = null,
    scopes: ?[]const u8 = null,
    register: bool = false,
    /// Request a refresh token from providers such as Google. Disabled by
    /// default because it is not part of the general MCP OAuth profile.
    access_type_offline: bool = false,
    /// Force the authorization server to show its consent screen again.
    /// Google may require this to issue a new refresh token.
    prompt_consent: bool = false,
};

const Metadata = metadata_mod.Metadata;
const discoverMetadata = metadata_mod.discoverMetadata;
const metadataFromJson = metadata_mod.metadataFromJson;
pub const validateAuthorizationIssuer = metadata_mod.validateAuthorizationIssuer;
const exchangeCode = token_mod.exchangeCode;
const refreshToken = token_mod.refreshToken;
const parseTokenResponse = token_mod.parseTokenResponse;
const fetchJson = token_mod.fetchJson;
const tokenFromResponse = token_mod.tokenFromResponse;
const registerClient = registration.registerClient;
const canonicalResourceUri = oauth_url.canonicalResourceUri;
const formField = oauth_url.formField;
const tokenKey = keys.tokenKey;
const tokenMatches = keys.tokenMatches;
const findIssuerCredentials = keys.findIssuerCredentials;

pub const OauthChallenge = metadata_mod.Challenge;

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
            const refreshed = refreshToken(allocator, http, metadata.token_endpoint, metadata.issuer, endpoint, stored) catch null;
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
        if (refreshToken(allocator, http, metadata.token_endpoint, metadata.issuer, endpoint, stored)) |token| {
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
        const registered = try registerClient(allocator, http, metadata.registration_endpoint, redirect_uri);
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
    const auth_url = try buildAuthorizationUrl(allocator, metadata.authorization_endpoint, actual_client_id, redirect_uri, config.scopes, config.access_type_offline, config.prompt_consent, challenge, state, resource);
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

fn openBrowser(io: Io, url: []const u8) void {
    diagnostics_out.report("Open this URL to authorize mcpx:\n{s}\n", .{url});
    if (@import("builtin").os.tag == .linux) {
        var child = std.process.spawn(io, .{ .argv = &.{ "xdg-open", url }, .stdin = .ignore, .stdout = .ignore, .stderr = .ignore }) catch return;
        _ = child.wait(io) catch return;
    }
}

fn buildAuthorizationUrl(allocator: Allocator, endpoint: []const u8, client_id: []const u8, redirect_uri: []const u8, scopes: ?[]const u8, access_type_offline: bool, prompt_consent: bool, challenge: []const u8, state: []const u8, resource: []const u8) ![]const u8 {
    var output: Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    try output.writer.writeAll(endpoint);
    try output.writer.writeByte(if (std.mem.indexOfScalar(u8, endpoint, '?') == null) '?' else '&');
    try formField(&output.writer, "response_type", "code", false);
    try formField(&output.writer, "client_id", client_id, true);
    try formField(&output.writer, "redirect_uri", redirect_uri, true);
    if (scopes) |value| try formField(&output.writer, "scope", value, true);
    if (access_type_offline) try formField(&output.writer, "access_type", "offline", true);
    if (prompt_consent) try formField(&output.writer, "prompt", "consent", true);
    try formField(&output.writer, "code_challenge", challenge, true);
    try formField(&output.writer, "code_challenge_method", "S256", true);
    try formField(&output.writer, "state", state, true);
    try formField(&output.writer, "resource", resource, true);
    return output.toOwnedSlice();
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

test "authorization URL and token forms carry the canonical resource" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const resource = try canonicalResourceUri(allocator, "HTTPS://MCP.EXAMPLE:443/mcp");
    try std.testing.expectEqualStrings("https://mcp.example/mcp", resource);
    const url = try buildAuthorizationUrl(allocator, "https://issuer.example/auth", "client", "http://127.0.0.1:1/callback", null, false, false, "challenge", "state", resource);
    try std.testing.expect(std.mem.indexOf(u8, url, "resource=https%3A%2F%2Fmcp.example%2Fmcp") != null);
    try std.testing.expect(std.mem.indexOf(u8, url, "MCP.EXAMPLE") == null);
    try std.testing.expect(std.mem.indexOf(u8, url, "access_type=") == null);
    try std.testing.expect(std.mem.indexOf(u8, url, "prompt=") == null);
}

test "authorization URL supports opt-in Google refresh token parameters" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const url = try buildAuthorizationUrl(arena.allocator(), "https://accounts.google.com/o/oauth2/v2/auth", "client", "http://127.0.0.1:1/callback", "openid email", true, true, "challenge", "state", "https://mcp.example/mcp");
    try std.testing.expect(std.mem.indexOf(u8, url, "scope=openid%20email") != null);
    try std.testing.expect(std.mem.indexOf(u8, url, "access_type=offline") != null);
    try std.testing.expect(std.mem.indexOf(u8, url, "prompt=consent") != null);
    try std.testing.expect(std.mem.indexOf(u8, url, "resource=https%3A%2F%2Fmcp.example%2Fmcp") != null);
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
