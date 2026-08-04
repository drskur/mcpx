const std = @import("std");
const rpc = @import("../rpc.zig");
const diagnostics_out = @import("../diagnostics.zig");
const oauth_url = @import("url.zig");
const token = @import("token.zig");

const Allocator = std.mem.Allocator;
const Io = std.Io;
const Value = std.json.Value;
const max_metadata_size = 1024 * 1024;
const requireSecureUrl = oauth_url.requireSecureUrl;
const sameOrigin = oauth_url.sameOrigin;
const canonicalResourceUri = oauth_url.canonicalResourceUri;
const originUrl = oauth_url.originUrl;
const componentText = oauth_url.componentText;
const reportOauthFailure = token.reportOauthFailure;

pub const Challenge = struct {
    resource_metadata: ?[]const u8 = null,
    scope: ?[]const u8 = null,
};

pub const Metadata = struct {
    issuer: []const u8,
    authorization_endpoint: []const u8,
    token_endpoint: []const u8,
    registration_endpoint: ?[]const u8 = null,
    authorization_response_iss_parameter_supported: bool = false,
};

pub fn discoverMetadata(allocator: Allocator, http: *std.http.Client, endpoint: []const u8, challenge: ?Challenge) !Metadata {
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
        else |err| {
            diagnostics_out.warn("ignoring resource_metadata challenge: origin mismatch\n", .{});
            if (diagnostics_out.isDebug())
                diagnostics_out.warn("resource_metadata challenge URL '{s}': {s}\n", .{ url, @errorName(err) });
        }
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
                diagnostics_out.warn("rejecting authorization server metadata\n", .{});
                if (diagnostics_out.isDebug())
                    diagnostics_out.warn("authorization server metadata URL '{s}': {s}\n", .{ metadata_url, @errorName(err) });
                continue;
            };
        }
    }
    return error.OauthMetadataDiscoveryFailed;
}

pub fn metadataFromJson(allocator: Allocator, value: Value, expected_issuer: []const u8) !Metadata {
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
    try std.testing.expectError(error.OauthDiscoveryRedirectPolicyViolation, validateDiscoveryUrl(allocator, "https://attacker.example/next", "https://mcp.example/mcp", .resource));
    try std.testing.expectError(error.OauthDiscoveryRedirectPolicyViolation, validateDiscoveryUrl(allocator, "http://mcp.example/next", "https://mcp.example/mcp", .resource));
    try std.testing.expectError(error.OauthDiscoveryRedirectPolicyViolation, validateDiscoveryUrl(allocator, "https://127.0.0.1/next", "https://issuer.example", .authorization_server));
    try std.testing.expectError(error.OauthDiscoveryRedirectPolicyViolation, validateDiscoveryUrl(allocator, "https://10.0.0.1/next", "https://issuer.example", .authorization_server));
}

test "discovery follows safe relative redirects and rejects loops" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    const test_http = @import("../test_http.zig");

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
    try std.testing.expectError(error.OauthDiscoveryRedirectLoop, fetchDiscoveryJson(allocator, &http, loop_url, &.{}, loop_origin, .resource));
    try loop_serving.await(io);
}
