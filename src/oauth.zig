const std = @import("std");

const Allocator = std.mem.Allocator;
const Io = std.Io;
const Value = std.json.Value;

pub const OauthConfig = struct {
    client_id: ?[]const u8 = null,
    scopes: ?[]const u8 = null,
    register: bool = false,
};

pub const Token = struct {
    access_token: []const u8,
    refresh_token: ?[]const u8 = null,
    token_type: []const u8 = "Bearer",
    expires_at: ?i64 = null,
    client_id: ?[]const u8 = null,
    client_secret: ?[]const u8 = null,
};

pub const TokenStore = std.StringHashMapUnmanaged(Token);

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

pub const Callback = struct {
    code: []const u8,
    state: []const u8,
};

pub fn generateVerifier(io: Io, allocator: Allocator) ![]const u8 {
    var random: [32]u8 = undefined;
    try io.randomSecure(&random);
    const result = try allocator.alloc(u8, std.base64.url_safe_no_pad.Encoder.calcSize(random.len));
    return std.base64.url_safe_no_pad.Encoder.encode(result, &random);
}

pub fn codeChallenge(allocator: Allocator, verifier: []const u8) ![]const u8 {
    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(verifier, &digest, .{});
    const result = try allocator.alloc(u8, std.base64.url_safe_no_pad.Encoder.calcSize(digest.len));
    return std.base64.url_safe_no_pad.Encoder.encode(result, &digest);
}

pub fn generateState(io: Io, allocator: Allocator) ![]const u8 {
    var random: [24]u8 = undefined;
    try io.randomSecure(&random);
    const result = try allocator.alloc(u8, std.base64.url_safe_no_pad.Encoder.calcSize(random.len));
    return std.base64.url_safe_no_pad.Encoder.encode(result, &random);
}

pub fn tokenNeedsRefresh(token: Token, now: i64) bool {
    const expires_at = token.expires_at orelse return false;
    return expires_at <= now + 60;
}

pub fn parseCallbackRequestLine(allocator: Allocator, line: []const u8) !Callback {
    var pieces = std.mem.splitScalar(u8, line, ' ');
    if (!std.mem.eql(u8, pieces.next() orelse return error.InvalidCallbackRequest, "GET"))
        return error.InvalidCallbackRequest;
    const target = pieces.next() orelse return error.InvalidCallbackRequest;
    const query_start = std.mem.indexOfScalar(u8, target, '?') orelse return error.CallbackMissingQuery;
    const query_end = std.mem.indexOfScalarPos(u8, target, query_start, '#') orelse target.len;
    var code: ?[]const u8 = null;
    var state: ?[]const u8 = null;
    var fields = std.mem.splitScalar(u8, target[query_start + 1 .. query_end], '&');
    while (fields.next()) |field| {
        const equals = std.mem.indexOfScalar(u8, field, '=') orelse continue;
        const name = field[0..equals];
        const decoded = try percentDecode(allocator, field[equals + 1 ..]);
        if (std.mem.eql(u8, name, "code")) code = decoded;
        if (std.mem.eql(u8, name, "state")) state = decoded;
    }
    return .{
        .code = code orelse return error.CallbackMissingCode,
        .state = state orelse return error.CallbackMissingState,
    };
}

pub fn serializeTokens(allocator: Allocator, tokens: TokenStore) ![]const u8 {
    var output: Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    var iterator = tokens.iterator();
    while (iterator.next()) |entry| {
        try output.writer.print("[{s}]\n", .{entry.key_ptr.*});
        try writeTomlString(&output.writer, "access_token", entry.value_ptr.access_token);
        if (entry.value_ptr.refresh_token) |value| try writeTomlString(&output.writer, "refresh_token", value);
        try writeTomlString(&output.writer, "token_type", entry.value_ptr.token_type);
        if (entry.value_ptr.expires_at) |value| try output.writer.print("expires_at = {d}\n", .{value});
        if (entry.value_ptr.client_id) |value| try writeTomlString(&output.writer, "client_id", value);
        if (entry.value_ptr.client_secret) |value| try writeTomlString(&output.writer, "client_secret", value);
        try output.writer.writeByte('\n');
    }
    return output.toOwnedSlice();
}

pub fn parseTokens(allocator: Allocator, input: []const u8) !TokenStore {
    const Builder = struct {
        name: []const u8,
        access_token: ?[]const u8 = null,
        refresh_token: ?[]const u8 = null,
        token_type: []const u8 = "Bearer",
        expires_at: ?i64 = null,
        client_id: ?[]const u8 = null,
        client_secret: ?[]const u8 = null,
    };
    var result: TokenStore = .empty;
    errdefer result.deinit(allocator);
    var current: ?Builder = null;
    var lines = std.mem.splitScalar(u8, input, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        if (line[0] == '[' and line[line.len - 1] == ']') {
            if (current) |section| try putBuilder(allocator, &result, section);
            current = .{ .name = try allocator.dupe(u8, line[1 .. line.len - 1]) };
            continue;
        }
        if (current == null) return error.TokenFieldOutsideSection;
        const equals = std.mem.indexOfScalar(u8, line, '=') orelse return error.InvalidTokenToml;
        const key = std.mem.trim(u8, line[0..equals], " \t");
        const raw_value = std.mem.trim(u8, line[equals + 1 ..], " \t");
        if (std.mem.eql(u8, key, "expires_at")) {
            current.?.expires_at = try std.fmt.parseInt(i64, raw_value, 10);
        } else {
            const value = try parseTomlString(allocator, raw_value);
            if (std.mem.eql(u8, key, "access_token")) current.?.access_token = value else if (std.mem.eql(u8, key, "refresh_token")) current.?.refresh_token = value else if (std.mem.eql(u8, key, "token_type")) current.?.token_type = value else if (std.mem.eql(u8, key, "client_id")) current.?.client_id = value else if (std.mem.eql(u8, key, "client_secret")) current.?.client_secret = value;
        }
    }
    if (current) |section| try putBuilder(allocator, &result, section);
    return result;
}

pub fn loadTokens(io: Io, allocator: Allocator, path: []const u8) !TokenStore {
    const raw = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(16 * 1024 * 1024)) catch |err| switch (err) {
        error.FileNotFound => return .empty,
        else => return err,
    };
    return parseTokens(allocator, raw);
}

pub fn saveTokens(io: Io, allocator: Allocator, path: []const u8, tokens: TokenStore) !void {
    const parent = std.fs.path.dirname(path) orelse ".";
    try std.Io.Dir.cwd().createDirPath(io, parent);
    var dir = try std.Io.Dir.cwd().openDir(io, parent, .{});
    defer dir.close(io);
    const basename = std.fs.path.basename(path);
    const text = try serializeTokens(allocator, tokens);
    var atomic = try dir.createFileAtomic(io, basename, .{
        .permissions = @enumFromInt(0o600),
        .replace = true,
    });
    defer atomic.deinit(io);
    try atomic.file.writeStreamingAll(io, text);
    try atomic.file.sync(io);
    try atomic.replace(io);
}

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
    const callback = try acceptCallback(allocator, io, &callback_server);
    if (state.len != callback.state.len or !std.crypto.timing_safe.eql([32]u8, fixedState(state), fixedState(callback.state)))
        return error.OauthStateMismatch;
    const response = try exchangeCode(allocator, http, metadata.token_endpoint, callback.code, verifier, redirect_uri, actual_client_id, client_secret);
    const token = tokenFromResponse(response, actual_client_id, client_secret, unixNow(io));
    try tokens.put(allocator, server_name, token);
    try saveTokens(io, allocator, token_path, tokens.*);
    return token;
}

fn fixedState(state: []const u8) [32]u8 {
    var result = [_]u8{0} ** 32;
    @memcpy(result[0..@min(result.len, state.len)], state[0..@min(result.len, state.len)]);
    return result;
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
        if (getString(value, "authorization_endpoint") != null and getString(value, "token_endpoint") != null)
            return metadataFromJson(value);
        if (getString(value, "authorization_server")) |server| authorization_server = server;
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
        .authorization_endpoint = getString(value, "authorization_endpoint") orelse return error.OauthMetadataMissingAuthorizationEndpoint,
        .token_endpoint = getString(value, "token_endpoint") orelse return error.OauthMetadataMissingTokenEndpoint,
        .registration_endpoint = getString(value, "registration_endpoint"),
    };
}

const Registration = struct { client_id: []const u8, client_secret: ?[]const u8 };

fn registerClient(allocator: Allocator, http: *std.http.Client, metadata: Metadata, redirect_uri: []const u8) !Registration {
    const url = metadata.registration_endpoint orelse return error.OauthRegistrationUnsupported;
    var payload = Value{ .object = .empty };
    try payload.object.put(allocator, "client_name", .{ .string = "mcpx" });
    try payload.object.put(allocator, "redirect_uris", try stringArray(allocator, &.{redirect_uri}));
    try payload.object.put(allocator, "grant_types", try stringArray(allocator, &.{ "authorization_code", "refresh_token" }));
    try payload.object.put(allocator, "response_types", try stringArray(allocator, &.{"code"}));
    try payload.object.put(allocator, "token_endpoint_auth_method", .{ .string = "client_secret_post" });
    const body = try jsonString(allocator, payload);
    const value = try fetchJson(allocator, http, .POST, url, body, &.{.{ .name = "Content-Type", .value = "application/json" }});
    return .{
        .client_id = getString(value, "client_id") orelse return error.OauthRegistrationMissingClientId,
        .client_secret = getString(value, "client_secret"),
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
        .access_token = getString(value, "access_token") orelse return error.OauthTokenMissingAccessToken,
        .refresh_token = getString(value, "refresh_token"),
        .token_type = getString(value, "token_type") orelse "Bearer",
        .expires_in = getInteger(value, "expires_in"),
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

fn bindCallback(io: Io) !std.Io.net.Server {
    const address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    return address.listen(io, .{ .reuse_address = true });
}

fn acceptCallback(allocator: Allocator, io: Io, server: *std.Io.net.Server) !Callback {
    const stream = try server.accept(io);
    defer stream.close(io);
    var read_buffer: [8192]u8 = undefined;
    var reader = stream.reader(io, &read_buffer);
    const line = try reader.interface.takeDelimiterExclusive('\n');
    const callback = try parseCallbackRequestLine(allocator, std.mem.trimEnd(u8, line, "\r"));
    while (true) {
        const header = try reader.interface.takeDelimiterExclusive('\n');
        if (std.mem.trim(u8, header, "\r").len == 0) break;
    }
    const html = "<!doctype html><title>mcpx OAuth complete</title><p>Authorization complete. You may close this window.</p>";
    var write_buffer: [1024]u8 = undefined;
    var writer = stream.writer(io, &write_buffer);
    try writer.interface.print("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{ html.len, html });
    try writer.interface.flush();
    return callback;
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

fn percentDecode(allocator: Allocator, value: []const u8) ![]const u8 {
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

fn jsonString(allocator: Allocator, value: Value) ![]const u8 {
    var output: Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    try std.json.Stringify.value(value, .{}, &output.writer);
    return output.toOwnedSlice();
}

fn stringArray(allocator: Allocator, values: []const []const u8) !Value {
    var array = Value{ .array = .init(allocator) };
    for (values) |value| try array.array.append(.{ .string = value });
    return array;
}

fn getString(value: Value, key: []const u8) ?[]const u8 {
    if (value != .object) return null;
    const child = value.object.get(key) orelse return null;
    return if (child == .string) child.string else null;
}

fn getInteger(value: Value, key: []const u8) ?i64 {
    if (value != .object) return null;
    const child = value.object.get(key) orelse return null;
    return if (child == .integer) child.integer else null;
}

fn unixNow(io: Io) i64 {
    return @intCast(@divFloor(Io.Clock.real.now(io).nanoseconds, std.time.ns_per_s));
}

fn writeTomlString(writer: *Io.Writer, key: []const u8, value: []const u8) !void {
    try writer.print("{s} = \"", .{key});
    for (value) |byte| switch (byte) {
        '\\' => try writer.writeAll("\\\\"),
        '"' => try writer.writeAll("\\\""),
        '\n' => try writer.writeAll("\\n"),
        '\r' => try writer.writeAll("\\r"),
        '\t' => try writer.writeAll("\\t"),
        else => try writer.writeByte(byte),
    };
    try writer.writeAll("\"\n");
}

fn parseTomlString(allocator: Allocator, raw: []const u8) ![]const u8 {
    if (raw.len < 2 or raw[0] != '"' or raw[raw.len - 1] != '"') return error.InvalidTokenToml;
    var output: Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    var i: usize = 1;
    while (i + 1 < raw.len) {
        if (raw[i] != '\\') {
            try output.writer.writeByte(raw[i]);
            i += 1;
            continue;
        }
        i += 1;
        if (i + 1 >= raw.len) return error.InvalidTokenToml;
        try output.writer.writeByte(switch (raw[i]) {
            '\\' => '\\',
            '"' => '"',
            'n' => '\n',
            'r' => '\r',
            't' => '\t',
            else => return error.InvalidTokenToml,
        });
        i += 1;
    }
    return output.toOwnedSlice();
}

fn putBuilder(allocator: Allocator, result: *TokenStore, section: anytype) !void {
    try result.put(allocator, section.name, .{
        .access_token = section.access_token orelse return error.TokenMissingAccessToken,
        .refresh_token = section.refresh_token,
        .token_type = section.token_type,
        .expires_at = section.expires_at,
        .client_id = section.client_id,
        .client_secret = section.client_secret,
    });
}

test "PKCE verifier and RFC 7636 challenge" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const verifier = try generateVerifier(std.testing.io, arena.allocator());
    try std.testing.expect(verifier.len >= 43 and verifier.len <= 128);
    for (verifier) |byte| try std.testing.expect(std.ascii.isAlphanumeric(byte) or byte == '-' or byte == '.' or byte == '_' or byte == '~');
    const challenge = try codeChallenge(arena.allocator(), "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
    try std.testing.expectEqualStrings("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", challenge);
}

test "token expiry includes sixty second refresh window" {
    const token: Token = .{ .access_token = "a", .expires_at = 1000 };
    try std.testing.expect(tokenNeedsRefresh(token, 1000));
    try std.testing.expect(tokenNeedsRefresh(token, 940));
    try std.testing.expect(!tokenNeedsRefresh(token, 939));
    try std.testing.expect(!tokenNeedsRefresh(.{ .access_token = "a" }, 5000));
}

test "token TOML round trip preserves fields" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var tokens: TokenStore = .empty;
    try tokens.put(arena.allocator(), "github", .{
        .access_token = "a\"b",
        .refresh_token = "refresh",
        .token_type = "Bearer",
        .expires_at = 1754000000,
        .client_id = "client",
        .client_secret = "secret",
    });
    const encoded = try serializeTokens(arena.allocator(), tokens);
    var parsed = try parseTokens(arena.allocator(), encoded);
    const token = parsed.get("github").?;
    try std.testing.expectEqualStrings("a\"b", token.access_token);
    try std.testing.expectEqualStrings("refresh", token.refresh_token.?);
    try std.testing.expectEqual(@as(?i64, 1754000000), token.expires_at);
    try std.testing.expectEqualStrings("client", token.client_id.?);
    try std.testing.expectEqualStrings("secret", token.client_secret.?);
}

test "generated states are non-empty and distinct" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const first = try generateState(std.testing.io, arena.allocator());
    const second = try generateState(std.testing.io, arena.allocator());
    try std.testing.expect(first.len > 0);
    try std.testing.expect(!std.mem.eql(u8, first, second));
}

test "callback request line extracts and decodes code and state" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const callback = try parseCallbackRequestLine(arena.allocator(), "GET /callback?code=a%2Fb&state=hello%20world HTTP/1.1");
    try std.testing.expectEqualStrings("a/b", callback.code);
    try std.testing.expectEqualStrings("hello world", callback.state);
}

test "callback listener binds an ephemeral loopback port" {
    var server = try bindCallback(std.testing.io);
    defer server.deinit(std.testing.io);
    try std.testing.expect(server.socket.address.getPort() != 0);
}
