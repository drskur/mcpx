const std = @import("std");

const Allocator = std.mem.Allocator;
const Io = std.Io;

pub const Token = struct {
    issuer: []const u8,
    access_token: []const u8,
    refresh_token: ?[]const u8 = null,
    token_type: []const u8 = "Bearer",
    expires_at: ?i64 = null,
    client_id: ?[]const u8 = null,
    client_secret: ?[]const u8 = null,
};

pub const TokenStore = std.StringHashMapUnmanaged(Token);

pub fn serializeTokens(allocator: Allocator, tokens: TokenStore) ![]const u8 {
    var output: Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    var iterator = tokens.iterator();
    while (iterator.next()) |entry| {
        try output.writer.print("[{s}]\n", .{entry.key_ptr.*});
        try writeTomlString(&output.writer, "issuer", entry.value_ptr.issuer);
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
        issuer: ?[]const u8 = null,
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
            if (std.mem.eql(u8, key, "issuer")) current.?.issuer = value else if (std.mem.eql(u8, key, "access_token")) current.?.access_token = value else if (std.mem.eql(u8, key, "refresh_token")) current.?.refresh_token = value else if (std.mem.eql(u8, key, "token_type")) current.?.token_type = value else if (std.mem.eql(u8, key, "client_id")) current.?.client_id = value else if (std.mem.eql(u8, key, "client_secret")) current.?.client_secret = value;
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

pub fn writeTomlString(writer: *Io.Writer, key: []const u8, value: []const u8) !void {
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

pub fn parseTomlString(allocator: Allocator, raw: []const u8) ![]const u8 {
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

pub fn putBuilder(allocator: Allocator, result: *TokenStore, section: anytype) !void {
    try result.put(allocator, section.name, .{
        .issuer = section.issuer orelse section.name,
        .access_token = section.access_token orelse return error.TokenMissingAccessToken,
        .refresh_token = section.refresh_token,
        .token_type = section.token_type,
        .expires_at = section.expires_at,
        .client_id = section.client_id,
        .client_secret = section.client_secret,
    });
}

pub fn tokenNeedsRefresh(token: Token, now: i64) bool {
    const expires_at = token.expires_at orelse return false;
    return expires_at <= now + 60;
}

test "token expiry includes sixty second refresh window" {
    const token: Token = .{ .issuer = "https://issuer.example", .access_token = "a", .expires_at = 1000 };
    try std.testing.expect(tokenNeedsRefresh(token, 1000));
    try std.testing.expect(tokenNeedsRefresh(token, 940));
    try std.testing.expect(!tokenNeedsRefresh(token, 939));
    try std.testing.expect(!tokenNeedsRefresh(.{ .issuer = "https://issuer.example", .access_token = "a" }, 5000));
}

test "token TOML round trip preserves fields" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var tokens: TokenStore = .empty;
    try tokens.put(arena.allocator(), "github", .{
        .issuer = "https://issuer.example",
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
    try std.testing.expectEqualStrings("https://issuer.example", token.issuer);
    try std.testing.expectEqualStrings("refresh", token.refresh_token.?);
    try std.testing.expectEqual(@as(?i64, 1754000000), token.expires_at);
    try std.testing.expectEqualStrings("client", token.client_id.?);
    try std.testing.expectEqualStrings("secret", token.client_secret.?);
}

test "token store keys can isolate credentials by issuer" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var tokens: TokenStore = .empty;
    try tokens.put(arena.allocator(), "https://one.example", .{ .issuer = "https://one.example", .access_token = "one", .client_id = "one-client" });
    try tokens.put(arena.allocator(), "https://two.example", .{ .issuer = "https://two.example", .access_token = "two", .client_id = "two-client" });
    try std.testing.expectEqualStrings("one-client", tokens.get("https://one.example").?.client_id.?);
    try std.testing.expectEqualStrings("two-client", tokens.get("https://two.example").?.client_id.?);
}
