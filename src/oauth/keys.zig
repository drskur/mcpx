const std = @import("std");
const token_store = @import("token_store.zig");
const oauth_url = @import("url.zig");

const Allocator = std.mem.Allocator;
const Token = token_store.Token;
const TokenStore = token_store.TokenStore;
const canonicalResourceUri = oauth_url.canonicalResourceUri;

pub fn tokenKey(allocator: Allocator, issuer: []const u8, resource: []const u8) ![]const u8 {
    const raw = try std.fmt.allocPrint(allocator, "{s}\x00{s}", .{ issuer, resource });
    const encoded_len = std.base64.url_safe_no_pad.Encoder.calcSize(raw.len);
    const result = try allocator.alloc(u8, "token-".len + encoded_len);
    @memcpy(result[0.."token-".len], "token-");
    _ = std.base64.url_safe_no_pad.Encoder.encode(result["token-".len..], raw);
    return result;
}

pub fn tokenMatches(token: Token, issuer: []const u8, resource: []const u8) bool {
    return std.mem.eql(u8, token.issuer, issuer) and
        token.resource != null and std.mem.eql(u8, token.resource.?, resource);
}

pub fn findIssuerCredentials(tokens: TokenStore, issuer: []const u8) ?Token {
    var iterator = tokens.iterator();
    while (iterator.next()) |entry|
        if (std.mem.eql(u8, entry.value_ptr.issuer, issuer) and entry.value_ptr.client_id != null)
            return entry.value_ptr.*;
    return null;
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
