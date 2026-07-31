const std = @import("std");

const Allocator = std.mem.Allocator;
const Io = std.Io;

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

/// Compares two `state` values in constant time regardless of length by
/// comparing their digests, so callers cannot leak a prefix match.
pub fn statesMatch(expected: []const u8, received: []const u8) bool {
    const Sha256 = std.crypto.hash.sha2.Sha256;
    var expected_digest: [Sha256.digest_length]u8 = undefined;
    var received_digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(expected, &expected_digest, .{});
    Sha256.hash(received, &received_digest, .{});
    return std.crypto.timing_safe.eql([Sha256.digest_length]u8, expected_digest, received_digest);
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

test "generated states are non-empty and distinct" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const first = try generateState(std.testing.io, arena.allocator());
    const second = try generateState(std.testing.io, arena.allocator());
    try std.testing.expect(first.len > 0);
    try std.testing.expect(!std.mem.eql(u8, first, second));
}

test "state comparison rejects prefixes and length changes" {
    try std.testing.expect(statesMatch("abc", "abc"));
    try std.testing.expect(!statesMatch("abc", "abcd"));
    try std.testing.expect(!statesMatch("abc", "ab"));
    try std.testing.expect(!statesMatch("", "a"));
    const long = "0123456789012345678901234567890123456789";
    try std.testing.expect(statesMatch(long, long));
    try std.testing.expect(!statesMatch(long, long[0..32] ++ "xxxxxxxx"));
}
