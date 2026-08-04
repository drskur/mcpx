const std = @import("std");
const callback = @import("callback.zig");

const Allocator = std.mem.Allocator;
const Io = std.Io;

pub fn requireSecureUrl(allocator: Allocator, url: []const u8) !void {
    const uri = std.Uri.parse(url) catch return error.OauthInsecureUrl;
    const host = try componentText(allocator, uri.host orelse return error.OauthInsecureUrl);
    if (std.ascii.eqlIgnoreCase(uri.scheme, "https")) return;
    if (!std.ascii.eqlIgnoreCase(uri.scheme, "http")) return error.OauthInsecureUrl;
    if (isLoopbackHost(host)) return;
    return error.OauthInsecureUrl;
}

pub fn isLoopbackHost(host: []const u8) bool {
    if (std.ascii.eqlIgnoreCase(host, "localhost")) return true;
    if (std.mem.eql(u8, host, "::1") or std.mem.eql(u8, host, "[::1]")) return true;
    return std.mem.startsWith(u8, host, "127.");
}

pub fn sameOrigin(allocator: Allocator, url: []const u8, endpoint: []const u8) !void {
    const candidate = std.Uri.parse(url) catch return error.OauthChallengeInvalidUrl;
    const expected = try std.Uri.parse(endpoint);
    if (!std.ascii.eqlIgnoreCase(candidate.scheme, expected.scheme)) return error.OauthChallengeOriginMismatch;
    const candidate_host = try componentText(allocator, candidate.host orelse return error.OauthChallengeInvalidUrl);
    const expected_host = try componentText(allocator, expected.host orelse return error.OauthEndpointMissingHost);
    if (!std.ascii.eqlIgnoreCase(candidate_host, expected_host)) return error.OauthChallengeOriginMismatch;
    if (defaultedPort(candidate) != defaultedPort(expected)) return error.OauthChallengeOriginMismatch;
}

pub fn defaultedPort(uri: std.Uri) u16 {
    return uri.port orelse if (std.ascii.eqlIgnoreCase(uri.scheme, "https")) 443 else 80;
}

pub fn canonicalResourceUri(allocator: Allocator, input: []const u8) ![]const u8 {
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

pub fn originUrl(allocator: Allocator, uri: std.Uri) ![]const u8 {
    const scheme = uri.scheme;
    const host = try componentText(allocator, uri.host orelse return error.OauthEndpointMissingHost);
    const port = if (uri.port) |value| try std.fmt.allocPrint(allocator, ":{d}", .{value}) else "";
    return std.fmt.allocPrint(allocator, "{s}://{s}{s}", .{ scheme, host, port });
}

pub fn componentText(allocator: Allocator, component: std.Uri.Component) ![]const u8 {
    return switch (component) {
        .raw => |value| value,
        .percent_encoded => |value| callback.percentDecode(allocator, value),
    };
}

pub fn formField(writer: *Io.Writer, name: []const u8, value: []const u8, separator: bool) !void {
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
