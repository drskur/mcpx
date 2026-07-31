const std = @import("std");

const Io = std.Io;

/// Everything mcpx tells the user that is not command output goes through this
/// module: warnings, protocol diagnostics and the OAuth authorization URL. It
/// keeps `std.debug.print` out of the protocol code, makes the destination
/// explicit, and lets `--quiet` silence non-fatal notes.
var quiet = false;
var debug = false;

pub fn setQuiet(value: bool) void {
    quiet = value;
}

pub fn isQuiet() bool {
    return quiet;
}

pub fn setDebug(value: bool) void {
    debug = value;
}

pub fn isDebug() bool {
    return debug;
}

pub fn enableDebugFromEnvironment(value: ?[]const u8) void {
    if (value == null or value.?.len == 0 or std.mem.eql(u8, value.?, "0")) return;
    debug = true;
    report("warning: MCPX_DEBUG is enabled; remote response bodies and RPC error data may contain secrets\n", .{});
}

pub fn isSensitiveKey(key: []const u8) bool {
    const names = [_][]const u8{ "token", "authorization", "secret", "password", "client_secret", "access_token", "refresh_token", "api_key", "credential" };
    for (names) |name| if (std.ascii.eqlIgnoreCase(key, name)) return true;
    return false;
}

pub fn redactJson(allocator: std.mem.Allocator, value: std.json.Value) !std.json.Value {
    return switch (value) {
        .object => |object| blk: {
            var redacted = std.json.Value{ .object = .empty };
            var iterator = object.iterator();
            while (iterator.next()) |entry| try redacted.object.put(allocator, entry.key_ptr.*, if (isSensitiveKey(entry.key_ptr.*))
                .{ .string = "[REDACTED]" }
            else
                try redactJson(allocator, entry.value_ptr.*));
            break :blk redacted;
        },
        .array => |array| blk: {
            var redacted = std.json.Value{ .array = .init(allocator) };
            for (array.items) |item| try redacted.array.append(try redactJson(allocator, item));
            break :blk redacted;
        },
        else => value,
    };
}

pub fn safeRemoteMessage(allocator: std.mem.Allocator, category: []const u8, code: anytype) ![]const u8 {
    return std.fmt.allocPrint(allocator, "{s} {d}: remote request failed", .{ category, code });
}

/// Diagnostics that a user always needs to see, even with `--quiet`: failures
/// and the authorization URL that a browser may have failed to open.
pub fn report(comptime format: []const u8, args: anytype) void {
    std.debug.print(format, args);
}

/// Non-fatal notes that `--quiet` suppresses.
pub fn note(comptime format: []const u8, args: anytype) void {
    if (quiet) return;
    std.debug.print(format, args);
}

pub fn warn(comptime format: []const u8, args: anytype) void {
    if (quiet) return;
    std.debug.print("warning: " ++ format, args);
}

test "quiet suppresses notes but is restored for other tests" {
    const previous = isQuiet();
    defer setQuiet(previous);
    setQuiet(true);
    try std.testing.expect(isQuiet());
    note("this note is suppressed\n", .{});
    warn("this warning is suppressed\n", .{});
    setQuiet(false);
    try std.testing.expect(!isQuiet());
}

test "recursive JSON redaction removes sentinel secrets" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const input = try std.json.parseFromSliceLeaky(std.json.Value, allocator,
        \\{"message":"safe","nested":{"access_token":"SENTINEL_ACCESS"},"items":[{"password":"SENTINEL_PASSWORD"}],"API_KEY":"SENTINEL_KEY"}
    , .{});
    const redacted = try redactJson(allocator, input);
    var output: Io.Writer.Allocating = .init(allocator);
    try std.json.Stringify.value(redacted, .{}, &output.writer);
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "SENTINEL") == null);
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "safe") != null);
}

test "default remote diagnostic never incorporates remote content" {
    const message = try safeRemoteMessage(std.testing.allocator, "HTTP", 500);
    defer std.testing.allocator.free(message);
    const remote_body = "{\"password\":\"SENTINEL_STDERR_SECRET\"}";
    try std.testing.expect(std.mem.indexOf(u8, message, "SENTINEL_STDERR_SECRET") == null);
    try std.testing.expect(std.mem.indexOf(u8, message, remote_body) == null);
    try std.testing.expectEqualStrings("HTTP 500: remote request failed", message);
}
