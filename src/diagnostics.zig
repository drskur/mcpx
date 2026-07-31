const std = @import("std");

const Io = std.Io;

/// Everything mcpx tells the user that is not command output goes through this
/// module: warnings, protocol diagnostics and the OAuth authorization URL. It
/// keeps `std.debug.print` out of the protocol code, makes the destination
/// explicit, and lets `--quiet` silence non-fatal notes.
var quiet = false;

pub fn setQuiet(value: bool) void {
    quiet = value;
}

pub fn isQuiet() bool {
    return quiet;
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
