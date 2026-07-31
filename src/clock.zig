const std = @import("std");

const Io = std.Io;

/// Sleeps for `seconds` on the awake clock. `Io.Timeout.sleep` only fails with
/// `error.Canceled`, which is exactly what the losing branch of a select
/// receives, so cancelation is intentionally swallowed here.
pub fn waitForTimeout(io: Io, seconds: u64) void {
    const limited_seconds = @min(seconds, @as(u64, std.math.maxInt(i64)));
    Io.Timeout.sleep(.{ .duration = .{
        .clock = .awake,
        .raw = .fromSeconds(@intCast(limited_seconds)),
    } }, io) catch {};
}

pub fn unixNow(io: Io) i64 {
    return @intCast(@divFloor(Io.Clock.real.now(io).nanoseconds, std.time.ns_per_s));
}
