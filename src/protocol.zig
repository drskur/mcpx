const std = @import("std");

pub const legacy_version = "2025-03-26";
pub const latest_version = "2026-07-28";

pub const Capabilities = struct {
    has_sessions: bool = false,
    needs_meta: bool = false,
    needs_discover: bool = false,
    has_mcp_method_header: bool = false,
    has_mcp_name_header: bool = false,
    supports_result_type: bool = false,
    allows_server_requests: bool = false,
    has_cancel_notification: bool = false,
};

pub const Version = struct {
    name: []const u8,
    capabilities: Capabilities,
};

pub const versions = [_]Version{
    .{ .name = "2025-03-26", .capabilities = .{
        .has_sessions = true,
        .allows_server_requests = true,
        .has_cancel_notification = true,
    } },
    .{ .name = "2025-06-18", .capabilities = .{
        .has_sessions = true,
        .allows_server_requests = true,
        .has_cancel_notification = true,
    } },
    .{ .name = "2025-11-25", .capabilities = .{
        .has_sessions = true,
        .allows_server_requests = true,
        .has_cancel_notification = true,
    } },
    .{ .name = "2026-07-28", .capabilities = .{
        .needs_meta = true,
        .needs_discover = true,
        .has_mcp_method_header = true,
        .has_mcp_name_header = true,
        .supports_result_type = true,
    } },
};

pub fn capabilitiesFor(version: []const u8) ?Capabilities {
    for (versions) |entry|
        if (std.mem.eql(u8, entry.name, version)) return entry.capabilities;
    return null;
}

/// The table is ordered oldest to newest. Prefer the newest version supported
/// by both peers, independently of the order supplied by the server.
pub fn bestMutualVersion(supported: []const []const u8) ?Version {
    var index = versions.len;
    while (index > 0) {
        index -= 1;
        for (supported) |candidate|
            if (std.mem.eql(u8, versions[index].name, candidate)) return versions[index];
    }
    return null;
}

test "capability table covers known protocol versions" {
    try std.testing.expect(capabilitiesFor("2025-03-26").?.has_sessions);
    try std.testing.expect(capabilitiesFor("2025-06-18").?.has_sessions);
    try std.testing.expect(capabilitiesFor("2025-11-25").?.has_sessions);
    try std.testing.expect(!capabilitiesFor("2025-11-25").?.needs_meta);
    const modern = capabilitiesFor("2026-07-28").?;
    try std.testing.expect(!modern.has_sessions);
    try std.testing.expect(modern.needs_discover);
    try std.testing.expect(modern.has_mcp_method_header);
    try std.testing.expect(modern.supports_result_type);
    try std.testing.expect(capabilitiesFor("2099-01-01") == null);
}

test "best mutual version uses table order rather than server order" {
    const selected = bestMutualVersion(&.{ "2025-03-26", "2026-07-28", "unknown" }).?;
    try std.testing.expectEqualStrings("2026-07-28", selected.name);
    try std.testing.expect(bestMutualVersion(&.{"unknown"}) == null);
}
