const std = @import("std");
const rpc = @import("../rpc.zig");
const token = @import("token.zig");

const Allocator = std.mem.Allocator;
const Value = std.json.Value;

pub const Registration = struct { client_id: []const u8, client_secret: ?[]const u8 };
pub fn registerClient(allocator: Allocator, http: *std.http.Client, registration_endpoint: ?[]const u8, redirect_uri: []const u8) !Registration {
    const url = registration_endpoint orelse return error.OauthRegistrationUnsupported;
    var payload = Value{ .object = .empty };
    try payload.object.put(allocator, "client_name", .{ .string = "mcpx" });
    try payload.object.put(allocator, "application_type", .{ .string = "native" });
    try payload.object.put(allocator, "redirect_uris", try stringArray(allocator, &.{redirect_uri}));
    try payload.object.put(allocator, "grant_types", try stringArray(allocator, &.{ "authorization_code", "refresh_token" }));
    try payload.object.put(allocator, "response_types", try stringArray(allocator, &.{"code"}));
    // A CLI is a public client: PKCE replaces client authentication, so no
    // secret has to be stored on disk (RFC 8252 section 8.4, OAuth 2.1).
    try payload.object.put(allocator, "token_endpoint_auth_method", .{ .string = "none" });
    const body = try rpc.jsonString(allocator, payload);
    const value = try token.fetchJson(allocator, http, .POST, url, body, &.{.{ .name = "Content-Type", .value = "application/json" }});
    return .{
        .client_id = rpc.getString(value, "client_id") orelse return error.OauthRegistrationMissingClientId,
        .client_secret = rpc.getString(value, "client_secret"),
    };
}

fn stringArray(allocator: Allocator, values: []const []const u8) !Value {
    var array = Value{ .array = .init(allocator) };
    for (values) |value| try array.array.append(.{ .string = value });
    return array;
}
