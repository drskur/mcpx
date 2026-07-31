const std = @import("std");

const Allocator = std.mem.Allocator;
const Io = std.Io;
const Value = std.json.Value;

/// `std.json.parseFromSliceLeaky` defaults to `.alloc_if_needed`, which makes
/// `Value.string` alias the input buffer. Every parse in mcpx outlives its
/// input, so strings are always copied into the allocator instead.
const parse_options: std.json.ParseOptions = .{ .allocate = .alloc_always };

pub fn parse(allocator: Allocator, text: []const u8) !Value {
    return std.json.parseFromSliceLeaky(Value, allocator, text, parse_options);
}

pub fn get(value: Value, key: []const u8) ?Value {
    return if (value == .object) value.object.get(key) else null;
}

pub fn getString(value: Value, key: []const u8) ?[]const u8 {
    const value_at_key = get(value, key) orelse return null;
    return if (value_at_key == .string) value_at_key.string else null;
}

pub fn getInteger(value: Value, key: []const u8) ?i64 {
    const value_at_key = get(value, key) orelse return null;
    return if (value_at_key == .integer) value_at_key.integer else null;
}

pub fn getBool(value: Value, key: []const u8) ?bool {
    const value_at_key = get(value, key) orelse return null;
    return if (value_at_key == .bool) value_at_key.bool else null;
}

pub fn stringify(allocator: Allocator, value: Value) ![]u8 {
    var output: Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    try std.json.Stringify.value(value, .{}, &output.writer);
    return output.toOwnedSlice();
}

/// Strings render as themselves; every other scalar renders as JSON.
pub fn displayScalar(allocator: Allocator, value: Value) ![]const u8 {
    return if (value == .string) value.string else stringify(allocator, value);
}

test "accessors ignore mismatched types instead of failing" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const value = try parse(arena.allocator(),
        \\{"name":"search","count":2,"flag":true,"nested":{"a":1}}
    );
    try std.testing.expectEqualStrings("search", getString(value, "name").?);
    try std.testing.expect(getString(value, "count") == null);
    try std.testing.expectEqual(@as(?i64, 2), getInteger(value, "count"));
    try std.testing.expect(getInteger(value, "name") == null);
    try std.testing.expectEqual(@as(?bool, true), getBool(value, "flag"));
    try std.testing.expect(getBool(value, "count") == null);
    try std.testing.expect(get(value, "nested").? == .object);
    try std.testing.expect(get(.{ .integer = 1 }, "nested") == null);
}

test "parsed strings survive the input buffer" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const input = try allocator.dupe(u8, "{\"name\":\"search\"}");
    const value = try parse(allocator, input);
    @memset(input, '#');
    try std.testing.expectEqualStrings("search", getString(value, "name").?);
}

test "displayScalar renders non-strings as JSON" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    try std.testing.expectEqualStrings("text", try displayScalar(allocator, .{ .string = "text" }));
    try std.testing.expectEqualStrings("-32602", try displayScalar(allocator, .{ .integer = -32602 }));
    try std.testing.expectEqualStrings("true", try displayScalar(allocator, .{ .bool = true }));
}
