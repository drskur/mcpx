const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Value = std.json.Value;
const Tool = @import("client.zig").Tool;

pub fn renderTool(out: *Io.Writer, allocator: Allocator, tool: Tool) !void {
    try out.print("## {s}\n", .{tool.name() orelse return error.ToolMissingName});
    if (tool.description()) |desc| try out.print("\n{s}\n", .{desc});
    if (get(tool.value, "inputSchema")) |schema| {
        try out.writeAll("\n### Parameters\n\n");
        try renderSchema(out, allocator, schema, 0);
    }
    if (get(tool.value, "outputSchema")) |schema| {
        try out.writeAll("\n### Returns\n\n");
        try renderSchema(out, allocator, schema, 0);
    }
    try out.writeByte('\n');
}

pub fn prettyPrint(out: *Io.Writer, value: Value) !void {
    try std.json.Stringify.value(value, .{ .whitespace = .indent_2 }, out);
    try out.writeByte('\n');
}

fn renderSchema(out: *Io.Writer, allocator: Allocator, schema: Value, indent: usize) !void {
    if (getString(schema, "$ref")) |ref| {
        try spaces(out, indent);
        try out.print("- Reference: `{s}`\n", .{ref});
        return;
    }
    const props = get(schema, "properties") orelse {
        try out.writeAll("```json\n");
        try prettyPrint(out, schema);
        try out.writeAll("```\n");
        return;
    };
    if (props != .object) return error.InvalidSchemaProperties;
    var it = props.object.iterator();
    while (it.next()) |entry| {
        const prop = entry.value_ptr.*;
        try spaces(out, indent);
        try out.print("- `{s}` ({s})", .{ entry.key_ptr.*, try schemaType(allocator, prop) });
        if (isRequired(schema, entry.key_ptr.*)) try out.writeAll(" **(required)**");
        try schemaDetails(out, allocator, prop);
        if (getString(prop, "description")) |desc| if (desc.len != 0) try out.print(": {s}", .{desc});
        try out.writeByte('\n');
        if (get(prop, "properties") != null) try renderSchema(out, allocator, prop, indent + 1) else if (get(prop, "items")) |items| if (get(items, "properties") != null or get(items, "$ref") != null) try renderSchema(out, allocator, items, indent + 1);
    }
}

fn spaces(out: *Io.Writer, indent: usize) !void {
    for (0..indent) |_| try out.writeAll("  ");
}

fn isRequired(schema: Value, name: []const u8) bool {
    const req = get(schema, "required") orelse return false;
    if (req != .array) return false;
    for (req.array.items) |v| if (v == .string and std.mem.eql(u8, v.string, name)) return true;
    return false;
}

fn schemaType(allocator: Allocator, schema: Value) ![]const u8 {
    if (getString(schema, "$ref")) |ref| return std.fmt.allocPrint(allocator, "ref: {s}", .{ref});
    const kind = getString(schema, "type") orelse return "any";
    if (!std.mem.eql(u8, kind, "array")) return kind;
    return std.fmt.allocPrint(allocator, "array of {s}", .{if (get(schema, "items")) |items| try schemaType(allocator, items) else "any"});
}

fn schemaDetails(out: *Io.Writer, allocator: Allocator, schema: Value) !void {
    var first = true;
    if (get(schema, "enum")) |values| if (values == .array) {
        try out.writeAll(" (enum: ");
        for (values.array.items, 0..) |v, i| {
            if (i != 0) try out.writeAll(" | ");
            try out.writeAll(try displayScalar(allocator, v));
        }
        first = false;
    };
    const fields = [_][]const u8{ "minLength", "maxLength", "minimum", "maximum", "pattern", "default" };
    for (fields) |field| if (get(schema, field)) |v| {
        try out.print("{s}{s}: {s}", .{ if (first) " (" else ", ", field, try displayScalar(allocator, v) });
        first = false;
    };
    if (!first) try out.writeByte(')');
}

fn get(value: Value, key: []const u8) ?Value {
    return if (value == .object) value.object.get(key) else null;
}

fn getString(value: Value, key: []const u8) ?[]const u8 {
    const v = get(value, key) orelse return null;
    return if (v == .string) v.string else null;
}

fn jsonString(allocator: Allocator, value: Value) ![]u8 {
    var output: Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    try std.json.Stringify.value(value, .{}, &output.writer);
    return output.toOwnedSlice();
}

fn displayScalar(allocator: Allocator, value: Value) ![]const u8 {
    return if (value == .string) value.string else jsonString(allocator, value);
}

fn parseTestJson(allocator: Allocator, text: []const u8) !Value {
    return std.json.parseFromSliceLeaky(Value, allocator, text, .{});
}

fn renderTestTool(allocator: Allocator) ![]const u8 {
    const value = try parseTestJson(allocator,
        \\{"name":"search","inputSchema":{"type":"object","properties":{"kind":{"type":"string","enum":["a","b"]}},"required":["kind"]}}
    );
    var output: Io.Writer.Allocating = .init(allocator);
    try renderTool(&output.writer, allocator, .{ .value = value });
    return output.toOwnedSlice();
}

test "renderTool produces markdown with heading" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const output = try renderTestTool(arena.allocator());
    try std.testing.expect(std.mem.startsWith(u8, output, "## search\n"));
}

test "renderTool shows required flag" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const output = try renderTestTool(arena.allocator());
    try std.testing.expect(std.mem.indexOf(u8, output, "**(required)**") != null);
}

test "renderTool shows enum constraints" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const output = try renderTestTool(arena.allocator());
    try std.testing.expect(std.mem.indexOf(u8, output, "enum: a | b") != null);
}

test "prettyPrint produces indented JSON" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const value = try parseTestJson(arena.allocator(), "{\"outer\":{\"value\":1}}");
    var output: Io.Writer.Allocating = .init(arena.allocator());
    try prettyPrint(&output.writer, value);
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "\n  \"outer\": {\n    \"value\": 1\n") != null);
}
