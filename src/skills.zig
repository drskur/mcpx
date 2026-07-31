const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Value = std.json.Value;
const Tool = @import("client.zig").Tool;
const json = @import("json.zig");

const get = json.get;
const getString = json.getString;
const displayScalar = json.displayScalar;

/// A server controls the schema it advertises, so rendering is bounded instead
/// of recursing as deeply as the JSON parser allows.
const max_schema_depth: usize = 16;

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
    if (indent >= max_schema_depth) {
        try spaces(out, indent);
        try out.writeAll("- ... (schema nested too deeply)\n");
        return;
    }
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
    return schemaTypeAtDepth(allocator, schema, 0);
}

fn schemaTypeAtDepth(allocator: Allocator, schema: Value, depth: usize) ![]const u8 {
    if (depth >= max_schema_depth) return "...";
    if (getString(schema, "$ref")) |ref| return std.fmt.allocPrint(allocator, "ref: {s}", .{ref});
    const kind = getString(schema, "type") orelse return "any";
    if (!std.mem.eql(u8, kind, "array")) return kind;
    const items = get(schema, "items") orelse return "array of any";
    return std.fmt.allocPrint(allocator, "array of {s}", .{try schemaTypeAtDepth(allocator, items, depth + 1)});
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

fn parseTestJson(allocator: Allocator, text: []const u8) !Value {
    return json.parse(allocator, text);
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

test "deeply nested schemas are truncated instead of recursing without bound" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var text: std.ArrayList(u8) = .empty;
    const depth = max_schema_depth + 8;
    for (0..depth) |_| try text.appendSlice(allocator, "{\"type\":\"object\",\"properties\":{\"next\":");
    try text.appendSlice(allocator, "{\"type\":\"string\"}");
    for (0..depth) |_| try text.appendSlice(allocator, "}}");
    const schema = try json.parse(allocator, text.items);
    var output: Io.Writer.Allocating = .init(allocator);
    try renderSchema(&output.writer, allocator, schema, 0);
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "schema nested too deeply") != null);
}

test "deeply nested array types are truncated" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var text: std.ArrayList(u8) = .empty;
    const depth = max_schema_depth + 4;
    for (0..depth) |_| try text.appendSlice(allocator, "{\"type\":\"array\",\"items\":");
    try text.appendSlice(allocator, "{\"type\":\"string\"}");
    for (0..depth) |_| try text.appendSlice(allocator, "}");
    const schema = try json.parse(allocator, text.items);
    try std.testing.expect(std.mem.endsWith(u8, try schemaType(allocator, schema), "array of ..."));
}
