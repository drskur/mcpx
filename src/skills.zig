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

/// Identifies the mcpx invocation that produced a document so the rendered
/// markdown can show commands that work as printed.
pub const Context = struct {
    server: []const u8,
    /// The `-c` / `--config` path in effect, when one was supplied.
    config: ?[]const u8 = null,

    fn writePrefix(self: Context, out: *Io.Writer) !void {
        try out.writeAll("mcpx ");
        if (self.config) |path| try out.print("-c {s} ", .{path});
    }
};

/// Renders one document for a whole server: a preamble that ties the tool
/// reference back to the mcpx commands that reach it, then every tool.
pub fn renderDocument(out: *Io.Writer, allocator: Allocator, ctx: Context, tools: []const Tool) !void {
    try renderPreamble(out, ctx, tools.len);
    for (tools) |tool| try renderTool(out, allocator, ctx, tool);
}

fn renderPreamble(out: *Io.Writer, ctx: Context, tool_count: usize) !void {
    try out.print("# MCP server `{s}`\n\n", .{ctx.server});
    if (tool_count == 0) {
        try out.writeAll("This server advertises no tools. Re-run `");
        try ctx.writePrefix(out);
        try out.print("skills {s}` once it exposes some.\n", .{ctx.server});
        return;
    }
    if (tool_count == 1)
        try out.writeAll("The tool below is reached through the mcpx CLI, not through direct HTTP.\nThe call takes one JSON object argument:\n\n```sh\n")
    else
        try out.print("The {d} tools below are reached through the mcpx CLI, not through direct HTTP.\nEvery call takes one JSON object argument:\n\n```sh\n", .{tool_count});
    try ctx.writePrefix(out);
    try out.print("call {s} <tool> '<json_arguments>'\n```\n\nRelated commands:\n\n- `", .{ctx.server});
    try ctx.writePrefix(out);
    try out.print("list {s}` — tool names with their first description line\n- `", .{ctx.server});
    try ctx.writePrefix(out);
    try out.print("skills {s} <tool>` — this reference for a single tool\n- `", .{ctx.server});
    try ctx.writePrefix(out);
    try out.print("auth {s}` — force a fresh OAuth authorization when the server requires one\n\n", .{ctx.server});
    try out.writeAll(
        \\Argument rules: the JSON must be an object. Pass it as a single shell argument,
        \\or pass `-` to read it from stdin; omit it to send `{}`. On success mcpx prints
        \\the server's JSON result and exits `0`. Exit `6` means the tool ran and reported
        \\`isError`; exit `7` means the tool needs more input.
        \\
        \\
    );
}

pub fn renderTool(out: *Io.Writer, allocator: Allocator, ctx: Context, tool: Tool) !void {
    const name = tool.name() orelse return error.ToolMissingName;
    try out.print("## {s}\n", .{name});
    if (tool.description()) |desc| try out.print("\n{s}\n", .{desc});
    const input_schema = get(tool.value, "inputSchema");
    if (input_schema) |schema| {
        try out.writeAll("\n### Parameters\n\n");
        try renderSchema(out, allocator, schema, 0);
    }
    if (get(tool.value, "outputSchema")) |schema| {
        try out.writeAll("\n### Returns\n\n");
        try renderSchema(out, allocator, schema, 0);
    }
    try out.writeAll("\n### Invocation\n\n```sh\n");
    try ctx.writePrefix(out);
    try out.print("call {s} {s} '", .{ ctx.server, name });
    try writeExampleArgs(out, allocator, input_schema);
    try out.writeAll("'\n```\n");
    try writeOptionalSummary(out, allocator, input_schema);
    try out.writeByte('\n');
}

/// Builds a skeleton argument object out of the required properties so the
/// example is a starting point rather than a placeholder to decode.
fn writeExampleArgs(out: *Io.Writer, allocator: Allocator, schema: ?Value) !void {
    const actual = schema orelse return out.writeAll("{}");
    const props = get(actual, "properties") orelse return out.writeAll("{}");
    if (props != .object) return out.writeAll("{}");
    try out.writeByte('{');
    var first = true;
    var it = props.object.iterator();
    while (it.next()) |entry| {
        const key = entry.key_ptr.*;
        if (!isRequired(actual, key)) continue;
        if (!first) try out.writeAll(", ");
        first = false;
        try out.print("\"{s}\": {s}", .{ key, try exampleValue(allocator, entry.value_ptr.*) });
    }
    try out.writeByte('}');
}

fn exampleValue(allocator: Allocator, schema: Value) ![]const u8 {
    if (get(schema, "default")) |v| return json.stringify(allocator, v);
    if (get(schema, "enum")) |values| if (values == .array and values.array.items.len != 0)
        return json.stringify(allocator, values.array.items[0]);
    const kind = getString(schema, "type") orelse return "null";
    if (std.mem.eql(u8, kind, "integer") or std.mem.eql(u8, kind, "number")) return "0";
    if (std.mem.eql(u8, kind, "boolean")) return "false";
    if (std.mem.eql(u8, kind, "array")) return "[]";
    if (std.mem.eql(u8, kind, "object")) return "{}";
    return "\"...\"";
}

/// Lists optional parameters with their type and default so the caller can
/// tune the invocation without scrolling back to the Parameters section.
fn writeOptionalSummary(out: *Io.Writer, allocator: Allocator, schema: ?Value) !void {
    const actual = schema orelse return;
    const props = get(actual, "properties") orelse return;
    if (props != .object) return;
    var first = true;
    var it = props.object.iterator();
    while (it.next()) |entry| {
        if (isRequired(actual, entry.key_ptr.*)) continue;
        if (first) {
            try out.writeAll("\nOptional: ");
            first = false;
        } else try out.writeAll(", ");
        try out.print("{s} ({s}", .{ entry.key_ptr.*, try schemaType(allocator, entry.value_ptr.*) });
        if (get(entry.value_ptr.*, "default")) |v|
            try out.print(", default {s}", .{try displayScalar(allocator, v)});
        try out.writeByte(')');
    }
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
    try renderTool(&output.writer, allocator, .{ .server = "demo" }, .{ .value = value });
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

test "renderTool includes an mcpx invocation example" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const output = try renderTestTool(arena.allocator());
    try std.testing.expect(std.mem.indexOf(u8, output, "### Invocation") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "mcpx call demo search '{\"kind\": \"a\"}'") != null);
}

test "renderDocument explains the mcpx commands and honors the config flag" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const value = try parseTestJson(allocator, "{\"name\":\"search\"}");
    var output: Io.Writer.Allocating = .init(allocator);
    try renderDocument(&output.writer, allocator, .{ .server = "demo", .config = "my.toml" }, &.{.{ .value = value }});
    const text = output.written();
    try std.testing.expect(std.mem.startsWith(u8, text, "# MCP server `demo`\n"));
    try std.testing.expect(std.mem.indexOf(u8, text, "mcpx -c my.toml list demo`") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "mcpx -c my.toml call demo search '{}'") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "pass `-` to read it from stdin") != null);
}

test "renderDocument reports an empty tool list without an invocation section" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var output: Io.Writer.Allocating = .init(allocator);
    try renderDocument(&output.writer, allocator, .{ .server = "demo" }, &.{});
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "advertises no tools") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "### Invocation") == null);
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
