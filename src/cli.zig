const std = @import("std");
const diagnostics_out = @import("diagnostics.zig");
const build_info = @import("build_info");
const Io = std.Io;

pub const ParsedArgs = struct {
    config: ?[]const u8,
    command: []const u8,
    positionals: [3][]const u8,
    positionals_len: usize,
    help: bool = false,
};

pub fn parseArgs(args: []const []const u8) !ParsedArgs {
    var config: ?[]const u8 = null;
    var command: ?[]const u8 = null;
    var positions: [3][]const u8 = undefined;
    var count: usize = 0;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) return .{
            .config = config,
            .command = "",
            .positionals = undefined,
            .positionals_len = 0,
            .help = true,
        };
        if (std.mem.eql(u8, arg, "-c") or std.mem.eql(u8, arg, "--config")) {
            i += 1;
            if (i == args.len) return error.MissingConfigPath;
            if (isFlag(args[i])) return error.MissingConfigPath;
            config = args[i];
        } else if (std.mem.startsWith(u8, arg, "--config=")) {
            config = arg["--config=".len..];
            if (config.?.len == 0) return error.MissingConfigPath;
        } else if (isFlag(arg)) {
            // Unknown options must not be silently consumed as a server, tool
            // or JSON argument.
            diagnostics_out.report("unknown option '{s}'\n", .{arg});
            return error.UnknownOption;
        } else if (command == null) command = arg else {
            if (count == positions.len) return error.TooManyArguments;
            positions[count] = arg;
            count += 1;
        }
    }
    const cmd = command orelse return .{
        .config = config,
        .command = "",
        .positionals = undefined,
        .positionals_len = 0,
        .help = true,
    };
    const needed: usize = if (std.mem.eql(u8, cmd, "servers")) 0 else if (std.mem.eql(u8, cmd, "auth")) 1 else if (std.mem.eql(u8, cmd, "list")) 1 else if (std.mem.eql(u8, cmd, "call")) 2 else if (std.mem.eql(u8, cmd, "skills")) 1 else {
        if (count == positions.len) return error.TooManyArguments;
        var index = count;
        while (index > 0) : (index -= 1) positions[index] = positions[index - 1];
        positions[0] = cmd;
        count += 1;
        const default_command = if (count == 1) "list" else "call";
        return .{ .config = config, .command = default_command, .positionals = positions, .positionals_len = count };
    };
    if (count < needed) return error.MissingArgument;
    return .{ .config = config, .command = cmd, .positionals = positions, .positionals_len = count };
}

/// A lone "-" and negative numbers stay usable as positional arguments.
fn isFlag(arg: []const u8) bool {
    if (arg.len < 2 or arg[0] != '-') return false;
    return !std.ascii.isDigit(arg[1]) and arg[1] != '.';
}

pub fn writeUsage(io: Io) !void {
    var buffer: [2048]u8 = undefined;
    var file: Io.File.Writer = .init(.stdout(), io, &buffer);
    try file.interface.print("mcpx {s} - CLI bridge for MCP HTTP servers\n", .{build_info.version});
    try file.interface.writeAll(
        \\
        \\Usage: mcpx [-c PATH] <COMMAND>
        \\       mcpx [-c PATH] <server> [tool] [json_args]
        \\
        \\Commands:
        \\  servers
        \\  auth <server>
        \\  list <server>
        \\  call <server> <tool> [json_args]
        \\    Use - as json_args to read JSON from stdin.
        \\  skills <server> [tool]
        \\
        \\Omitting the command lists a server's tools, or calls the named tool.
        \\Command names are reserved and take priority over server names.
        \\
    );
    try file.interface.flush();
}

test "argument parser accepts global config flag" {
    const parsed = try parseArgs(&.{ "mcpx", "skills", "demo", "search", "-c", "test.toml" });
    try std.testing.expectEqualStrings("skills", parsed.command);
    try std.testing.expectEqualStrings("test.toml", parsed.config.?);
    try std.testing.expectEqualStrings("search", parsed.positionals[1]);
}

test "argument parser treats no arguments as help" {
    const parsed = try parseArgs(&.{"mcpx"});
    try std.testing.expect(parsed.help);
}

test "argument parser defaults server to list" {
    const parsed = try parseArgs(&.{ "mcpx", "demo" });
    try std.testing.expectEqualStrings("list", parsed.command);
    try std.testing.expectEqual(@as(usize, 1), parsed.positionals_len);
    try std.testing.expectEqualStrings("demo", parsed.positionals[0]);
}

test "argument parser defaults server and tool to call" {
    const parsed = try parseArgs(&.{ "mcpx", "demo", "search" });
    try std.testing.expectEqualStrings("call", parsed.command);
    try std.testing.expectEqual(@as(usize, 2), parsed.positionals_len);
    try std.testing.expectEqualStrings("demo", parsed.positionals[0]);
    try std.testing.expectEqualStrings("search", parsed.positionals[1]);
}

test "argument parser rejects missing argument" {
    try std.testing.expectError(error.MissingArgument, parseArgs(&.{ "mcpx", "call", "demo" }));
}

test "argument parser rejects too many arguments" {
    try std.testing.expectError(error.TooManyArguments, parseArgs(&.{ "mcpx", "call", "demo", "tool", "{}", "extra" }));
}

test "argument parser accepts config after positionals" {
    const parsed = try parseArgs(&.{ "mcpx", "call", "demo", "tool", "-c", "late.toml" });
    try std.testing.expectEqualStrings("late.toml", parsed.config.?);
    try std.testing.expectEqual(@as(usize, 2), parsed.positionals_len);
}

test "argument parser accepts auth command" {
    const parsed = try parseArgs(&.{ "mcpx", "auth", "demo" });
    try std.testing.expectEqualStrings("auth", parsed.command);
    try std.testing.expectEqualStrings("demo", parsed.positionals[0]);
}

test "argument parser gives recognized commands priority" {
    const list = try parseArgs(&.{ "mcpx", "list", "demo" });
    try std.testing.expectEqualStrings("list", list.command);
    try std.testing.expectEqualStrings("demo", list.positionals[0]);

    const call = try parseArgs(&.{ "mcpx", "call", "demo", "search" });
    try std.testing.expectEqualStrings("call", call.command);
    try std.testing.expectEqualStrings("demo", call.positionals[0]);
    try std.testing.expectEqualStrings("search", call.positionals[1]);

    const skills = try parseArgs(&.{ "mcpx", "skills", "demo" });
    try std.testing.expectEqualStrings("skills", skills.command);
    const auth = try parseArgs(&.{ "mcpx", "auth", "demo" });
    try std.testing.expectEqualStrings("auth", auth.command);
}

test "argument parser keeps servers as a command without positionals" {
    const parsed = try parseArgs(&.{ "mcpx", "servers" });
    try std.testing.expectEqualStrings("servers", parsed.command);
    try std.testing.expectEqual(@as(usize, 0), parsed.positionals_len);
}

test "argument parser rejects unknown options instead of taking them as arguments" {
    try std.testing.expectError(error.UnknownOption, parseArgs(&.{ "mcpx", "list", "demo", "--verbose" }));
    try std.testing.expectError(error.UnknownOption, parseArgs(&.{ "mcpx", "-x", "list", "demo" }));
    try std.testing.expectError(error.MissingConfigPath, parseArgs(&.{ "mcpx", "list", "demo", "-c" }));
    try std.testing.expectError(error.MissingConfigPath, parseArgs(&.{ "mcpx", "-c", "--help", "list", "demo" }));
}

test "argument parser accepts inline config values and negative arguments" {
    const parsed = try parseArgs(&.{ "mcpx", "--config=inline.toml", "call", "demo", "tool" });
    try std.testing.expectEqualStrings("inline.toml", parsed.config.?);
    const negative = try parseArgs(&.{ "mcpx", "call", "demo", "tool", "-1" });
    try std.testing.expectEqualStrings("-1", negative.positionals[2]);
}
