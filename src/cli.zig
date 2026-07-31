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
    const needed: usize = if (std.mem.eql(u8, cmd, "servers")) 0 else if (std.mem.eql(u8, cmd, "auth")) 1 else if (std.mem.eql(u8, cmd, "list")) 1 else if (std.mem.eql(u8, cmd, "call")) 2 else if (std.mem.eql(u8, cmd, "skills")) 1 else return error.UnknownCommand;
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
        \\
        \\Commands:
        \\  servers
        \\  auth <server>
        \\  list <server>
        \\  call <server> <tool> [json_args]
        \\  skills <server> [tool]
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

test "argument parser rejects unknown command" {
    try std.testing.expectError(error.UnknownCommand, parseArgs(&.{ "mcpx", "wat" }));
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
