const std = @import("std");

/// The package manifest is the single source of truth for the version that
/// mcpx reports over MCP and in `--help`.
const manifest_version = @import("build.zig.zon").version;

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const build_info = b.addOptions();
    build_info.addOption([]const u8, "version", manifest_version);
    const strip: ?bool = if (optimize != .Debug) true else null;
    const toml_dep = b.dependency("toml", .{
        .target = target,
        .optimize = optimize,
    });
    const exe = b.addExecutable(.{
        .name = "mcpx",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .strip = strip,
            .imports = &.{
                .{ .name = "toml", .module = toml_dep.module("toml") },
                .{ .name = "build_info", .module = build_info.createModule() },
            },
        }),
    });
    b.installArtifact(exe);

    const run = b.addRunArtifact(exe);
    if (b.args) |args| run.addArgs(args);
    const run_step = b.step("run", "Run mcpx");
    run_step.dependOn(&run.step);

    const tests = b.addTest(.{ .root_module = exe.root_module });
    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_tests.step);
}
