const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
    });

    const source_files = &.{"src/ipcrypt2.c"};
    lib_mod.addCSourceFiles(.{ .files = source_files });

    const lib = b.addLibrary(.{
        .linkage = .static,
        .name = "ipcrypt2",
        .root_module = lib_mod,
        .version = .{ .major = 1, .minor = 0, .patch = 0 },
    });

    lib.linkLibC();

    b.installArtifact(lib);

    b.installDirectory(.{
        .install_dir = .header,
        .install_subdir = "",
        .source_dir = b.path("src/include"),
    });

    const main_tests = b.addTest(.{
        .root_source_file = b.path("src/test/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    main_tests.addIncludePath(b.path("src/include"));
    main_tests.linkLibrary(lib);

    const run_main_tests = b.addRunArtifact(main_tests);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_main_tests.step);
}
