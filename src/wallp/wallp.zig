const std = @import("std");
const win = @import("windows");
const ansi = @import("../ansi.zig");
const unicode = std.unicode;

const Allocator = std.mem.Allocator;
const Io = std.Io;

const ERROR = ansi.@"error" ++ "Error: " ++ ansi.reset;

const DesktopManager = struct {
    inner: *win.IDesktopWallpaper,
    monitors: [][*:0]const u16,
    monitors_len: usize,

    const Self = @This();

    fn init(allocator: Allocator) !Self {
        var self: Self = undefined;

        var hr = win.CoInitializeEx(null, win.COINIT_APARTMENTTHREADED);
        if (win.FAILED(hr)) {
            std.debug.print(ERROR ++ "CoInit Failed\n", .{});
            return error.ComInitFailed;
        }
        errdefer win.CoUninitialize();

        hr = win.CoCreateInstance(
            &win.CLSID_DesktopWallpaper,
            null,
            win.CLSCTX_ALL,
            &win.IID_IDesktopWallpaper,
            @ptrCast(&self.inner),
        );
        if (win.FAILED(hr)) {
            std.debug.print(ERROR ++ "CoCreateInstance Failed\n", .{});
            return error.ComInitFailed;
        }

        var monitors_len: c_uint = undefined;
        hr = self.inner.lpVtbl.*.GetMonitorDevicePathCount.?(@ptrCast(self.inner), &monitors_len);
        if (win.FAILED(hr)) {
            std.debug.print(ERROR ++ "cannot obtain monitor device count\n", .{});
            return error.ComInitFailed;
        }

        self.monitors_len = 0;
        self.monitors = try allocator.alloc([*:0]const u16, @intCast(monitors_len));
        errdefer {
            for (0..monitors_len) |i|
                win.CoTaskMemFree(@ptrCast(@constCast(self.monitors[i])));
            allocator.free(self.monitors);
        }

        for (0..monitors_len) |i| {
            var monitor_id: [*:0]const u16 = undefined;
            hr = self.inner.lpVtbl.*.GetMonitorDevicePathAt.?(
                @ptrCast(self.inner),
                @intCast(i),
                @ptrCast(&monitor_id),
            );
            if (win.FAILED(hr)) {
                std.debug.print(ERROR ++ "cannot obtain monitor device count\n", .{});
                return error.ComInitFailed;
            }
            errdefer win.CoTaskMemFree(@ptrCast(@constCast(monitor_id)));

            self.monitors[self.monitors_len] = monitor_id;
            self.monitors_len += 1;
        }

        return self;
    }

    fn deinit(self: *const Self, allocator: Allocator) void {
        for (0..self.monitors_len) |i|
            win.CoTaskMemFree(@ptrCast(@constCast(self.monitors[i])));
        allocator.free(self.monitors);
        win.CoUninitialize();
    }
};

pub fn wallp(
    allocator: Allocator,
    io: Io,
    monitor: usize,
    wallp_path: []const u8,
    print_list: bool,
) !void {
    const dm = try DesktopManager.init(allocator);
    defer dm.deinit(allocator);

    if (print_list) {
        for (dm.monitors, 0..) |monitor_str_utf16, i| {
            const monitor_str_utf16_len = std.mem.len(monitor_str_utf16);
            const monitor_str = try unicode.utf16LeToUtf8Alloc(
                allocator,
                monitor_str_utf16[0..monitor_str_utf16_len],
            );
            defer allocator.free(monitor_str);

            std.debug.print("{}: {s}\n", .{ i, monitor_str });
        }
    } else {
        // change monitor wallpaper
        const wallpaper_utf8 = try Io.Dir.realPathFileAlloc(.cwd(), io, wallp_path, allocator);
        defer allocator.free(wallpaper_utf8);
        const wallpaper = try unicode.utf8ToUtf16LeAllocZ(allocator, wallpaper_utf8);
        defer allocator.free(wallpaper);

        if (monitor >= dm.monitors_len) {
            std.debug.print(ERROR ++ "monitor number is too big\n", .{});
            return error.WallpFailed;
        }

        const hr = dm.inner.lpVtbl.*.SetWallpaper.?(
            @ptrCast(dm.inner),
            @ptrCast(dm.monitors[monitor]),
            @ptrCast(wallpaper),
        );
        if (win.FAILED(hr)) {
            std.debug.print(ERROR ++ "failed to change wallpaper\n", .{});
            return error.WallpFailed;
        }
    }
}
