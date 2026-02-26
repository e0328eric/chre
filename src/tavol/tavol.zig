const std = @import("std");
const builtin = @import("builtin");
const mem = std.mem;

const assert = std.debug.assert;

const ArrayList = std.ArrayList;
const Allocator = mem.Allocator;
const Io = std.Io;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Aes256 = std.crypto.core.aes.Aes256;
const Endian = std.builtin.Endian;

const aes256_block_size = 16;
const aes256_block_number = 8;

pub fn tavol(
    io: Io,
    key: []const u8,
    input: []const u8,
    output: []const u8,
    encrypt: bool,
    decrypt: bool,
) !void {
    if (encrypt) {
        @branchHint(.likely);
        return encryptFile(io, key, input, output);
    } else if (decrypt) {
        return decryptFile(io, key, input, output);
    }
}

fn encryptFile(
    io: Io,
    key: []const u8,
    to_encrypt: []const u8,
    encrypted: []const u8,
) !void {
    comptime assert(Sha256.digest_length == 32);

    var key_hasher = Sha256.init(.{});
    key_hasher.update(key);
    const orig_key = key_hasher.finalResult();

    const keys: [32]u8, const key_rand: [32]u8 = make_key: {
        var key_rand_orig = [_]u8{0} ** 32;
        io.random(&key_rand_orig);
        var key_rand: @Vector(32, u8) = key_rand_orig;
        key_rand ^= @as(@Vector(32, u8), orig_key);
        break :make_key .{ key_rand, key_rand_orig };
    };

    var cipher = Aes256.initEnc(keys);
    const plaintext_file = try Io.Dir.openFile(.cwd(), io, to_encrypt, .{});
    defer plaintext_file.close(io);
    const cipertext_file = try Io.Dir.createFile(.cwd(), io, encrypted, .{});
    defer cipertext_file.close(io);

    var plaintext_buf: [1024]u8 = undefined;
    var cipertext_buf: [1024]u8 = undefined;
    var plaintext = plaintext_file.reader(io, &plaintext_buf);
    var cipertext = cipertext_file.writer(io, &cipertext_buf);

    var file_buffer = [_]u8{0} ** (aes256_block_size * aes256_block_number);
    var aes_buffer = [_]u8{0} ** (aes256_block_size * aes256_block_number);
    var padding_bytes: u128 = 0;
    while (true) {
        const bytes_read = try plaintext.interface.readSliceShort(&file_buffer);
        const end_of_encrypt = bytes_read < aes256_block_size * aes256_block_number;
        if (end_of_encrypt) {
            padding_bytes = (aes256_block_size * aes256_block_number) - bytes_read;
            io.random(file_buffer[bytes_read..]);
        }

        cipher.encryptWide(aes256_block_number, &aes_buffer, &file_buffer);
        _ = try cipertext.interface.write(&aes_buffer);

        if (end_of_encrypt) {
            break;
        }
    }
    _ = try cipertext.interface.write(&key_rand);

    var padding_bytes_buf: [@sizeOf(u128)]u8 = undefined;
    var padding_aes_buf: [@sizeOf(u128)]u8 = undefined;
    mem.writeInt(u128, &padding_bytes_buf, padding_bytes, Endian.big);
    cipher.encrypt(&padding_aes_buf, &padding_bytes_buf);
    _ = try cipertext.interface.write(&padding_aes_buf);

    // do not forget to flush
    try cipertext.interface.flush();
}

fn decryptFile(
    io: Io,
    key: []const u8,
    input: []const u8,
    output: []const u8,
) !void {
    comptime assert(Sha256.digest_length == 32);

    var key_hasher = Sha256.init(.{});
    key_hasher.update(key);
    const orig_key = key_hasher.finalResult();

    const cipertext_file = try Io.Dir.openFile(.cwd(), io, input, .{});
    defer cipertext_file.close(io);

    var cipertext_buf: [1024]u8 = undefined;
    var cipertext = cipertext_file.reader(io, &cipertext_buf);

    const keys: [32]u8, _ = extract_key: {
        var key_buf: [32]u8 = undefined;
        try cipertext.seekTo(try cipertext.getSize());
        try cipertext.seekBy(-32 - @sizeOf(u128));
        const bytes_read = try cipertext.interface.readSliceShort(&key_buf);
        assert(bytes_read == 32);
        try cipertext.seekTo(0);

        var key_rand: @Vector(32, u8) = key_buf;
        key_rand ^= @as(@Vector(32, u8), orig_key);
        break :extract_key .{ key_rand, key_buf };
    };

    var cipher = Aes256.initDec(keys);
    const padding_bytes = extract_padding: {
        var padding_bytes_buf: [@sizeOf(u128)]u8 = undefined;
        var padding_aes_buf: [@sizeOf(u128)]u8 = undefined;

        try cipertext.seekTo(try cipertext.getSize());
        try cipertext.seekBy(-@sizeOf(u128));
        const bytes_read = try cipertext.interface.readSliceShort(&padding_bytes_buf);
        assert(bytes_read == @sizeOf(u128));
        try cipertext.seekTo(0);

        cipher.decrypt(&padding_aes_buf, &padding_bytes_buf);
        break :extract_padding mem.nativeToBig(u128, mem.bytesToValue(u128, &padding_aes_buf));
    };

    const plaintext_file = try Io.Dir.createFile(.cwd(), io, output, .{});
    defer plaintext_file.close(io);

    var plaintext_buf: [1024]u8 = undefined;
    var plaintext = plaintext_file.writer(io, &plaintext_buf);

    var file_buffer = [_]u8{0} ** (aes256_block_size * aes256_block_number);
    var aes_buffer = [_]u8{0} ** (aes256_block_size * aes256_block_number);
    var i: u128 = 0;
    while (true) {
        const bytes_read = try cipertext.interface.readSliceShort(&file_buffer);
        const end_of_decrypt = bytes_read < aes256_block_size * aes256_block_number;
        if (end_of_decrypt) {
            break;
        }

        cipher.decryptWide(aes256_block_number, &aes_buffer, &file_buffer);
        _ = try plaintext.interface.write(&aes_buffer);
        i += 1;
    }

    const to_drop_bytes: u64 = @intCast(i * 128 -| padding_bytes);
    try plaintext_file.setLength(io, to_drop_bytes);
}

fn getPassword(alloc: Allocator, prompt: []const u8) ![]const u8 {
    var stdout_buf: [1024]u8 = undefined;
    var stdout = std.fs.File.stdout().writer(&stdout_buf);
    try stdout.interface.writeAll(prompt);
    try stdout.end();

    var buf = std.Io.Writer.Allocating.init(alloc);
    errdefer buf.deinit();

    switch (builtin.os.tag) {
        .windows => {
            const w = std.os.windows;
            const k32 = w.kernel32;
            const hIn = k32.GetStdHandle(w.STD_INPUT_HANDLE);
            if (hIn == w.INVALID_HANDLE_VALUE) return error.InputFailure;

            var mode: w.DWORD = 0;
            if (k32.GetConsoleMode(hIn, &mode) == 0) {
                // Not a console (e.g. piped).
                var stdin_buf: [1024]u8 = undefined;
                var stdin = std.fs.File.stdin().reader(&stdin_buf);
                try stdin.interface.streamDelimiterLimit(
                    &buf.writer,
                    '\n',
                    .limited(1 << 16),
                );
                return buf.toOwnedSlice();
            }
        },
        else => @compileError("not supported yet"),
    }
}
