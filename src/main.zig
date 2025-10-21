const std = @import("std");
const hashcli = @import("hashcli");
const Allocator = std.mem.Allocator;
const builtin = @import("builtin");

const hashFuncCmd = enum {
    HELP,
    MD5,
    SHA1,
    SHA256,
    SHA512,

    const Self = @This();

    fn fromString(str: []const u8) !Self {
        if (str.len > 8) return error.WrongHashMethod;

        var buf: [8]u8 = undefined;

        var fba = std.heap.FixedBufferAllocator.init(&buf);

        const allocator = fba.allocator();
        const enum_string = try std.ascii.allocUpperString(allocator, str);

        const cmd = std.meta.stringToEnum(hashFuncCmd, enum_string) orelse return error.UnknownHashFunc;

        return cmd;
    }
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    var iter = try std.process.ArgIterator.initWithAllocator(allocator);
    defer iter.deinit();

    _ = iter.next();

    const subCmd = iter.next() orelse return error.EmptySubCommand;

    if (std.mem.eql(u8, subCmd, "-h") or std.mem.eql(u8, subCmd, "--help")) {
        try printHelpInfo(allocator);
        return;
    }

    const hashFunc = try hashFuncCmd.fromString(subCmd);

    var parser = argsPaser.init(allocator, hashFunc);
    try parser.parseArgs(&iter);
    try parser.getHash();
}

const sourceFormat = enum {
    String,
    File,
    Hex,
    Base64,

    Unknown,

    fn fromStringCaseInsensitive(str: []const u8) sourceFormat {
        inline for (@typeInfo(sourceFormat).@"enum".fields) |field| {
            if (std.ascii.eqlIgnoreCase(str, field.name)) {
                return @field(sourceFormat, field.name);
            }
        }
        return .Unknown;
    }
};

const argsPaser = struct {
    allocator: Allocator,

    sourceFormat: sourceFormat = .String,
    content: []const u8 = "",

    hashFunc: hashFuncCmd,
    helpInfo: bool = false,

    const Self = @This();
    fn init(allocator: Allocator, _hashFunc: hashFuncCmd) Self {
        return .{
            .allocator = allocator,
            .hashFunc = _hashFunc,
        };
    }

    fn parseArgs(self: *Self, iter: *std.process.ArgIterator) !void {
        var kv_map = std.StringHashMap([]const u8).init(self.allocator);
        defer kv_map.deinit();

        var last_key: ?[]const u8 = null;

        while (true) {
            const arg = iter.next();
            if (arg == null) break;

            if (last_key == null) {
                if (arg.?[0] != '-' and self.content.len == 0) {
                    self.content = arg.?;
                    // std.debug.print("read content: {s}\n", .{self.content});
                    continue;
                }

                const kv = try parseKeyOrValue(arg.?);
                if (kv.value) |value| {
                    try kv_map.put(kv.key, value);
                } else {
                    last_key = kv.key;
                }
            } else { // find value
                try kv_map.put(last_key.?, arg.?);
                last_key = null;
            }
        }

        var map_iter = kv_map.iterator();
        while (map_iter.next()) |entry| {
            const key = entry.key_ptr.*;
            const value = entry.value_ptr.*;
            // std.debug.print("key: {s} value: {s}\n", .{ entry.key_ptr.*, entry.value_ptr.* });

            if (std.mem.eql(u8, key, "sourceFormat") or std.mem.eql(u8, key, "s")) {
                self.sourceFormat = sourceFormat.fromStringCaseInsensitive(value);
            }
            if (std.mem.eql(u8, key, "help") or std.mem.eql(u8, key, "h")) {
                self.helpInfo = true;
            }
        }

        if (self.sourceFormat == .Unknown) {
            return error.UnknownSourceFormat;
        }

        return;
    }

    fn parseKeyOrValue(_arg: []const u8) !struct { key: []const u8, value: ?[]const u8 } {
        var arg = _arg;
        var key: ?[]const u8 = null;
        var value: ?[]const u8 = null;

        // remove - or --
        if (std.mem.startsWith(u8, arg, "--")) {
            arg = arg[2..];
        }
        if (std.mem.startsWith(u8, arg, "-")) {
            arg = arg[1..];
        }

        const eq_index = std.mem.indexOfScalar(u8, arg, '='); // find the first '='

        if (eq_index) |i| {
            key = arg[0..i];
            value = arg[i + 1 ..];
        } else {
            key = arg;
        }

        return .{
            .key = key.?,
            .value = value,
        };
    }

    fn getHash(self: Self) !void {
        const r: Reader = switch (self.sourceFormat) {
            .File => blk: {
                const file = try std.fs.cwd().openFile(self.content, .{ .mode = .read_only });
                // defer file.close();
                break :blk Reader{ .FileReader = file };
            },

            .String => blk: {
                break :blk Reader{ .Bytes = self.content };
            },
            .Base64 => blk: {
                const decode_size = try std.base64.standard.Decoder.calcSizeForSlice(self.content);
                const dest = try self.allocator.alloc(u8, decode_size);
                try std.base64.standard.Decoder.decode(dest, self.content);
                break :blk Reader{ .Bytes = dest };
            },
            .Hex => blk: {
                var dest = try self.allocator.alloc(u8, self.content.len / 2);

                dest = try std.fmt.hexToBytes(dest, self.content);
                break :blk Reader{ .Bytes = dest };
            },

            else => {
                return error.UnknownSourceFormat;
            },
        };

        switch (self.hashFunc) {
            .MD5 => try self.hashAdapt(std.crypto.hash.Md5, r),
            .SHA1 => try self.hashAdapt(std.crypto.hash.Sha1, r),
            .SHA256 => try self.hashAdapt(std.crypto.hash.sha2.Sha256, r),
            .SHA512 => try self.hashAdapt(std.crypto.hash.sha2.Sha512, r),

            else => return error.UnsupportHashFunc,
        }

        return;
    }
    const Reader = union(enum) {
        Bytes: []const u8,
        FileReader: std.fs.File,
    };

    fn hashAdapt(self: Self, comptime T: type, reader: Reader) !void {
        var hasher = T.init(.{});

        switch (reader) {
            .Bytes => |val| {
                hasher.update(val);
            },
            .FileReader => |file| {
                defer file.close();
                var buff: [4096]u8 = undefined;

                while (true) {
                    const n = try file.read(&buff);
                    if (n == 0) break;
                    hasher.update(buff[0..n]);
                }
            },
        }

        var hashBuff: [T.digest_length]u8 = undefined;

        hasher.final(&hashBuff);

        std.debug.print("{s}: {x}\n", .{ @tagName(self.hashFunc), hashBuff });
    }
};

fn printHelpInfo(allocator: Allocator) !void {
    const help_text = try std.fmt.allocPrint(allocator, "Usage: hashcli <hash_method> [options] <content>\n\n" ++
        "Hash Methods:\n" ++
        "  MD5      Calculate MD5 hash\n" ++
        "  SHA1     Calculate SHA1 hash\n" ++
        "  SHA256   Calculate SHA256 hash\n" ++
        "  SHA512   Calculate SHA512 hash\n\n" ++
        "Options:\n" ++
        "  -s, --sourceFormat <format>  Input format (string, file, hex, base64) default: string\n" ++
        "  -h, --help                   Show this help message\n\n" ++
        "Example:\n" ++
        "  hashcli md5 -s string \"Hello World\"\n", .{});
    defer allocator.free(help_text);

    try std.fs.File.stdout().writeAll(help_text);
}
