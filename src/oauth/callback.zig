const std = @import("std");

const Allocator = std.mem.Allocator;
const Io = std.Io;

pub const Callback = struct {
    code: []const u8,
    state: []const u8,
};

pub fn parseCallbackRequestLine(allocator: Allocator, line: []const u8) !Callback {
    var pieces = std.mem.splitScalar(u8, line, ' ');
    if (!std.mem.eql(u8, pieces.next() orelse return error.InvalidCallbackRequest, "GET"))
        return error.InvalidCallbackRequest;
    const target = pieces.next() orelse return error.InvalidCallbackRequest;
    const query_start = std.mem.indexOfScalar(u8, target, '?') orelse return error.CallbackMissingQuery;
    const query_end = std.mem.indexOfScalarPos(u8, target, query_start, '#') orelse target.len;
    var code: ?[]const u8 = null;
    var state: ?[]const u8 = null;
    var fields = std.mem.splitScalar(u8, target[query_start + 1 .. query_end], '&');
    while (fields.next()) |field| {
        const equals = std.mem.indexOfScalar(u8, field, '=') orelse continue;
        const name = field[0..equals];
        const decoded = try percentDecode(allocator, field[equals + 1 ..]);
        if (std.mem.eql(u8, name, "code")) code = decoded;
        if (std.mem.eql(u8, name, "state")) state = decoded;
    }
    return .{
        .code = code orelse return error.CallbackMissingCode,
        .state = state orelse return error.CallbackMissingState,
    };
}

pub fn percentDecode(allocator: Allocator, value: []const u8) ![]const u8 {
    var output: Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    var i: usize = 0;
    while (i < value.len) {
        if (value[i] == '%' and i + 2 < value.len) {
            try output.writer.writeByte(try std.fmt.parseInt(u8, value[i + 1 .. i + 3], 16));
            i += 3;
        } else {
            try output.writer.writeByte(if (value[i] == '+') ' ' else value[i]);
            i += 1;
        }
    }
    return output.toOwnedSlice();
}

pub fn bindCallback(io: Io) !std.Io.net.Server {
    const address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    return address.listen(io, .{ .reuse_address = true });
}

pub fn acceptCallback(allocator: Allocator, io: Io, server: *std.Io.net.Server) !Callback {
    const stream = try server.accept(io);
    defer stream.close(io);
    var read_buffer: [8192]u8 = undefined;
    var reader = stream.reader(io, &read_buffer);
    const line = try reader.interface.takeDelimiterExclusive('\n');
    const callback = try parseCallbackRequestLine(allocator, std.mem.trimEnd(u8, line, "\r"));
    while (true) {
        const header = try reader.interface.takeDelimiterExclusive('\n');
        if (std.mem.trim(u8, header, "\r").len == 0) break;
    }
    const html = "<!doctype html><title>mcpx OAuth complete</title><p>Authorization complete. You may close this window.</p>";
    var write_buffer: [1024]u8 = undefined;
    var writer = stream.writer(io, &write_buffer);
    try writer.interface.print("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{ html.len, html });
    try writer.interface.flush();
    return callback;
}

test "callback request line extracts and decodes code and state" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const callback = try parseCallbackRequestLine(arena.allocator(), "GET /callback?code=a%2Fb&state=hello%20world HTTP/1.1");
    try std.testing.expectEqualStrings("a/b", callback.code);
    try std.testing.expectEqualStrings("hello world", callback.state);
}

test "callback listener binds an ephemeral loopback port" {
    var server = try bindCallback(std.testing.io);
    defer server.deinit(std.testing.io);
    try std.testing.expect(server.socket.address.getPort() != 0);
}
