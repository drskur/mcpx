const std = @import("std");

const Io = std.Io;

pub const max_scripted_responses = 16;
const max_recorded_request = 8192;

pub const Response = struct {
    status: []const u8,
    content_type: []const u8 = "application/json",
    extra_headers: []const u8 = "",
    body: []const u8,
};

pub const Script = struct {
    responses: []const Response,
    /// Serves every response over a single connection so that connection reuse
    /// is exercised the way real MCP servers behave.
    keep_alive: bool = false,
    requests: [max_scripted_responses][max_recorded_request]u8 = undefined,
    request_lengths: [max_scripted_responses]usize = @splat(0),

    pub fn serve(self: *Script, io: Io, server: *std.Io.net.Server) !void {
        if (self.responses.len > max_scripted_responses) return error.TestTooManyResponses;
        if (self.keep_alive) {
            const stream = try server.accept(io);
            defer stream.close(io);
            var read_buffer: [max_recorded_request]u8 = undefined;
            var reader = stream.reader(io, &read_buffer);
            var write_buffer: [1024]u8 = undefined;
            var writer = stream.writer(io, &write_buffer);
            for (self.responses, 0..) |response, index| {
                try self.readRequest(&reader.interface, index);
                try writeResponse(&writer.interface, response, true);
            }
            return;
        }
        for (self.responses, 0..) |response, index| {
            const stream = try server.accept(io);
            defer stream.close(io);
            var read_buffer: [max_recorded_request]u8 = undefined;
            var reader = stream.reader(io, &read_buffer);
            try self.readRequest(&reader.interface, index);
            var write_buffer: [1024]u8 = undefined;
            var writer = stream.writer(io, &write_buffer);
            try writeResponse(&writer.interface, response, false);
        }
    }

    fn readRequest(self: *Script, reader: *Io.Reader, index: usize) !void {
        var content_length: usize = 0;
        var request_writer = Io.Writer.fixed(&self.requests[index]);
        while (true) {
            const line = try reader.takeDelimiterExclusive('\n');
            const trimmed = std.mem.trimEnd(u8, line, "\r");
            reader.toss(1);
            if (trimmed.len == 0) break;
            try request_writer.writeAll(trimmed);
            try request_writer.writeByte('\n');
            if (std.ascii.startsWithIgnoreCase(trimmed, "Content-Length:")) {
                content_length = try std.fmt.parseInt(
                    usize,
                    std.mem.trim(u8, trimmed["Content-Length:".len..], " \t"),
                    10,
                );
            }
        }
        self.request_lengths[index] = request_writer.end;
        if (content_length > max_recorded_request) return error.TestRequestTooLarge;
        var body: [max_recorded_request]u8 = undefined;
        try reader.readSliceAll(body[0..content_length]);
    }

    pub fn request(self: *const Script, index: usize) []const u8 {
        return self.requests[index][0..self.request_lengths[index]];
    }
};

fn writeResponse(writer: *Io.Writer, response: Response, keep_alive: bool) !void {
    try writer.print(
        "HTTP/1.1 {s}\r\nContent-Type: {s}\r\nContent-Length: {d}\r\nConnection: {s}\r\n{s}\r\n{s}",
        .{
            response.status,
            response.content_type,
            response.body.len,
            if (keep_alive) "keep-alive" else "close",
            response.extra_headers,
            response.body,
        },
    );
    try writer.flush();
}

/// Accepts one connection, reads the request and then never answers, so the
/// client side has to hit its own deadline.
pub fn serveStalled(io: Io, server: *std.Io.net.Server) !void {
    const stream = try server.accept(io);
    defer stream.close(io);
    var read_buffer: [4096]u8 = undefined;
    var reader = stream.reader(io, &read_buffer);
    while (true) {
        const line = reader.interface.takeDelimiterExclusive('\n') catch break;
        reader.interface.toss(1);
        if (std.mem.trimEnd(u8, line, "\r").len == 0) break;
    }
    // Cancelation of this task is the only way out.
    while (true) Io.Timeout.sleep(.{ .duration = .{ .clock = .awake, .raw = .fromSeconds(3600) } }, io) catch return;
}

pub fn listenLoopback(io: Io) !std.Io.net.Server {
    const address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    return address.listen(io, .{ .reuse_address = true });
}

pub fn endpointFor(allocator: std.mem.Allocator, server: *const std.Io.net.Server) ![]const u8 {
    return std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/mcp", .{server.socket.address.getPort()});
}

pub fn originFor(allocator: std.mem.Allocator, server: *const std.Io.net.Server) ![]const u8 {
    return std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}", .{server.socket.address.getPort()});
}
