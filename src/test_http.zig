const std = @import("std");

const Io = std.Io;

pub const Response = struct {
    status: []const u8,
    content_type: []const u8 = "application/json",
    extra_headers: []const u8 = "",
    body: []const u8,
};

pub const Script = struct {
    responses: []const Response,
    requests: [8][8192]u8 = undefined,
    request_lengths: [8]usize = @splat(0),

    pub fn serve(self: *Script, io: Io, server: *std.Io.net.Server) !void {
        for (self.responses, 0..) |response, index| {
            const stream = try server.accept(io);
            defer stream.close(io);
            var read_buffer: [8192]u8 = undefined;
            var reader = stream.reader(io, &read_buffer);
            var content_length: usize = 0;
            var request_writer = Io.Writer.fixed(&self.requests[index]);
            while (true) {
                const line = try reader.interface.takeDelimiterExclusive('\n');
                const trimmed = std.mem.trimEnd(u8, line, "\r");
                reader.interface.toss(1);
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
            if (content_length > read_buffer.len) return error.TestRequestTooLarge;
            var body: [8192]u8 = undefined;
            try reader.interface.readSliceAll(body[0..content_length]);

            var write_buffer: [1024]u8 = undefined;
            var writer = stream.writer(io, &write_buffer);
            try writer.interface.print(
                "HTTP/1.1 {s}\r\nContent-Type: {s}\r\nContent-Length: {d}\r\nConnection: close\r\n{s}\r\n{s}",
                .{ response.status, response.content_type, response.body.len, response.extra_headers, response.body },
            );
            try writer.interface.flush();
        }
    }

    pub fn request(self: *const Script, index: usize) []const u8 {
        return self.requests[index][0..self.request_lengths[index]];
    }
};
