const std = @import("std");

const Allocator = std.mem.Allocator;
const Io = std.Io;
const Value = std.json.Value;

const toml = @import("toml");
const rpc_module = @import("rpc.zig");
const transport = @import("transport.zig");

const version = "0.1.0";
const protocol_version = "2025-03-26";

pub const Server = struct {
    name: []const u8,
    endpoint: []const u8,
    headers: ?toml.HashMap([]const u8) = null,
    timeout_secs: ?u64 = null,

    pub fn timeoutSecs(self: Server) u64 {
        return self.timeout_secs orelse 30;
    }
};

pub const Tool = struct {
    value: Value,

    pub fn name(self: Tool) ?[]const u8 {
        return rpc_module.getString(self.value, "name");
    }

    pub fn description(self: Tool) ?[]const u8 {
        return rpc_module.getString(self.value, "description");
    }
};

pub const McpClient = struct {
    allocator: Allocator,
    io: Io,
    http: std.http.Client,
    server: Server,
    session_id: ?[]const u8 = null,
    negotiated_version: []const u8 = protocol_version,
    supports_tools: bool = false,
    next_id: u64 = 1,
    test_server_responses: ?*std.ArrayList([]u8) = null,

    pub fn init(allocator: Allocator, io: Io, server: Server) McpClient {
        return .{ .allocator = allocator, .io = io, .http = .{ .allocator = allocator, .io = io }, .server = server };
    }

    pub fn deinit(self: *McpClient) void {
        self.http.deinit();
    }

    pub fn connect(self: *McpClient) anyerror!void {
        var params = Value{ .object = .empty };
        try params.object.put(self.allocator, "protocolVersion", .{ .string = protocol_version });
        try params.object.put(self.allocator, "capabilities", .{ .object = .empty });
        var info = Value{ .object = .empty };
        try info.object.put(self.allocator, "name", .{ .string = "mcpx" });
        try info.object.put(self.allocator, "version", .{ .string = version });
        try params.object.put(self.allocator, "clientInfo", info);
        const initialized = try self.rpc("initialize", params);
        const negotiated = rpc_module.getString(initialized, "protocolVersion") orelse return error.InitializeMissingProtocolVersion;
        if (!std.mem.eql(u8, negotiated, protocol_version)) return error.UnsupportedProtocolVersion;
        self.negotiated_version = negotiated;
        const capabilities = rpc_module.get(initialized, "capabilities");
        self.supports_tools = if (capabilities) |c| rpc_module.get(c, "tools") != null else false;
        try self.notifyInitialized();
    }

    pub fn request(self: *McpClient, body: []const u8, notification: bool) !?Value {
        return self.requestExpected(body, notification, null, true, false);
    }

    pub fn requestExpected(self: *McpClient, body: []const u8, notification: bool, expected_id: ?i64, allow_session_recovery: bool, cancellable: bool) anyerror!?Value {
        const Result = union(enum) { response: anyerror!?Value, timeout: void };
        var completions: [2]Result = undefined;
        var select: Io.Select(Result) = .init(self.io, &completions);
        try select.concurrent(.response, requestInner, .{ self, body, notification, expected_id });
        try select.concurrent(.timeout, transport.waitForTimeout, .{ self.io, self.server.timeoutSecs() });
        const result = try select.await();
        select.cancelDiscard();
        return switch (result) {
            .response => |response| response catch |err| {
                if (err == error.SessionExpired and allow_session_recovery) {
                    self.session_id = null;
                    self.negotiated_version = protocol_version;
                    self.supports_tools = false;
                    try self.connect();
                    return self.requestExpected(body, notification, expected_id, false, cancellable);
                }
                return err;
            },
            .timeout => {
                std.debug.print("request to {s} timed out after {d} seconds\n", .{ self.server.endpoint, self.server.timeoutSecs() });
                if (cancellable) if (expected_id) |id| transport.notifyCancelled(self, id) catch {};
                return error.RequestTimedOut;
            },
        };
    }

    pub fn rpc(self: *McpClient, method: []const u8, params: ?Value) anyerror!Value {
        if ((std.mem.eql(u8, method, "tools/list") or std.mem.eql(u8, method, "tools/call")) and !self.supports_tools)
            return error.ServerDoesNotSupportTools;
        var request_value = Value{ .object = .empty };
        try request_value.object.put(self.allocator, "jsonrpc", .{ .string = "2.0" });
        const request_id: i64 = @intCast(self.next_id);
        try request_value.object.put(self.allocator, "id", .{ .integer = request_id });
        try request_value.object.put(self.allocator, "method", .{ .string = method });
        if (params) |p| try request_value.object.put(self.allocator, "params", p);
        self.next_id += 1;
        const body = try rpc_module.jsonString(self.allocator, request_value);
        return (try self.requestExpected(body, false, request_id, true, !std.mem.eql(u8, method, "initialize"))).?;
    }

    fn notifyInitialized(self: *McpClient) !void {
        var note = Value{ .object = .empty };
        try note.object.put(self.allocator, "jsonrpc", .{ .string = "2.0" });
        try note.object.put(self.allocator, "method", .{ .string = "notifications/initialized" });
        const body = try rpc_module.jsonString(self.allocator, note);
        _ = try self.request(body, true);
    }

    pub fn respondServerRequest(self: *McpClient, id: Value, method: []const u8) !void {
        if (std.mem.eql(u8, method, "ping"))
            return transport.respondPing(self, id);
        return transport.respondMethodNotFound(self, id);
    }

    pub fn listTools(self: *McpClient) ![]const Tool {
        if (!self.supports_tools) return error.ServerDoesNotSupportTools;
        var tools: std.ArrayList(Tool) = .empty;
        var seen_cursors: std.StringHashMapUnmanaged(void) = .empty;
        defer seen_cursors.deinit(self.allocator);
        var cursor: ?[]const u8 = null;
        while (true) {
            var params: ?Value = null;
            if (cursor) |c| {
                var object = Value{ .object = .empty };
                try object.object.put(self.allocator, "cursor", .{ .string = c });
                params = object;
            }
            const result = try self.rpc("tools/list", params);
            const list = rpc_module.get(result, "tools") orelse return error.ToolsListMissingTools;
            if (list != .array) return error.ToolsListMissingTools;
            for (list.array.items) |tool| try tools.append(self.allocator, .{ .value = tool });
            cursor = rpc_module.getString(result, "nextCursor");
            if (cursor == null or cursor.?.len == 0) break;
            const entry = try seen_cursors.getOrPut(self.allocator, cursor.?);
            if (entry.found_existing) return error.RepeatedPaginationCursor;
        }
        return tools.toOwnedSlice(self.allocator);
    }
};

fn requestInner(self: *McpClient, body: []const u8, notification: bool, expected_id: ?i64) anyerror!?Value {
    return transport.requestInner(self, body, notification, expected_id);
}
