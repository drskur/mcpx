const std = @import("std");

const Allocator = std.mem.Allocator;
const Io = std.Io;
const Value = std.json.Value;

const toml = @import("toml");
const rpc_module = @import("rpc.zig");
const transport = @import("transport.zig");
const oauth_module = @import("oauth.zig");

const version = "0.1.0";
const protocol_version = "2025-03-26";
const max_pagination_pages: usize = 1000;
const max_pagination_tools: usize = 100_000;

pub const Server = struct {
    name: []const u8,
    endpoint: []const u8,
    headers: ?toml.HashMap([]const u8) = null,
    timeout_secs: ?u64 = null,
    oauth: ?oauth_module.OauthConfig = null,

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
    token_path: []const u8,
    authorization_header: ?[]const u8 = null,
    oauth_recovery_in_progress: bool = false,

    /// `allocator` MUST be an arena or process-scoped allocator that outlives
    /// the client. Individual allocations are intentionally not freed.
    pub fn init(allocator: Allocator, io: Io, server: Server, token_path: []const u8) McpClient {
        return .{
            .allocator = allocator,
            .io = io,
            .http = .{ .allocator = allocator, .io = io },
            .server = server,
            .token_path = token_path,
        };
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
        const initialization = try validateInitialization(initialized);
        self.negotiated_version = initialization.negotiated_version;
        self.supports_tools = initialization.supports_tools;
        try self.notifyInitialized();
    }

    pub fn request(self: *McpClient, body: []const u8, notification: bool) !?Value {
        return self.requestExpected(body, notification, null, true, false);
    }

    pub fn requestExpected(self: *McpClient, body: []const u8, notification: bool, expected_id: ?i64, allow_session_recovery: bool, cancellable: bool) anyerror!?Value {
        return self.requestExpectedWithTimeout(body, notification, expected_id, allow_session_recovery, cancellable, false, self.server.timeoutSecs());
    }

    pub fn requestExpectedWithTimeout(
        self: *McpClient,
        body: []const u8,
        notification: bool,
        expected_id: ?i64,
        allow_session_recovery: bool,
        cancellable: bool,
        initialize_request: bool,
        timeout_secs: u64,
    ) anyerror!?Value {
        if (self.server.oauth) |oauth_config| if (self.authorization_header == null) {
            const token = try oauth_module.ensureToken(
                self.allocator,
                self.io,
                &self.http,
                self.server.name,
                self.server.endpoint,
                oauth_config,
                self.token_path,
            );
            try self.setAuthorization(token);
        };
        const Result = union(enum) { response: anyerror!?Value, timeout: void };
        var completions: [2]Result = undefined;
        var select: Io.Select(Result) = .init(self.io, &completions);
        try select.concurrent(.response, requestInner, .{ self, body, notification, expected_id, initialize_request });
        try select.concurrent(.timeout, transport.waitForTimeout, .{ self.io, timeout_secs });
        const result = try select.await();
        select.cancelDiscard();
        return switch (result) {
            .response => |response| response catch |err| {
                if (err == error.HttpUnauthorized and self.server.oauth != null and !self.oauth_recovery_in_progress) {
                    self.oauth_recovery_in_progress = true;
                    defer self.oauth_recovery_in_progress = false;
                    const token = try oauth_module.recoverUnauthorized(
                        self.allocator,
                        self.io,
                        &self.http,
                        self.server.name,
                        self.server.endpoint,
                        self.server.oauth.?,
                        self.token_path,
                    );
                    try self.setAuthorization(token);
                    return self.requestExpectedWithTimeout(body, notification, expected_id, allow_session_recovery, cancellable, initialize_request, timeout_secs);
                }
                if (err == error.SessionExpired and allow_session_recovery) {
                    self.session_id = null;
                    self.negotiated_version = protocol_version;
                    self.supports_tools = false;
                    try self.connect();
                    return self.requestExpectedWithTimeout(body, notification, expected_id, false, cancellable, initialize_request, timeout_secs);
                }
                return err;
            },
            .timeout => {
                std.debug.print("request to {s} timed out after {d} seconds\n", .{ self.server.endpoint, timeout_secs });
                if (cancellable) if (expected_id) |id| transport.notifyCancelled(self, id) catch |err|
                    std.debug.print("failed to send cancellation for request {d}: {s}\n", .{ id, @errorName(err) });
                return error.RequestTimedOut;
            },
        };
    }

    pub fn authenticate(self: *McpClient) !void {
        const config = self.server.oauth orelse return error.OauthNotConfigured;
        const token = try oauth_module.forceAuthenticate(
            self.allocator,
            self.io,
            &self.http,
            self.server.name,
            self.server.endpoint,
            config,
            self.token_path,
        );
        try self.setAuthorization(token);
    }

    fn setAuthorization(self: *McpClient, token: oauth_module.Token) !void {
        self.authorization_header = try std.fmt.allocPrint(self.allocator, "{s} {s}", .{ token.token_type, token.access_token });
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
        const initialize_request = std.mem.eql(u8, method, "initialize");
        return (try self.requestExpectedWithTimeout(
            body,
            false,
            request_id,
            true,
            !initialize_request,
            initialize_request,
            self.server.timeoutSecs(),
        )).?;
    }

    fn notifyInitialized(self: *McpClient) !void {
        var note = Value{ .object = .empty };
        try note.object.put(self.allocator, "jsonrpc", .{ .string = "2.0" });
        try note.object.put(self.allocator, "method", .{ .string = "notifications/initialized" });
        const body = try rpc_module.jsonString(self.allocator, note);
        _ = try self.requestExpected(body, true, null, false, false);
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
        var page_count: usize = 0;
        while (true) {
            try enforcePaginationLimits(page_count, tools.items.len, 0);
            page_count += 1;
            var params: ?Value = null;
            if (cursor) |c| {
                var object = Value{ .object = .empty };
                try object.object.put(self.allocator, "cursor", .{ .string = c });
                params = object;
            }
            const result = try self.rpc("tools/list", params);
            const list = rpc_module.get(result, "tools") orelse return error.ToolsListMissingTools;
            if (list != .array) return error.ToolsListMissingTools;
            try enforcePaginationLimits(page_count - 1, tools.items.len, list.array.items.len);
            for (list.array.items) |tool| try tools.append(self.allocator, .{ .value = tool });
            cursor = rpc_module.getString(result, "nextCursor");
            if (cursor == null or cursor.?.len == 0) break;
            const entry = try seen_cursors.getOrPut(self.allocator, cursor.?);
            if (entry.found_existing) return error.RepeatedPaginationCursor;
        }
        return tools.toOwnedSlice(self.allocator);
    }
};

const Initialization = struct {
    negotiated_version: []const u8,
    supports_tools: bool,
};

fn validateInitialization(initialized: Value) !Initialization {
    const negotiated = rpc_module.getString(initialized, "protocolVersion") orelse return error.InitializeMissingProtocolVersion;
    if (!std.mem.eql(u8, negotiated, protocol_version)) return error.UnsupportedProtocolVersion;
    const capabilities = rpc_module.get(initialized, "capabilities") orelse return error.InitializeMissingCapabilities;
    if (capabilities != .object) return error.InitializeCapabilitiesMustBeObject;
    const server_info = rpc_module.get(initialized, "serverInfo") orelse return error.InitializeMissingServerInfo;
    if (server_info != .object) return error.InitializeServerInfoMustBeObject;
    _ = rpc_module.getString(server_info, "name") orelse return error.InitializeServerInfoMissingName;
    _ = rpc_module.getString(server_info, "version") orelse return error.InitializeServerInfoMissingVersion;
    const tools = rpc_module.get(capabilities, "tools");
    if (tools) |value| if (value != .object) return error.InitializeToolsCapabilityMustBeObject;
    return .{ .negotiated_version = negotiated, .supports_tools = tools != null };
}

fn enforcePaginationLimits(page_count: usize, total_tools: usize, additional_tools: usize) !void {
    if (page_count >= max_pagination_pages) return error.PaginationLimitExceeded;
    if (additional_tools > max_pagination_tools -| total_tools) return error.PaginationLimitExceeded;
}

fn requestInner(self: *McpClient, body: []const u8, notification: bool, expected_id: ?i64, initialize_request: bool) anyerror!?Value {
    return transport.requestInner(self, body, notification, expected_id, initialize_request);
}

test "initialization requires serverInfo version" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const initialized = try std.json.parseFromSliceLeaky(Value, arena.allocator(), "{\"protocolVersion\":\"2025-03-26\",\"capabilities\":{},\"serverInfo\":{\"name\":\"server\"}}", .{});
    try std.testing.expectError(error.InitializeServerInfoMissingVersion, validateInitialization(initialized));
}

test "initialization requires tools capability to be an object" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const initialized = try std.json.parseFromSliceLeaky(Value, arena.allocator(), "{\"protocolVersion\":\"2025-03-26\",\"capabilities\":{\"tools\":\"yes\"},\"serverInfo\":{\"name\":\"server\",\"version\":\"1\"}}", .{});
    try std.testing.expectError(error.InitializeToolsCapabilityMustBeObject, validateInitialization(initialized));
}

test "pagination aggregate limits are enforced" {
    try std.testing.expectError(error.PaginationLimitExceeded, enforcePaginationLimits(max_pagination_pages, 0, 0));
    try std.testing.expectError(error.PaginationLimitExceeded, enforcePaginationLimits(1, max_pagination_tools, 1));
}
