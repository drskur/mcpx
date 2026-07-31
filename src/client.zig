const std = @import("std");

const Allocator = std.mem.Allocator;
const Io = std.Io;
const Value = std.json.Value;

const toml = @import("toml");
const rpc_module = @import("rpc.zig");
const transport = @import("transport.zig");
const oauth_module = @import("oauth.zig");
const protocol = @import("protocol.zig");
const build_info = @import("build_info");
const test_http = @import("test_http.zig");
const diagnostics_out = @import("diagnostics.zig");

const version = build_info.version;
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

    /// Rejects entries that would fail late, with a confusing error, or that
    /// would make every request time out immediately.
    pub fn validate(self: Server) !void {
        if (self.name.len == 0) return error.ServerNameEmpty;
        if (self.endpoint.len == 0) return error.ServerEndpointEmpty;
        if (self.timeout_secs) |secs| if (secs == 0) return error.ServerTimeoutZero;
        const uri = std.Uri.parse(self.endpoint) catch return error.ServerEndpointNotAbsoluteUri;
        if (!std.ascii.eqlIgnoreCase(uri.scheme, "http") and !std.ascii.eqlIgnoreCase(uri.scheme, "https"))
            return error.ServerEndpointSchemeUnsupported;
        if (uri.host == null) return error.ServerEndpointMissingHost;
        if (self.headers) |headers| {
            var it = headers.map.iterator();
            while (it.next()) |entry| {
                if (!isValidHeaderName(entry.key_ptr.*)) return error.ServerHeaderNameInvalid;
                if (!isValidHeaderValue(entry.value_ptr.*)) return error.ServerHeaderValueInvalid;
            }
        }
    }
};

/// RFC 9110 field name: a non-empty token. Anything else could smuggle a
/// request line or header break into the connection.
fn isValidHeaderName(name: []const u8) bool {
    if (name.len == 0) return false;
    for (name) |byte| switch (byte) {
        'a'...'z', 'A'...'Z', '0'...'9' => {},
        '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => {},
        else => return false,
    };
    return true;
}

fn isValidHeaderValue(value: []const u8) bool {
    for (value) |byte| if (byte < 0x20 or byte == 0x7f) return false;
    return true;
}

pub const Tool = struct {
    value: Value,

    pub fn name(self: Tool) ?[]const u8 {
        return rpc_module.getString(self.value, "name");
    }

    pub fn description(self: Tool) ?[]const u8 {
        return rpc_module.getString(self.value, "description");
    }
};

const HeaderMapping = struct {
    argument: []const u8,
    header: []const u8,
};

pub const ResultType = enum {
    complete,
    input_required,
};

pub const RpcOutcome = union(enum) {
    complete: Value,
    input_required: Value,
};

pub fn resultType(result: Value, supports_result_type: bool) !ResultType {
    if (!supports_result_type) return .complete;
    const raw = rpc_module.getString(result, "resultType") orelse return .complete;
    if (std.mem.eql(u8, raw, "complete")) return .complete;
    if (std.mem.eql(u8, raw, "input_required")) return .input_required;
    return error.UnsupportedResultType;
}

pub const McpClient = struct {
    allocator: Allocator,
    io: Io,
    http: std.http.Client,
    server: Server,
    session_id: ?[]const u8 = null,
    negotiated_version: []const u8 = protocol.latest_version,
    capabilities: protocol.Capabilities = protocol.capabilitiesFor(protocol.latest_version).?,
    server_supported_versions: ?[]const []const u8 = null,
    supports_tools: bool = false,
    next_id: u64 = 1,
    test_server_responses: ?*std.ArrayList([]u8) = null,
    token_path: []const u8,
    authorization_header: ?[]const u8 = null,
    oauth_recovery_in_progress: bool = false,
    oauth_challenge: ?oauth_module.OauthChallenge = null,
    tool_header_mappings: std.StringHashMapUnmanaged([]const HeaderMapping) = .empty,
    /// Populated by the transport whenever a JSON-RPC error response arrives.
    last_rpc_error: ?rpc_module.RpcError = null,

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
        self.tool_header_mappings.deinit(self.allocator);
        self.http.deinit();
    }

    pub fn connect(self: *McpClient) anyerror!void {
        self.negotiated_version = protocol.latest_version;
        self.capabilities = protocol.capabilitiesFor(protocol.latest_version).?;
        self.server_supported_versions = null;
        const discovered = self.rpcUnchecked("server/discover", null) catch |err| switch (err) {
            error.UnsupportedProtocolVersionError => blk: {
                const supported = self.server_supported_versions orelse
                    return error.UnsupportedProtocolVersion;
                const selected = protocol.bestMutualVersion(supported) orelse
                    return error.UnsupportedProtocolVersion;
                self.negotiated_version = selected.name;
                self.capabilities = selected.capabilities;
                if (!selected.capabilities.needs_discover) {
                    try self.connectInitialized(selected.name);
                    return;
                }
                break :blk try self.rpcUnchecked("server/discover", null);
            },
            // A 2025-03-26 server does not implement server/discover.
            error.MethodNotFound, error.LegacyProbeRejected => {
                try self.connectInitialized(protocol.legacy_version);
                return;
            },
            else => return err,
        };
        try self.applyDiscovery(discovered);
    }

    fn connectInitialized(self: *McpClient, proposed_version: []const u8) !void {
        self.negotiated_version = proposed_version;
        self.capabilities = protocol.capabilitiesFor(proposed_version) orelse
            return error.UnsupportedProtocolVersion;
        var params = Value{ .object = .empty };
        try params.object.put(self.allocator, "protocolVersion", .{ .string = proposed_version });
        try params.object.put(self.allocator, "capabilities", .{ .object = .empty });
        var info = Value{ .object = .empty };
        try info.object.put(self.allocator, "name", .{ .string = "mcpx" });
        try info.object.put(self.allocator, "version", .{ .string = version });
        try params.object.put(self.allocator, "clientInfo", info);
        const initialized = try self.rpc("initialize", params);
        const initialization = try validateInitialization(initialized);
        self.negotiated_version = initialization.negotiated_version;
        self.capabilities = protocol.capabilitiesFor(initialization.negotiated_version) orelse
            return error.UnsupportedProtocolVersion;
        self.supports_tools = initialization.supports_tools;
        try self.notifyInitialized();
    }

    fn applyDiscovery(self: *McpClient, discovered: Value) !void {
        const negotiated = rpc_module.getString(discovered, "protocolVersion") orelse self.negotiated_version;
        const caps = protocol.capabilitiesFor(negotiated) orelse return error.UnsupportedProtocolVersion;
        const server_caps = rpc_module.get(discovered, "capabilities") orelse return error.DiscoverMissingCapabilities;
        if (server_caps != .object) return error.DiscoverCapabilitiesMustBeObject;
        self.negotiated_version = negotiated;
        self.capabilities = caps;
        const tools = rpc_module.get(server_caps, "tools");
        if (tools) |value| if (value != .object) return error.DiscoverToolsCapabilityMustBeObject;
        self.supports_tools = tools != null;
    }

    pub fn requestExpected(self: *McpClient, body: []const u8, notification: bool, expected_id: ?i64, allow_session_recovery: bool, cancellable: bool, context: transport.RequestContext) anyerror!?Value {
        return self.requestExpectedWithTimeout(body, notification, expected_id, allow_session_recovery, cancellable, context, self.server.timeoutSecs());
    }

    pub fn requestExpectedWithTimeout(
        self: *McpClient,
        body: []const u8,
        notification: bool,
        expected_id: ?i64,
        allow_session_recovery: bool,
        cancellable: bool,
        context: transport.RequestContext,
        timeout_secs: u64,
    ) anyerror!?Value {
        if (self.server.oauth) |oauth_config| if (self.authorization_header == null) {
            const token = try oauth_module.ensureToken(
                self.allocator,
                self.io,
                &self.http,
                self.server.endpoint,
                oauth_config,
                self.token_path,
            );
            try self.setAuthorization(token);
        };
        const Result = union(enum) { response: anyerror!?Value, timeout: void };
        var completions: [2]Result = undefined;
        var select: Io.Select(Result) = .init(self.io, &completions);
        try select.concurrent(.response, requestInner, .{ self, body, notification, expected_id, context });
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
                        self.server.endpoint,
                        self.server.oauth.?,
                        self.token_path,
                        self.oauth_challenge,
                    );
                    try self.setAuthorization(token);
                    return self.requestExpectedWithTimeout(body, notification, expected_id, allow_session_recovery, cancellable, context, timeout_secs);
                }
                if (err == error.SessionExpired and self.capabilities.has_sessions and allow_session_recovery) {
                    self.session_id = null;
                    self.supports_tools = false;
                    try self.connect();
                    return self.requestExpectedWithTimeout(body, notification, expected_id, false, cancellable, context, timeout_secs);
                }
                return err;
            },
            .timeout => {
                diagnostics_out.report("request to {s} timed out after {d} seconds\n", .{ self.server.endpoint, timeout_secs });
                if (cancellable and self.capabilities.has_cancel_notification) if (expected_id) |id| transport.notifyCancelled(self, id) catch |err|
                    diagnostics_out.warn("failed to send cancellation for request {d}: {s}\n", .{ id, @errorName(err) });
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
            self.server.endpoint,
            config,
            self.token_path,
        );
        try self.setAuthorization(token);
    }

    fn setAuthorization(self: *McpClient, token: oauth_module.Token) !void {
        try @import("oauth/token_store.zig").validateToken(token);
        self.authorization_header = try std.fmt.allocPrint(self.allocator, "{s} {s}", .{ token.token_type, token.access_token });
    }

    pub fn rpc(self: *McpClient, method: []const u8, params: ?Value) anyerror!Value {
        return switch (try self.rpcOutcome(method, params)) {
            .complete => |result| result,
            .input_required => error.InputRequired,
        };
    }

    pub fn rpcOutcome(self: *McpClient, method: []const u8, params: ?Value) anyerror!RpcOutcome {
        if ((std.mem.eql(u8, method, "tools/list") or std.mem.eql(u8, method, "tools/call")) and !self.supports_tools)
            return error.ServerDoesNotSupportTools;
        const result = try self.rpcUnchecked(method, params);
        return outcomeFor(result, self.capabilities.supports_result_type);
    }

    fn rpcUnchecked(self: *McpClient, method: []const u8, params: ?Value) anyerror!Value {
        const request_params = try self.prepareParams(params);
        var request_value = Value{ .object = .empty };
        try request_value.object.put(self.allocator, "jsonrpc", .{ .string = "2.0" });
        const request_id: i64 = @intCast(self.next_id);
        try request_value.object.put(self.allocator, "id", .{ .integer = request_id });
        try request_value.object.put(self.allocator, "method", .{ .string = method });
        if (request_params) |p| try request_value.object.put(self.allocator, "params", p);
        self.next_id += 1;
        const body = try rpc_module.jsonString(self.allocator, request_value);
        const initialize_request = std.mem.eql(u8, method, "initialize");
        const discovery_request = std.mem.eql(u8, method, "server/discover");
        const name = requestName(request_params);
        const param_headers = try self.paramHeaders(method, request_params);
        self.last_rpc_error = null;
        const result = (try self.requestExpectedWithTimeout(
            body,
            false,
            request_id,
            true,
            !initialize_request,
            .{
                .method = method,
                .name = name,
                .param_headers = param_headers,
                .initialize = initialize_request,
                .probe = discovery_request,
            },
            self.server.timeoutSecs(),
        )).?;
        return result;
    }

    fn paramHeaders(self: *McpClient, method: []const u8, params: ?Value) ![]const transport.RequestContext.ParamHeader {
        if (!self.capabilities.has_mcp_name_header or !std.mem.eql(u8, method, "tools/call")) return &.{};
        const p = params orelse return &.{};
        const tool_name = rpc_module.getString(p, "name") orelse return &.{};
        const mappings = self.tool_header_mappings.get(tool_name) orelse return &.{};
        const arguments = rpc_module.get(p, "arguments") orelse return &.{};
        if (arguments != .object) return &.{};
        var headers: std.ArrayList(transport.RequestContext.ParamHeader) = .empty;
        for (mappings) |mapping| {
            const value = arguments.object.get(mapping.argument) orelse continue;
            const text: []const u8 = switch (value) {
                .string => |string| string,
                .integer => |integer| try std.fmt.allocPrint(self.allocator, "{d}", .{integer}),
                .float => |float| try std.fmt.allocPrint(self.allocator, "{d}", .{float}),
                .bool => |boolean| if (boolean) "true" else "false",
                else => continue,
            };
            try headers.append(self.allocator, .{ .name = mapping.header, .value = text });
        }
        return headers.toOwnedSlice(self.allocator);
    }

    fn prepareParams(self: *McpClient, supplied: ?Value) !?Value {
        if (!self.capabilities.needs_meta) return supplied;
        var params = supplied orelse Value{ .object = .empty };
        if (params != .object) return error.ModernParamsMustBeObject;
        var meta = rpc_module.get(params, "_meta") orelse Value{ .object = .empty };
        if (meta != .object) return error.ModernMetaMustBeObject;
        try meta.object.put(self.allocator, "io.modelcontextprotocol/protocolVersion", .{ .string = self.negotiated_version });
        try meta.object.put(self.allocator, "io.modelcontextprotocol/clientCapabilities", .{ .object = .empty });
        var info = Value{ .object = .empty };
        try info.object.put(self.allocator, "name", .{ .string = "mcpx" });
        try info.object.put(self.allocator, "version", .{ .string = version });
        try meta.object.put(self.allocator, "io.modelcontextprotocol/clientInfo", info);
        try params.object.put(self.allocator, "_meta", meta);
        return params;
    }

    fn notifyInitialized(self: *McpClient) !void {
        var note = Value{ .object = .empty };
        try note.object.put(self.allocator, "jsonrpc", .{ .string = "2.0" });
        try note.object.put(self.allocator, "method", .{ .string = "notifications/initialized" });
        const body = try rpc_module.jsonString(self.allocator, note);
        _ = try self.requestExpected(body, true, null, false, false, .{ .method = "notifications/initialized" });
    }

    pub fn respondServerRequest(self: *McpClient, id: Value, method: []const u8) !void {
        if (std.mem.eql(u8, method, "ping"))
            return transport.respondPing(self, id);
        return transport.respondMethodNotFound(self, id);
    }

    pub fn allowsServerRequests(self: *McpClient) bool {
        return self.capabilities.allows_server_requests;
    }

    pub fn listTools(self: *McpClient) ![]const Tool {
        if (!self.supports_tools) return error.ServerDoesNotSupportTools;
        self.tool_header_mappings.clearRetainingCapacity();
        var tools: std.ArrayList(Tool) = .empty;
        var seen_cursors: std.StringHashMapUnmanaged(void) = .empty;
        defer seen_cursors.deinit(self.allocator);
        var cursor: ?[]const u8 = null;
        var page_count: usize = 0;
        while (true) {
            try enforcePageLimit(page_count);
            page_count += 1;
            var params: ?Value = null;
            if (cursor) |c| {
                var object = Value{ .object = .empty };
                try object.object.put(self.allocator, "cursor", .{ .string = c });
                params = object;
            }
            const result = switch (try self.rpcOutcome("tools/list", params)) {
                .complete => |complete| complete,
                .input_required => return error.InputRequired,
            };
            const list = rpc_module.get(result, "tools") orelse return error.ToolsListMissingTools;
            if (list != .array) return error.ToolsListMissingTools;
            try enforceToolLimit(tools.items.len, list.array.items.len);
            for (list.array.items) |tool| {
                // A tool without a name cannot be listed, documented or
                // called, so it is rejected here instead of failing later.
                const tool_name = rpc_module.getString(tool, "name") orelse {
                    diagnostics_out.warn("skipping tool without a name\n", .{});
                    continue;
                };
                const mappings = validateHeaderMappings(self.allocator, tool) catch |err| {
                    diagnostics_out.warn("rejecting tool '{s}': {s}\n", .{ tool_name, @errorName(err) });
                    continue;
                };
                if (self.tool_header_mappings.contains(tool_name)) {
                    diagnostics_out.warn("skipping duplicate tool '{s}'\n", .{tool_name});
                    continue;
                }
                try self.tool_header_mappings.put(self.allocator, tool_name, mappings);
                try tools.append(self.allocator, .{ .value = tool });
            }
            cursor = rpc_module.getString(result, "nextCursor");
            if (cursor == null or cursor.?.len == 0) break;
            const entry = try seen_cursors.getOrPut(self.allocator, cursor.?);
            if (entry.found_existing) return error.RepeatedPaginationCursor;
        }
        return tools.toOwnedSlice(self.allocator);
    }
};

fn outcomeFor(result: Value, supports_result_type: bool) !RpcOutcome {
    return switch (try resultType(result, supports_result_type)) {
        .complete => .{ .complete = result },
        .input_required => .{ .input_required = result },
    };
}

fn validateHeaderMappings(allocator: Allocator, tool: Value) ![]const HeaderMapping {
    const schema = rpc_module.get(tool, "inputSchema") orelse return &.{};
    if (schema != .object) return &.{};
    const properties = rpc_module.get(schema, "properties") orelse return &.{};
    if (properties != .object) return &.{};
    var mappings: std.ArrayList(HeaderMapping) = .empty;
    var property_iterator = properties.object.iterator();
    while (property_iterator.next()) |entry| {
        const property = entry.value_ptr.*;
        const annotation_value = rpc_module.get(property, "x-mcp-header") orelse continue;
        if (annotation_value != .string) return error.InvalidMcpHeaderAnnotation;
        const header = annotation_value.string;
        if (header.len == 0) return error.InvalidMcpHeaderAnnotation;
        for (header) |byte| if (byte < 0x21 or byte > 0x7e or byte == ':')
            return error.InvalidMcpHeaderAnnotation;
        const property_type = rpc_module.getString(property, "type") orelse return error.InvalidMcpHeaderAnnotation;
        if (!std.mem.eql(u8, property_type, "string") and
            !std.mem.eql(u8, property_type, "number") and
            !std.mem.eql(u8, property_type, "integer") and
            !std.mem.eql(u8, property_type, "boolean"))
            return error.InvalidMcpHeaderAnnotation;
        for (mappings.items) |mapping| if (std.ascii.eqlIgnoreCase(mapping.header, header))
            return error.InvalidMcpHeaderAnnotation;
        try mappings.append(allocator, .{ .argument = entry.key_ptr.*, .header = header });
    }
    return mappings.toOwnedSlice(allocator);
}

const Initialization = struct {
    negotiated_version: []const u8,
    supports_tools: bool,
};

fn validateInitialization(initialized: Value) !Initialization {
    const negotiated = rpc_module.getString(initialized, "protocolVersion") orelse return error.InitializeMissingProtocolVersion;
    if (protocol.capabilitiesFor(negotiated) == null) return error.UnsupportedProtocolVersion;
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

fn enforcePageLimit(page_count: usize) !void {
    if (page_count >= max_pagination_pages) return error.PaginationLimitExceeded;
}

fn enforceToolLimit(total_tools: usize, additional_tools: usize) !void {
    if (additional_tools > max_pagination_tools -| total_tools) return error.PaginationLimitExceeded;
}

fn requestInner(self: *McpClient, body: []const u8, notification: bool, expected_id: ?i64, context: transport.RequestContext) anyerror!?Value {
    return transport.requestInner(self, body, notification, expected_id, context);
}

fn requestName(params: ?Value) ?[]const u8 {
    const value = params orelse return null;
    return rpc_module.getString(value, "name") orelse rpc_module.getString(value, "uri");
}

fn expectConnectHttpFailure(status: []const u8, body: []const u8, expected: anyerror) !void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const io = std.testing.io;
    const address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var server = try address.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    const endpoint = try std.fmt.allocPrint(
        arena.allocator(),
        "http://127.0.0.1:{d}/mcp",
        .{server.socket.address.getPort()},
    );
    var script = test_http.Script{ .responses = &.{
        .{ .status = status, .body = body },
    } };
    var serving = try io.concurrent(test_http.Script.serve, .{ &script, io, &server });
    var client = McpClient.init(arena.allocator(), io, .{ .name = "test", .endpoint = endpoint }, "unused");
    defer client.deinit();

    try std.testing.expectError(expected, client.connect());
    try serving.await(io);
    try std.testing.expect(std.ascii.indexOfIgnoreCase(script.request(0), "MCP-Protocol-Version: 2026-07-28") != null);
    try std.testing.expectEqual(@as(usize, 0), script.request_lengths[1]);
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
    try enforcePageLimit(max_pagination_pages - 1);
    try std.testing.expectError(error.PaginationLimitExceeded, enforcePageLimit(max_pagination_pages));
    try enforceToolLimit(max_pagination_tools - 1, 1);
    try std.testing.expectError(error.PaginationLimitExceeded, enforceToolLimit(max_pagination_tools, 1));
}

test "modern params receive protocol client metadata" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var client = McpClient.init(arena.allocator(), std.testing.io, .{
        .name = "test",
        .endpoint = "https://example.test/mcp",
    }, "unused");
    defer client.deinit();
    const params = (try client.prepareParams(null)).?;
    const meta = rpc_module.get(params, "_meta").?;
    try std.testing.expectEqualStrings("2026-07-28", rpc_module.getString(meta, "io.modelcontextprotocol/protocolVersion").?);
    try std.testing.expect(rpc_module.get(meta, "io.modelcontextprotocol/clientCapabilities").? == .object);
    const info = rpc_module.get(meta, "io.modelcontextprotocol/clientInfo").?;
    try std.testing.expectEqualStrings("mcpx", rpc_module.getString(info, "name").?);
}

test "resultType supports complete input-required and legacy omission" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const complete = try std.json.parseFromSliceLeaky(Value, arena.allocator(), "{\"resultType\":\"complete\"}", .{});
    const pending = try std.json.parseFromSliceLeaky(Value, arena.allocator(), "{\"resultType\":\"input_required\"}", .{});
    const missing = try std.json.parseFromSliceLeaky(Value, arena.allocator(), "{}", .{});
    try std.testing.expectEqual(ResultType.complete, try resultType(complete, true));
    try std.testing.expectEqual(ResultType.input_required, try resultType(pending, true));
    try std.testing.expectEqual(ResultType.complete, try resultType(missing, false));
}

test "tools call input-required is surfaced as a distinct intact outcome" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const pending = try std.json.parseFromSliceLeaky(Value, arena.allocator(),
        \\{"resultType":"input_required","inputRequests":{"confirm":{"type":"elicitation"}},"requestState":"opaque"}
    , .{});
    const outcome = try outcomeFor(pending, true);
    try std.testing.expect(outcome == .input_required);
    try std.testing.expectEqualStrings("opaque", rpc_module.getString(outcome.input_required, "requestState").?);
    try std.testing.expect(rpc_module.get(outcome.input_required, "inputRequests").? == .object);
}

test "tools list input-required does not enter final tools parsing" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const pending = try std.json.parseFromSliceLeaky(Value, arena.allocator(),
        \\{"resultType":"input_required","inputRequests":{},"requestState":"list-state"}
    , .{});
    const outcome = try outcomeFor(pending, true);
    try std.testing.expect(outcome == .input_required);
    try std.testing.expect(rpc_module.get(outcome.input_required, "tools") == null);
}

test "tool header annotations are validated and primitive arguments are mirrored" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const tool = try std.json.parseFromSliceLeaky(Value, allocator,
        \\{"name":"search","inputSchema":{"type":"object","properties":{
        \\  "tenant":{"type":"string","x-mcp-header":"Tenant"},
        \\  "limit":{"type":"integer","x-mcp-header":"Limit"},
        \\  "debug":{"type":"boolean","x-mcp-header":"Debug"}
        \\}}}
    , .{});
    const mappings = try validateHeaderMappings(allocator, tool);
    try std.testing.expectEqual(@as(usize, 3), mappings.len);

    var client = McpClient.init(allocator, std.testing.io, .{
        .name = "test",
        .endpoint = "https://example.test/mcp",
    }, "unused");
    defer client.deinit();
    try client.tool_header_mappings.put(allocator, "search", mappings);
    const params = try std.json.parseFromSliceLeaky(Value, allocator,
        \\{"name":"search","arguments":{"tenant":"acme","limit":7,"debug":true}}
    , .{});
    const headers = try client.paramHeaders("tools/call", params);
    try std.testing.expectEqual(@as(usize, 3), headers.len);
    try std.testing.expectEqualStrings("Tenant", headers[0].name);
    try std.testing.expectEqualStrings("acme", headers[0].value);
    try std.testing.expectEqualStrings("7", headers[1].value);
    try std.testing.expectEqualStrings("true", headers[2].value);
}

test "invalid and non-primitive tool header annotations are rejected" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const invalid_name = try std.json.parseFromSliceLeaky(Value, allocator,
        \\{"inputSchema":{"properties":{"value":{"type":"string","x-mcp-header":"bad name"}}}}
    , .{});
    try std.testing.expectError(error.InvalidMcpHeaderAnnotation, validateHeaderMappings(allocator, invalid_name));
    const duplicate = try std.json.parseFromSliceLeaky(Value, allocator,
        \\{"inputSchema":{"properties":{
        \\  "one":{"type":"string","x-mcp-header":"Tenant"},
        \\  "two":{"type":"number","x-mcp-header":"tenant"}
        \\}}}
    , .{});
    try std.testing.expectError(error.InvalidMcpHeaderAnnotation, validateHeaderMappings(allocator, duplicate));
    const object = try std.json.parseFromSliceLeaky(Value, allocator,
        \\{"inputSchema":{"properties":{"value":{"type":"object","x-mcp-header":"Value"}}}}
    , .{});
    try std.testing.expectError(error.InvalidMcpHeaderAnnotation, validateHeaderMappings(allocator, object));
}

test "non-primitive tool call argument is not emitted as a header" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var client = McpClient.init(allocator, std.testing.io, .{
        .name = "test",
        .endpoint = "https://example.test/mcp",
    }, "unused");
    defer client.deinit();
    try client.tool_header_mappings.put(allocator, "search", try allocator.dupe(HeaderMapping, &.{
        .{ .argument = "tenant", .header = "Tenant" },
    }));
    const params = try std.json.parseFromSliceLeaky(Value, allocator,
        \\{"name":"search","arguments":{"tenant":{"nested":true}}}
    , .{});
    try std.testing.expectEqual(@as(usize, 0), (try client.paramHeaders("tools/call", params)).len);
}

test "connect does not downgrade after HTTP 500" {
    try expectConnectHttpFailure(
        "500 Internal Server Error",
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32601,\"message\":\"Method not found\"}}",
        error.HttpServerError,
    );
}

test "connect does not downgrade after HTTP 429" {
    try expectConnectHttpFailure(
        "429 Too Many Requests",
        "{\"error\":\"rate_limited\"}",
        error.HttpRateLimited,
    );
}

test "connect does not downgrade after HTTP 403" {
    try expectConnectHttpFailure(
        "403 Forbidden",
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32601,\"message\":\"Method not found\"}}",
        error.HttpForbidden,
    );
}

test "connect negotiates recognized HTTP 400 unsupported-version response" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const io = std.testing.io;
    const address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var server = try address.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    const endpoint = try std.fmt.allocPrint(
        arena.allocator(),
        "http://127.0.0.1:{d}/mcp",
        .{server.socket.address.getPort()},
    );
    var script = test_http.Script{ .responses = &.{
        .{
            .status = "400 Bad Request",
            .body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32022,\"message\":\"unsupported\",\"data\":{\"supported\":[\"2025-03-26\",\"2026-07-28\"]}}}",
        },
        .{
            .status = "200 OK",
            .body = "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"protocolVersion\":\"2026-07-28\",\"capabilities\":{\"tools\":{}}}}",
        },
    } };
    var serving = try io.concurrent(test_http.Script.serve, .{ &script, io, &server });
    var client = McpClient.init(arena.allocator(), io, .{ .name = "test", .endpoint = endpoint }, "unused");
    defer client.deinit();

    try client.connect();
    try serving.await(io);
    try std.testing.expectEqualStrings("2026-07-28", client.negotiated_version);
    try std.testing.expect(client.supports_tools);
    try std.testing.expect(std.ascii.indexOfIgnoreCase(script.request(1), "Mcp-Method: server/discover") != null);
}

test "negotiated legacy session is sent after initialize" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const io = std.testing.io;
    const address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var server = try address.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    const endpoint = try std.fmt.allocPrint(
        arena.allocator(),
        "http://127.0.0.1:{d}/mcp",
        .{server.socket.address.getPort()},
    );
    var script = test_http.Script{ .responses = &.{
        .{
            .status = "400 Bad Request",
            .body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32022,\"message\":\"unsupported\",\"data\":{\"supported\":[\"2025-06-18\"]}}}",
        },
        .{
            .status = "200 OK",
            .extra_headers = "Mcp-Session-Id: legacy-session\r\n",
            .body = "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{\"tools\":{}},\"serverInfo\":{\"name\":\"legacy\",\"version\":\"1\"}}}",
        },
        .{ .status = "202 Accepted", .body = "" },
    } };
    var serving = try io.concurrent(test_http.Script.serve, .{ &script, io, &server });
    var client = McpClient.init(arena.allocator(), io, .{ .name = "test", .endpoint = endpoint }, "unused");
    defer client.deinit();

    try client.connect();
    try serving.await(io);
    try std.testing.expectEqualStrings("2025-06-18", client.negotiated_version);
    try std.testing.expectEqualStrings("legacy-session", client.session_id.?);
    try std.testing.expect(std.ascii.indexOfIgnoreCase(script.request(1), "Mcp-Session-Id") == null);
    try std.testing.expect(std.ascii.indexOfIgnoreCase(script.request(2), "Mcp-Session-Id: legacy-session") != null);
}

test "legacy discover rejection initializes and supports a search call" {
    for ([_][]const u8{ "404 Not Found", "405 Method Not Allowed" }) |probe_status| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const io = std.testing.io;
        const address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
        var server = try address.listen(io, .{ .reuse_address = true });
        defer server.deinit(io);
        const endpoint = try std.fmt.allocPrint(arena.allocator(), "http://127.0.0.1:{d}/mcp", .{server.socket.address.getPort()});
        var script = test_http.Script{ .responses = &.{
            .{ .status = probe_status, .body = "{\"error\":\"not_found\"}" },
            .{
                .status = "200 OK",
                .extra_headers = "Mcp-Session-Id: search-session\r\n",
                .body = "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"protocolVersion\":\"2025-03-26\",\"capabilities\":{\"tools\":{}},\"serverInfo\":{\"name\":\"search\",\"version\":\"1\"}}}",
            },
            .{ .status = "202 Accepted", .body = "" },
            .{ .status = "200 OK", .body = "{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"content\":[]}}" },
        } };
        var serving = try io.concurrent(test_http.Script.serve, .{ &script, io, &server });
        var client = McpClient.init(arena.allocator(), io, .{ .name = "test", .endpoint = endpoint }, "unused");
        defer client.deinit();

        try client.connect();
        var params = Value{ .object = .empty };
        try params.object.put(arena.allocator(), "name", .{ .string = "search" });
        try params.object.put(arena.allocator(), "arguments", .{ .object = .empty });
        const result = try client.rpc("tools/call", params);
        try serving.await(io);

        try std.testing.expectEqualStrings("2025-03-26", client.negotiated_version);
        try std.testing.expect(rpc_module.get(result, "content").? == .array);
        try std.testing.expect(std.ascii.indexOfIgnoreCase(script.request(3), "Mcp-Session-Id: search-session") != null);
    }
}

test "session-expiring 404 reconnects and retries the request" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const io = std.testing.io;
    const address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var server = try address.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    const endpoint = try std.fmt.allocPrint(arena.allocator(), "http://127.0.0.1:{d}/mcp", .{server.socket.address.getPort()});
    const initialized =
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"protocolVersion\":\"2025-03-26\",\"capabilities\":{\"tools\":{}},\"serverInfo\":{\"name\":\"legacy\",\"version\":\"1\"}}}";
    var script = test_http.Script{ .responses = &.{
        .{ .status = "404 Not Found", .body = "" },
        .{ .status = "200 OK", .extra_headers = "Mcp-Session-Id: old-session\r\n", .body = initialized },
        .{ .status = "202 Accepted", .body = "" },
        .{ .status = "404 Not Found", .body = "{\"error\":\"session_expired\"}" },
        .{ .status = "404 Not Found", .body = "" },
        .{
            .status = "200 OK",
            .extra_headers = "Mcp-Session-Id: new-session\r\n",
            .body = "{\"jsonrpc\":\"2.0\",\"id\":5,\"result\":{\"protocolVersion\":\"2025-03-26\",\"capabilities\":{\"tools\":{}},\"serverInfo\":{\"name\":\"legacy\",\"version\":\"1\"}}}",
        },
        .{ .status = "202 Accepted", .body = "" },
        .{ .status = "200 OK", .body = "{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"tools\":[]}}" },
    } };
    var serving = try io.concurrent(test_http.Script.serve, .{ &script, io, &server });
    var client = McpClient.init(arena.allocator(), io, .{ .name = "test", .endpoint = endpoint }, "unused");
    defer client.deinit();

    try client.connect();
    const tools = try client.listTools();
    try serving.await(io);

    try std.testing.expectEqual(@as(usize, 0), tools.len);
    try std.testing.expectEqualStrings("new-session", client.session_id.?);
    try std.testing.expect(std.ascii.indexOfIgnoreCase(script.request(3), "Mcp-Session-Id: old-session") != null);
    try std.testing.expect(std.ascii.indexOfIgnoreCase(script.request(4), "Mcp-Session-Id") == null);
    try std.testing.expect(std.ascii.indexOfIgnoreCase(script.request(7), "Mcp-Session-Id: new-session") != null);
}

test "server entries are validated before any request is made" {
    const base: Server = .{ .name = "demo", .endpoint = "https://mcp.example/mcp" };
    try base.validate();
    try (Server{ .name = "demo", .endpoint = "http://127.0.0.1:3000/mcp", .timeout_secs = 1 }).validate();
    try std.testing.expectError(error.ServerNameEmpty, (Server{ .name = "", .endpoint = "https://a.example/mcp" }).validate());
    try std.testing.expectError(error.ServerEndpointEmpty, (Server{ .name = "demo", .endpoint = "" }).validate());
    try std.testing.expectError(error.ServerTimeoutZero, (Server{ .name = "demo", .endpoint = "https://a.example/mcp", .timeout_secs = 0 }).validate());
    try std.testing.expectError(error.ServerEndpointNotAbsoluteUri, (Server{ .name = "demo", .endpoint = "mcp.example/mcp" }).validate());
    try std.testing.expectError(error.ServerEndpointSchemeUnsupported, (Server{ .name = "demo", .endpoint = "ftp://mcp.example/mcp" }).validate());
}

test "configured header names and values reject request smuggling" {
    try std.testing.expect(isValidHeaderName("X-Custom_1"));
    try std.testing.expect(!isValidHeaderName(""));
    try std.testing.expect(!isValidHeaderName("X Custom"));
    try std.testing.expect(!isValidHeaderName("X-Custom:"));
    try std.testing.expect(!isValidHeaderName("X\r\nInjected"));
    try std.testing.expect(isValidHeaderValue("plain value"));
    try std.testing.expect(!isValidHeaderValue("value\r\nX-Injected: 1"));
    try std.testing.expect(!isValidHeaderValue("tab\tvalue"));
}

fn discoverAndListScript(comptime tools_body: []const u8) [2]test_http.Response {
    return .{
        .{
            .status = "200 OK",
            .body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2026-07-28\",\"capabilities\":{\"tools\":{}}}}",
        },
        .{ .status = "200 OK", .body = tools_body },
    };
}

test "a keep-alive connection serves discovery and tool listing" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const io = std.testing.io;
    var server = try test_http.listenLoopback(io);
    defer server.deinit(io);
    const endpoint = try test_http.endpointFor(arena.allocator(), &server);
    const responses = discoverAndListScript(
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[{\"name\":\"search\",\"description\":\"find\"}]}}",
    );
    var script = test_http.Script{ .responses = &responses, .keep_alive = true };
    var serving = try io.concurrent(test_http.Script.serve, .{ &script, io, &server });
    var client = McpClient.init(arena.allocator(), io, .{ .name = "test", .endpoint = endpoint }, "unused");
    defer client.deinit();

    try client.connect();
    const tools = try client.listTools();
    try serving.await(io);

    try std.testing.expectEqual(@as(usize, 1), tools.len);
    try std.testing.expectEqualStrings("search", tools[0].name().?);
}

test "an SSE response is parsed through the real transport" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const io = std.testing.io;
    var server = try test_http.listenLoopback(io);
    defer server.deinit(io);
    const endpoint = try test_http.endpointFor(arena.allocator(), &server);
    var script = test_http.Script{ .responses = &.{
        .{
            .status = "200 OK",
            .body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2026-07-28\",\"capabilities\":{\"tools\":{}}}}",
        },
        .{
            .status = "200 OK",
            .content_type = "text/event-stream; charset=utf-8",
            .body = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"notifications/progress\"}\n\n" ++
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"ok\"}]}}\n\n",
        },
    } };
    var serving = try io.concurrent(test_http.Script.serve, .{ &script, io, &server });
    var client = McpClient.init(arena.allocator(), io, .{ .name = "test", .endpoint = endpoint }, "unused");
    defer client.deinit();

    try client.connect();
    var params = Value{ .object = .empty };
    try params.object.put(arena.allocator(), "name", .{ .string = "search" });
    try params.object.put(arena.allocator(), "arguments", .{ .object = .empty });
    const result = try client.rpc("tools/call", params);
    try serving.await(io);

    const content = rpc_module.get(result, "content").?;
    try std.testing.expectEqualStrings("ok", rpc_module.getString(content.array.items[0], "text").?);
}

test "tool parameter headers reach the wire for annotated arguments" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const io = std.testing.io;
    var server = try test_http.listenLoopback(io);
    defer server.deinit(io);
    const endpoint = try test_http.endpointFor(arena.allocator(), &server);
    var script = test_http.Script{ .responses = &.{
        .{
            .status = "200 OK",
            .body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2026-07-28\",\"capabilities\":{\"tools\":{}}}}",
        },
        .{
            .status = "200 OK",
            .body =
            \\{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"search","inputSchema":{"type":"object","properties":{"tenant":{"type":"string","x-mcp-header":"Tenant"}}}}]}}
            ,
        },
        .{ .status = "200 OK", .body = "{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"content\":[]}}" },
    } };
    var serving = try io.concurrent(test_http.Script.serve, .{ &script, io, &server });
    var client = McpClient.init(arena.allocator(), io, .{ .name = "test", .endpoint = endpoint }, "unused");
    defer client.deinit();

    try client.connect();
    _ = try client.listTools();
    var params = Value{ .object = .empty };
    try params.object.put(arena.allocator(), "name", .{ .string = "search" });
    var call_args = Value{ .object = .empty };
    try call_args.object.put(arena.allocator(), "tenant", .{ .string = "acme" });
    try params.object.put(arena.allocator(), "arguments", call_args);
    _ = try client.rpc("tools/call", params);
    try serving.await(io);

    const call_request = script.request(2);
    try std.testing.expect(std.ascii.indexOfIgnoreCase(call_request, "Mcp-Param-Tenant: acme") != null);
    try std.testing.expect(std.ascii.indexOfIgnoreCase(call_request, "Mcp-Name: search") != null);
}

test "a stalled server hits the configured timeout" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const io = std.testing.io;
    var server = try test_http.listenLoopback(io);
    defer server.deinit(io);
    const endpoint = try test_http.endpointFor(arena.allocator(), &server);
    var serving = try io.concurrent(test_http.serveStalled, .{ io, &server });
    defer serving.cancel(io) catch {};
    var client = McpClient.init(arena.allocator(), io, .{
        .name = "test",
        .endpoint = endpoint,
        .timeout_secs = 1,
    }, "unused");
    defer client.deinit();

    try std.testing.expectError(error.RequestTimedOut, client.connect());
}

test "a JSON-RPC error is reported as a diagnostic on the client" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const io = std.testing.io;
    var server = try test_http.listenLoopback(io);
    defer server.deinit(io);
    const endpoint = try test_http.endpointFor(arena.allocator(), &server);
    var script = test_http.Script{ .responses = &.{
        .{
            .status = "200 OK",
            .body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2026-07-28\",\"capabilities\":{\"tools\":{}}}}",
        },
        .{
            .status = "200 OK",
            .body = "{\"jsonrpc\":\"2.0\",\"id\":2,\"error\":{\"code\":-32602,\"message\":\"unknown tool\"}}",
        },
    } };
    var serving = try io.concurrent(test_http.Script.serve, .{ &script, io, &server });
    var client = McpClient.init(arena.allocator(), io, .{ .name = "test", .endpoint = endpoint }, "unused");
    defer client.deinit();

    try client.connect();
    var params = Value{ .object = .empty };
    try params.object.put(arena.allocator(), "name", .{ .string = "nope" });
    try params.object.put(arena.allocator(), "arguments", .{ .object = .empty });
    try std.testing.expectError(error.JsonRpcError, client.rpc("tools/call", params));
    try serving.await(io);

    try std.testing.expectEqual(@as(i64, -32602), client.last_rpc_error.?.code);
    try std.testing.expectEqualStrings("unknown tool", client.last_rpc_error.?.message);
}

test "unnamed and duplicate tools are skipped while listing" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const io = std.testing.io;
    var server = try test_http.listenLoopback(io);
    defer server.deinit(io);
    const endpoint = try test_http.endpointFor(arena.allocator(), &server);
    const responses = discoverAndListScript(
        \\{"jsonrpc":"2.0","id":2,"result":{"tools":[{"description":"no name"},{"name":"search"},{"name":"search","description":"duplicate"}]}}
    );
    var script = test_http.Script{ .responses = &responses };
    var serving = try io.concurrent(test_http.Script.serve, .{ &script, io, &server });
    var client = McpClient.init(arena.allocator(), io, .{ .name = "test", .endpoint = endpoint }, "unused");
    defer client.deinit();

    try client.connect();
    const tools = try client.listTools();
    try serving.await(io);

    try std.testing.expectEqual(@as(usize, 1), tools.len);
    try std.testing.expectEqualStrings("search", tools[0].name().?);
}
