# mcpx — CLI Bridge for MCP HTTP Servers

Use when you need to discover or invoke tools exposed by MCP (Model Context Protocol) HTTP servers from the command line. mcpx connects to any MCP server over HTTP (JSON-RPC 2.0 + SSE), lists tools, shows schemas, calls tools, and renders tool documentation as LLM-friendly markdown.

## Prerequisites

- `mcpx` binary on PATH (built from this repo with `zig build -Doptimize=ReleaseFast`)
- Config file at `~/.config/mcpx/config.toml` (or pass `-c PATH`)

## Config Format

```toml
[[http]]
name = "my-server"
endpoint = "https://mcp.example.com/mcp"
timeout_secs = 60          # optional, default 30

[http.headers]
Authorization = "Bearer ***"
X-Custom = "value"
```

Multiple `[[http]]` blocks register multiple servers.

## Commands

### List configured servers

```bash
mcpx servers
```

Output: `name\tendpoint` per line.

### List tools on a server

```bash
mcpx list <server>
```

Output: `tool_name\tfirst_line_of_description` per line.

### Show tool JSON schema

```bash
mcpx schema <server> <tool>
```

Output: pretty-printed JSON of the tool definition (name, description, inputSchema, outputSchema).

### Call a tool

```bash
mcpx call <server> <tool> '{"key": "value"}'
```

- Third argument is optional; defaults to `{}`.
- Must be valid JSON object.
- Output: pretty-printed JSON result from the server.

### Render tool documentation as markdown (skills)

```bash
mcpx skills <server>           # all tools
mcpx skills <server> <tool>    # single tool
```

Output: markdown with `## tool_name`, description, `### Parameters` / `### Returns` sections. Each parameter shows name, type, required flag, constraints (enum, min/max, pattern, default), and description. Nested objects and arrays are rendered recursively with indentation.

## Typical Workflow for an LLM Agent

1. **Discover**: `mcpx servers` → pick a server.
2. **Explore**: `mcpx skills <server>` → read markdown to understand available tools and their parameters.
3. **Invoke**: `mcpx call <server> <tool> '{...}'` → get structured JSON result.
4. **Inspect**: `mcpx schema <server> <tool>` → raw JSON schema if you need exact field types.

## Exit Codes

- `0` — success
- `1` — any error (message printed to stderr)

## Error Messages (stderr)

| Message | Cause |
|---------|-------|
| `cannot read config file: PATH` | Config missing or unreadable |
| `failed to parse config PATH: ERR` | Invalid TOML |
| `server 'X' not found. available: ...` | Wrong server name |
| `tool 'X' not found` | Wrong tool name |
| `request to URL timed out after N seconds` | Server too slow / unreachable |
| `HTTP NNN reason: body` | Non-2xx response |
| `RPC error [code]: message` | JSON-RPC error from server |
| `unsupported response Content-Type: T` | Server returned neither JSON nor SSE |

## Pitfalls

- The `-c` flag must come **before** the command: `mcpx -c alt.toml list srv` ✓, `mcpx list srv -c alt.toml` ✗ (parsed as positional).
- `call` arguments must be a single shell-quoted JSON string. Use single quotes: `'{"q": "hello"}'`.
- Servers using SSE transport return multiple JSON-RPC frames; mcpx automatically extracts the last one with a `result` or `error` field.
- `Mcp-Session-Id` is captured from the first response and sent on subsequent requests within the same invocation. Each `mcpx` call is a fresh session.
- Pagination (`nextCursor`) is handled automatically for `tools/list`.

## Building

```bash
zig build -Doptimize=ReleaseFast   # → zig-out/bin/mcpx (~1MB, stripped)
zig build test                     # run unit tests
```
