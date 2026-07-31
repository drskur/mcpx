# mcpx — CLI Bridge for MCP HTTP Servers

Use mcpx to discover and invoke tools exposed by Model Context Protocol (MCP) HTTP servers. It uses JSON-RPC 2.0 over HTTP, accepts JSON and SSE responses, calls tools, and renders tool documentation as LLM-friendly markdown.

## Prerequisites

- `mcpx` binary on `PATH` (build it from this repository with `zig build -Doptimize=ReleaseFast`)
- A config file at `~/.config/mcpx/config.toml`, or a path supplied with `-c PATH` / `--config PATH`

Without an explicit config path, mcpx requires `HOME` and reads `$HOME/.config/mcpx/config.toml`.

## Config Format

```toml
[[http]]
name = "my-server"
endpoint = "https://mcp.example.com/mcp"
timeout_secs = 60          # optional, default 30

[http.headers]
X-Custom = "value"

[http.oauth]
client_id = "my-app"          # optional when register = true
scopes = "repo read"          # optional, space-separated
register = true               # optional RFC 7591 dynamic registration
```

Multiple `[[http]]` blocks register multiple servers. `-c` and `--config` are global flags and work anywhere in the argument list, including after the command or its positionals.

OAuth-enabled servers use Authorization Code + PKCE. mcpx honors
`WWW-Authenticate` protected-resource challenges and RFC 9728 fallback, then
tries RFC 8414 and OIDC authorization-server discovery. It generates
an S256 PKCE challenge and CSRF state, opens the authorization URL with
`xdg-open` on Linux, and accepts one redirect on an ephemeral
`127.0.0.1` port. The URL is printed to stderr as a manual fallback. Dynamic
registration uses RFC 7591 with `application_type: native` when
`register = true`; credentials are reused only for the same validated issuer.
The callback `iss` is checked before code redemption, and both code and refresh
token requests include the MCP endpoint as RFC 8707 `resource`.

OAuth tokens and client credentials are kept out of the main config in
`~/.config/mcpx/tokens.toml`. Grants and refreshes atomically replace this file
with `0600` owner-only permissions. mcpx refreshes an access token when it is
expired or within 60 seconds of expiry. On HTTP 401 it performs at most one
refresh-or-authorization recovery and retries the request once.

## Usage and Commands

Running `mcpx` with no arguments, or with `-h` / `--help`, prints usage and exits successfully.

```text
mcpx [-c PATH] <COMMAND>

mcpx servers
mcpx auth <server>
mcpx list <server>
mcpx call <server> <tool> [json_args]
mcpx skills <server> [tool]
```

The parser accepts at most three positional arguments after the command. Commands may therefore accept surplus positionals until that shared limit; a fourth produces `TooManyArguments`. Do not rely on surplus arguments being meaningful.

### List configured servers

```bash
mcpx servers
```

Output is `name\tendpoint` per line, with ` [oauth]` appended to OAuth-enabled
servers. If the config contains no servers, output is `no servers configured.`

### Force OAuth authentication

```bash
mcpx auth <server>
```

The server must contain an `[http.oauth]` block. This runs a fresh browser and
localhost callback flow, stores the resulting token, and prints
`authenticated <server>` on success.

### List tools on a server

```bash
mcpx list <server>
```

Output is `tool_name\tfirst_line_of_description` per line. If the server returns no tools, output is `no tools available.`

### Call a tool

```bash
mcpx call <server> <tool> '{"key": "value"}'
```

The JSON argument is optional and defaults to `{}`. It must reach mcpx as one shell argument, must be valid JSON, and must be an object. Single quotes are recommended in shells that support them, but any quoting that delivers one argument works. `call` sends the supplied tool name directly to the server; it does not first check whether that name appeared in `tools/list`.

Output is the server's JSON result, pretty-printed.

### Render tool documentation as markdown

```bash
mcpx skills <server>           # all tools
mcpx skills <server> <tool>    # one tool
```

Single-tool mode looks up the tool locally and reports `ToolNotFound` if it is absent. Output uses `## tool_name`, the description, and `### Parameters` / `### Returns` sections.

The renderer displays only these constraints: `enum`, `minLength`, `maxLength`, `minimum`, `maximum`, `pattern`, and `default`. It recursively renders nested `properties`, plus array `items` that contain `properties` or `$ref`. A `$ref` is displayed but not resolved. A definition without `properties` falls back to a raw JSON block.

## Typical Workflow for an LLM Agent

1. **Discover**: `mcpx servers` and select a server.
2. **Explore**: `mcpx skills <server>` and read the rendered tool documentation.
3. **Invoke**: `mcpx call <server> <tool> '{...}'` and consume the structured result.

## Protocol Behavior and Limits

- `McpClient.init` requires an arena or process-scoped allocator that outlives the client. Individual client allocations are intentionally not freed; a general-purpose allocator is not supported for repeated client reuse.
- mcpx knows `2025-03-26`, `2025-06-18`, `2025-11-25`, and `2026-07-28`. It attempts `server/discover`, selects the newest mutual version from a `-32022` response, and falls back to legacy initialize when discovery is unavailable.
- Before `tools/list` or `tools/call`, mcpx checks the initialized server's `capabilities.tools`; absence produces `ServerDoesNotSupportTools`.
- `2026-07-28` requests carry protocol/client `_meta`, `Mcp-Method`, and (for named requests) `Mcp-Name`. `resultType: input_required` is surfaced intact; automatic multi-round-trip continuation is not implemented.
- Stateful `Mcp-Session-Id`, 404 session recovery, server requests/ping, and `notifications/cancelled` are enabled only when the negotiated version's capability row permits them. They remain active for legacy `2025-03-26`; modern cancellation closes the response stream.
- The configured timeout covers the entire request, including URI resolution, DNS, connection establishment, TLS, and response-body reading. Legacy cancellation uses a separate fixed 5-second timeout.
- Response bodies are limited to 16 MiB. Larger responses produce `ResponseTooLarge`.
- SSE events are parsed incrementally. Every message in a JSON-RPC batch is inspected before a matching numeric response is returned. Valid JSON-RPC 2.0 server requests are answered immediately during stream consumption using a separate HTTP POST: `ping` receives an empty successful result and unknown methods receive method-not-found. Notifications are inspected but require no response.
- Configured headers cannot override `Accept`, `Content-Type`, `MCP-Protocol-Version`, `Mcp-Session-Id`, `Mcp-Method`, `Mcp-Name`, or HTTP framing and hop-by-hop headers; matching names are skipped case-insensitively with a warning. `Authorization` is additionally reserved and managed by mcpx when the server has an OAuth block. Without OAuth, a static configured `Authorization` header is still allowed.
- Up to 1,000 `tools/list` pages and 100,000 tools are fetched automatically; exceeding either aggregate limit produces `PaginationLimitExceeded`. Empty `nextCursor` ends pagination, and a repeated non-empty cursor produces `RepeatedPaginationCursor`.

## Exit Codes and Errors

Success exits `0`; any error exits `1`. Every error prints a final `error: ErrorName` line to stderr, including errors that first print a more descriptive line.

| Error or preceding message | Cause |
|---|---|
| `MissingCommand` | No longer emitted: no arguments prints usage and exits `0` |
| `UnknownCommand` | Command name is not recognized |
| `OauthNotConfigured` | `mcpx auth` targeted a server without an OAuth block |
| `MissingArgument` | Command lacks a required server or tool positional |
| `MissingConfigPath` | `-c` / `--config` has no following path |
| `TooManyArguments` | More than three positional arguments follow the command |
| `ArgsNotValidJson` | Tool arguments are not valid JSON |
| `ArgsMustBeObject` | Tool arguments are valid JSON but not an object |
| `HomeNotSet` | No config flag was supplied and `HOME` is unavailable |
| `cannot read config file: PATH` then `ConfigReadFailed` | Config is missing or unreadable |
| `failed to parse config PATH: ERR` then `ConfigParseFailed` | TOML is invalid |
| `server 'X' not found. available: ...` then `ServerNotFound` | Server name is not configured |
| `tool 'X' not found` then `ToolNotFound` | Tool name is absent in `skills` single-tool mode |
| `ServerDoesNotSupportTools` | Initialized capabilities do not advertise tools |
| `SessionExpired` | A session-bound request received 404 and the one recovery attempt did not succeed |
| `request to URL timed out after N seconds` then `RequestTimedOut` | The explicit request timer expired |
| `ResponseTooLarge` | Response body exceeded 16 MiB |
| `RepeatedPaginationCursor` | A tools-list cursor repeated |
| `PaginationLimitExceeded` | Tool pagination exceeded 1,000 pages or 100,000 tools |
| `UnsupportedProtocolVersion` | Server negotiated neither supported MCP version |
| `HTTP NNN reason: body` then `HttpRequestFailed` | Server returned a non-2xx response |
| `RPC error [code]: message` then `JsonRpcError` | Server returned a JSON-RPC error |
| `unsupported response Content-Type: T` then `UnsupportedContentType` | Response was neither JSON nor SSE |

## Building

```bash
zig build -Doptimize=ReleaseFast
zig build test
```
