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
Authorization = "Bearer ***"
X-Custom = "value"
```

Multiple `[[http]]` blocks register multiple servers. `-c` and `--config` are global flags and work anywhere in the argument list, including after the command or its positionals.

## Usage and Commands

Running `mcpx` with no arguments, or with `-h` / `--help`, prints usage and exits successfully.

```text
mcpx [-c PATH] <COMMAND>

mcpx servers
mcpx list <server>
mcpx call <server> <tool> [json_args]
mcpx skills <server> [tool]
```

The parser accepts at most three positional arguments after the command. Commands may therefore accept surplus positionals until that shared limit; a fourth produces `TooManyArguments`. Do not rely on surplus arguments being meaningful.

### List configured servers

```bash
mcpx servers
```

Output is `name\tendpoint` per line. If the config contains no servers, output is `no servers configured.`

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

- mcpx proposes and accepts only MCP protocol version `2025-03-26`; other versions produce `UnsupportedProtocolVersion`.
- Before `tools/list` or `tools/call`, mcpx checks the initialized server's `capabilities.tools`; absence produces `ServerDoesNotSupportTools`.
- One stateful MCP session is initialized per invocation. `Mcp-Session-Id` is accepted only from the `initialize` response, must contain visible ASCII characters only, and is reused for later requests. If a request carrying it receives HTTP 404, mcpx clears the session, reconnects, and retries that request once.
- The configured timeout is an explicit timer. On timeout, mcpx attempts to send `notifications/cancelled` for an outstanding request using a separate fixed 5-second timeout, except initialization requests, which MCP prohibits cancelling. Cancellation therefore adds at most 5 seconds. DNS, TLS, connection, and other transport failures are separate errors, not timeouts.
- Response bodies are limited to 16 MiB. Larger responses produce `ResponseTooLarge`.
- SSE events are parsed incrementally and a matching numeric JSON-RPC response is returned as soon as it arrives. Valid JSON-RPC 2.0 events containing `method` are collected as server requests (with an `id`) or notifications (without one); after the matching response arrives, `ping` requests receive an empty successful result and other server requests receive method-not-found.
- Configured headers cannot override `Accept`, `Content-Type`, `MCP-Protocol-Version`, `Mcp-Session-Id`, or HTTP framing and hop-by-hop headers; matching names are skipped case-insensitively with a warning.
- All `tools/list` pages are fetched automatically. Empty `nextCursor` ends pagination, and a repeated non-empty cursor produces `RepeatedPaginationCursor`.

## Exit Codes and Errors

Success exits `0`; any error exits `1`. Every error prints a final `error: ErrorName` line to stderr, including errors that first print a more descriptive line.

| Error or preceding message | Cause |
|---|---|
| `MissingCommand` | No longer emitted: no arguments prints usage and exits `0` |
| `UnknownCommand` | Command name is not recognized |
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
| `UnsupportedProtocolVersion` | Server negotiated neither supported MCP version |
| `HTTP NNN reason: body` then `HttpRequestFailed` | Server returned a non-2xx response |
| `RPC error [code]: message` then `JsonRpcError` | Server returned a JSON-RPC error |
| `unsupported response Content-Type: T` then `UnsupportedContentType` | Response was neither JSON nor SSE |

## Building

```bash
zig build -Doptimize=ReleaseFast
zig build test
```
