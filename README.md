# mcpx

A single-binary Zig CLI bridge with no runtime dependencies for calling Model Context Protocol HTTP
servers directly.

## Build

Zig 0.16.0 is required.

```sh
zig build -Doptimize=ReleaseSafe
```

The executable is written to `zig-out/bin/mcpx`.

## Configuration

Create `~/.config/mcpx/config.toml`:

```toml
[[http]]
name = "search"
endpoint = "http://localhost:3000/mcp"

[[http]]
name = "github"
endpoint = "https://mcp.example.com/mcp"
timeout_secs = 60

[http.oauth]
client_id = "my-app"          # optional when register = true
scopes = "repo read"          # optional, space-separated
register = true               # RFC 7591 dynamic client registration
```

The default timeout is 30 seconds. Pass `-c <path>` to use another
configuration file.

For an OAuth-configured server, mcpx honors `WWW-Authenticate`
`resource_metadata` challenges or RFC 9728 protected-resource discovery, then
tries RFC 8414 Authorization Server Metadata and OIDC Discovery. It uses
Authorization Code with PKCE (S256), opens
the authorization URL with `xdg-open` on Linux, and waits for one redirect to
an ephemeral `127.0.0.1` callback port. The URL is always printed to stderr so
it can be opened manually. The callback state and authorization-server `iss`
(when supplied or required) are verified before code exchange. Both
authorization-code and refresh grants include the MCP endpoint as RFC 8707
`resource`.

Tokens and dynamically registered client credentials are keyed by validated
issuer and stored separately in
`~/.config/mcpx/tokens.toml`. The file is atomically replaced with owner-only
`0600` permissions after grants and refreshes. Access tokens are refreshed when
they are expired or within 60 seconds of expiry. To discard the effective
session and force a new browser authorization, run:

```text
mcpx auth <server>
```

When OAuth is configured, mcpx owns the `Authorization` header and ignores an
`Authorization` value in `[http.headers]`. Static authorization headers remain
supported for servers without an OAuth block.

## Usage

```text
mcpx servers
mcpx auth <server>
mcpx list <server>
mcpx call <server> <tool> [json_args]
mcpx skills <server> [tool]
```

`mcpx servers` appends `[oauth]` to OAuth-enabled entries. `mcpx` negotiates
MCP `2026-07-28` with `server/discover` and remains compatible with legacy
`2025-03-26` initialize/session servers. It supports JSON and SSE responses and
follows all `tools/list` pagination cursors.

## Protocol compatibility

Protocol behavior comes from one version/capability table covering
`2025-03-26`, `2025-06-18`, `2025-11-25`, and `2026-07-28`. mcpx attempts
modern discovery first, honors `-32022` supported-version responses by choosing
the newest mutual version, and falls back to legacy initialize when
`server/discover` is unavailable.

For `2026-07-28`, requests include protocol/client `_meta`, `Mcp-Method`, and
`Mcp-Name` where applicable. Modern requests do not use MCP sessions or legacy
cancellation notifications. A result with `resultType: input_required` is
returned intact; mcpx does not yet conduct that follow-up interaction
automatically.
