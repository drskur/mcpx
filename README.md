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

For an OAuth-configured server, mcpx discovers the MCP protected resource and
authorization server metadata, uses Authorization Code with PKCE (S256), opens
the authorization URL with `xdg-open` on Linux, and waits for one redirect to
an ephemeral `127.0.0.1` callback port. The URL is always printed to stderr so
it can be opened manually. The callback state is verified before the code is
exchanged.

Tokens and dynamically registered client credentials are stored separately in
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

`mcpx servers` appends `[oauth]` to OAuth-enabled entries. `mcpx` initializes
one stateful MCP session per invocation, supports JSON and SSE responses, and
follows all `tools/list` pagination cursors.
