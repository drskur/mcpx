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
endpoint = "http://localhost:8080/mcp"
headers = { Authorization = "Bearer xxx" }
timeout_secs = 60
```

The default timeout is 30 seconds. Pass `-c <path>` to use another
configuration file.

## Usage

```text
mcpx servers
mcpx list <server>
mcpx call <server> <tool> [json_args]
mcpx skills <server> [tool]
```

`mcpx` initializes one stateful MCP session per invocation, supports JSON and
SSE responses, and follows all `tools/list` pagination cursors.
