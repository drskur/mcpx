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

Create `$XDG_CONFIG_HOME/mcpx/config.toml`, or `~/.config/mcpx/config.toml`
when `XDG_CONFIG_HOME` is unset:

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

The default timeout is 30 seconds; `timeout_secs = 0` is rejected. Pass
`-c <path>` or `--config=<path>` to use another configuration file. Server
entries are validated before any request: names must be unique and non-empty,
endpoints must be absolute `http`/`https` URIs, and configured header names and
values must be valid HTTP field content.

For an OAuth-configured server, mcpx honors `WWW-Authenticate`
`resource_metadata` challenges or RFC 9728 protected-resource discovery, then
tries RFC 8414 Authorization Server Metadata and OIDC Discovery. A challenge
metadata URL is only followed when it stays on the resource server's own
origin, and every advertised authorization server is tried in order. Issuer,
authorization, token and registration URLs must use `https`, except on loopback
hosts.

mcpx uses Authorization Code with PKCE (S256), opens the authorization URL with
`xdg-open` on Linux, and waits up to 300 seconds for a redirect to an ephemeral
`127.0.0.1` callback port. Other requests on that port, such as a browser
favicon fetch, are answered and ignored. The URL is always printed to stderr so
it can be opened manually. The callback state is compared in constant time, an
`error=` response is reported with its description, and the
authorization-server `iss` (when supplied or required) is verified before code
exchange. Both authorization-code and refresh grants include the canonical MCP
endpoint as RFC 8707 `resource`.

Dynamic registration (`register = true`) registers a public native client with
`token_endpoint_auth_method: none`, so no client secret has to be stored.

Tokens and dynamically registered client credentials are keyed by validated
issuer and stored separately in
`<config dir>/mcpx/tokens.toml`. The directory is created with `0700` and the
file is atomically replaced with owner-only `0600` permissions after grants and
refreshes. Access tokens are refreshed when
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

`mcpx servers` appends `[oauth]` to OAuth-enabled entries. Unknown options are
rejected rather than being treated as arguments.

`mcpx skills` prints a skill document, not just schemas: a preamble states how to
reach the tools with `mcpx call <server> <tool> '<json_arguments>'`, points at
`mcpx list`, `mcpx skills <tool>` and `mcpx auth`, and explains the JSON argument
rules and the `6` / `7` exit codes. Every tool ends with an `### Invocation`
block containing a runnable `mcpx call` command seeded with its required
parameters. A `-c PATH` in effect is repeated in each printed command.

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Unclassified failure |
| `2` | Usage or configuration error, including an unknown server or tool |
| `3` | Authentication or authorization failure |
| `4` | Protocol or JSON-RPC failure |
| `5` | Request timeout |
| `6` | The tool ran and reported `isError` |
| `7` | The tool needs more input (`resultType: input_required`) |

A JSON-RPC error is reported on stderr with its code and a generic message.
Remote response bodies, messages, and error data are hidden by default because
they may contain submitted arguments or credentials. Set `MCPX_DEBUG=1` to
include that raw diagnostic content; mcpx prints a warning because this mode
may expose secrets in terminals and CI logs.

 `mcpx` negotiates
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
printed intact and reported with exit code 7; mcpx does not yet conduct that
follow-up interaction automatically.

## Development

```sh
zig build test          # includes loopback HTTP integration tests
zig fmt --check src build.zig
```

Tool listings skip entries without a name and duplicate names, tool schema
rendering is depth bounded, and responses are capped at 16 MiB (1 MiB for OAuth
metadata) so a hostile server cannot exhaust memory.

## CLI vs MCP: further reading

mcpx is a CLI bridge for MCP HTTP servers, which sits at the intersection of the
CLI-first vs MCP debate. The trade-offs are covered in the primary sources below
(summaries are the author's own; the linked posts are the authoritative text).

- **Mario Zechner (Pi agent creator) — "Benchmarking Tools for Coding Agents"**
  https://mariozechner.at/posts/2025-08-15-mcp-vs-cli/
  Directly benchmarked MCP vs CLI (120 runs, 3 tasks × 4 tools × 10 reps).
  Both hit 100% success; MCP was 23% faster and 2.5% cheaper. His core point:
  many MCPs are thin wrappers over existing CLIs (e.g. GitHub MCP vs `gh`), and a
  well-designed, token-efficient CLI is simpler and pipeable — add an MCP server
  on top of a good CLI only when you need it.

- **Lalatendu Swain — "Why CLIs Beat MCP for AI Agents — and How to Build Your Own CLI Army"**
  https://lalatenduswain.medium.com/why-clis-beat-mcp-for-ai-agents-and-how-to-build-your-own-cli-army-8db9e0467dd8
  Argues CLI wins on token efficiency (LM already knows Unix commands from training,
  no schema injection), Unix composability (pipe/filter only sends relevant output),
  and simplicity. Cites shell-based approaches showing 5–10x better token efficiency.

- **girma35 — "CLI-Agent vs MCP: A Practical Comparison"**
  https://dev.to/girma35/cli-agent-vs-mcp-a-practical-comparison-for-students-startups-and-developers-4com
  Recommends starting with CLI agents for prototyping/learning (faster iteration,
  lower cost, human legibility, inspectable output), and only adding MCP where
  reliability or shared standards demand it.

- **Firecrawl — "MCP vs CLI: Which One Should You Use in 2026?"**
  https://www.firecrawl.dev/blog/mcp-vs-cli
  Notes Peter Steinberger (OpenClaw) framed CLI as an ergonomics preference, not a
  capability gap. CLI wins on token efficiency for personal agents; MCP earns its
  complexity for OAuth per-user, multi-tenant, and enterprise audit-tail needs.

- **Tobias Pfuetze — "The MCP vs. CLI Debate Is the Wrong Fight"**
  https://medium.com/@tobias_pfuetze/the-mcp-vs-cli-debate-is-the-wrong-fight-a87f1b4c8006
  For a personal agent on your own machine, CLI-first is clearly superior
  (direct system access, zero abstraction overhead). MCP matters for distribution,
  discoverability, and enterprise governance — support both, let context decide.

- **Akshay Chame — "MCP vs CLI vs CLI+Skills: Trade-offs, Use Cases, and Best Practices"**
  https://medium.com/@akshaychame2/mcp-vs-cli-vs-cli-skills-trade-offs-use-cases-and-best-practices-49b9cfd7a556
  "CLI+Skills" is the underrated middle ground: the terminal's operational reality
  plus the repeatability agents need, without turning every workflow into a
  formal protocol. Use the lightest interface that gives enough reliability.

- **Latenode — "MCP vs CLI for AI Agents: Which One Should You Use?"**
  https://latenode.com/blog/mcp-vs-cli-ai-agents
  CLI is the better default for most agent tasks; MCP earns its complexity only for
  centralized auth, structured tool discovery, or multi-service orchestration.
  Most production systems end up using both.

- **Better Stack — "Playwright CLI vs. MCP: Browser Automation for Coding Agents"**
  https://betterstack.com/community/guides/ai/playwright-cli-vs-mcp-browser/
  A concrete case study: the Playwright CLI beat the MCP server on token efficiency
  ("pay-as-you-go" commands vs large upfront schema cost) and composability for
  coding agents in a fixed context window.
