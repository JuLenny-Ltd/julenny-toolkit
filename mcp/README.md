# JuLenny FHE: MCP Server

An [MCP](https://modelcontextprotocol.io) server that lets an AI agent (Claude
Desktop, Cursor, etc.) drive the JuLenny FHE platform from a chat prompt: list
collaborations and permissions, create them, and (as local crypto tools are
added) generate keys, encrypt, run, decrypt, and release, getting the plaintext
result back.

## Design: the crypto stays on your machine

The server **orchestrates** the JuLenny platform API; it does **not** do
cryptography itself. All key generation, encryption, and decryption run locally
through the `julenny-toolkit` CLI (the server shells out to it, exactly like the
[`examples/`](../examples) scripts). The agent never sees your keys or
plaintext, and nothing crypto-related moves server-side. This is the zero-trust
guarantee the toolkit is built on stays intact while adding full agent
automation. Because the server is TypeScript it is write-once and
cross-platform; only the CLI has per-OS builds.

This package is open source (same transparency obligation as the toolkit): it
runs on your machine and touches your keys, so it must be auditable.

## Security model

Security is enforced by **capabilities, not prompts**. Assume the agent driving
this server may be prompt-injected or hostile. It can only do what its tools
allow, so the server is built to make misbehavior structurally impossible rather
than instructing the model to behave. It exposes exactly **two families of typed
verbs and nothing else**:

1. **Platform API verbs** call the JuLenny REST API (ciphertext and metadata
   only; the platform never holds keys or plaintext).
2. **Toolkit verbs** invoke specific `julenny-toolkit` CLI commands locally for the
   cryptography.

There is deliberately **no** generic shell/`exec`/`run(command)` tool, **no**
generic filesystem read/write/list tool, and **no** arbitrary network/fetch
tool. Each toolkit verb runs the CLI through a fixed **argv array** (never a
shell string), validates and workdir-confines every path parameter, and
references keys **by alias**. The toolkit owns the key store and the server
never handles raw key bytes.

**Blind by design:** verbs return only references and status: paths, ids,
handles, ok/fail, non-secret metadata. They never return plaintext, decrypted
results, key bytes, or the API key, in results, errors, or logs. `decrypt_result`
writes the plaintext to a local file and returns its path; viewing it is your
explicit local choice. `decrypt_*` and `release_*` require a real,
host-enforced confirmation before they run.

### Honest scope

This design keeps the **agent, the model provider, and the JuLenny platform
blind to your keys and plaintext**, and that is the guarantee it delivers. It does
**not** blind a *separately-armed* agent: if you attach a generic shell or
filesystem MCP to the **same** agent, that agent can read your local files
directly and bypass this server entirely. For the blind-by-design property to
hold, run this MCP **without** a co-attached shell/filesystem MCP. The source is
open precisely so this contract is auditable: "check the code," not "trust us."

## Configuration

Two environment variables:

- `JULENNY_API_KEY` (**required**) is your platform API key (`sk_live_...`).
  Generate an MCP key in the dashboard; it inherits and cannot exceed your role.
- `JULENNY_API_URL` (optional) is the **bare base URL**, e.g. `https://julenny.net`,
  with **no** `/mcp` and **no** `/api` suffix (the client appends `/api/...`
  itself). Defaults to `https://julenny.net`. Set this to your deployment's base
  URL if it isn't served from `julenny.net` yet.

The API key is only ever sent in the `x-api-key` header. No telemetry, no
phone-home, and keys/plaintext are never logged.

## Build and run

```bash
cd mcp
npm install
npm run build      # tsc -> dist/
npm start          # node dist/index.js  (stdio transport)
# or, during development:
npm run dev        # tsx src/index.ts
```

## Use from Claude Desktop

Add to your Claude Desktop MCP config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "julenny": {
      "command": "node",
      "args": ["/absolute/path/to/fhe-toolkit/mcp/dist/index.js"],
      "env": {
        "JULENNY_API_KEY": "sk_live_...",
        "JULENNY_API_URL": "https://julenny.net"
      }
    }
  }
}
```

(A `julenny-toolkit mcp` launcher subcommand and per-OS installers that auto-write
this config are on the roadmap.)

## Tools

API tools (available now):

| tool | what it does |
|---|---|
| `list_functions`, `get_function_definition` | browse the FHE function library |
| `list_collaborations`, `create_collaboration` | manage collaborations with partner companies |
| `list_permissions_granted`, `list_permissions_received`, `create_permission`, `add_executions`, `revoke_permission` | manage function grants |
| `list_datasets`, `list_collaboration_datasets` | inspect uploaded encrypted datasets |
| `estimate_execution`, `trigger_execution`, `get_execution_status`, `list_executions` | cost, run, and track computations |
| `get_audit_log` | read the tamper-evident audit trail |

Local crypto tools (roadmap) wrap the CLI so an agent can run the full
pipeline end to end: `generate_keys`, `encrypt`, `decrypt`, `sign`, `release`.
These require explicit user confirmation on `decrypt` and especially `release`
(an agent must never silently approve a partner to see results).

## Examples as a reference for agents

The [`examples/`](../examples) folder runs this same end-to-end flow with the
`julenny-toolkit` CLI, using the same commands and flags these MCP tools generate.
It's a learnable reference corpus: an agent can read the examples to understand
the exact phase sequence (keysetup → encrypt → execute → release → decrypt) and
the arguments each step takes, then reproduce it through these tools. The
examples and the MCP tools are kept in lockstep on purpose.

## License

Business Source License 1.1. See [LICENSE](../LICENSE) in the repository root.
