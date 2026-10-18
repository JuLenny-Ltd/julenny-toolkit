# JuLenny Toolkit: MCP Server

An [MCP](https://modelcontextprotocol.io) server that lets an AI agent drive the JuLenny
platform from a chat: create collaborations and permissions, run the joint key setup,
encrypt and upload your data, run a function, and release or decrypt the result. It works
with any MCP client, such as Claude Desktop, Claude Code, Cursor, VS Code or Windsurf.

## Design: the crypto stays on your machine

The server orchestrates the JuLenny platform API; it does not do cryptography itself. Key
generation, encryption and decryption all run locally through the `julenny-toolkit` CLI,
which the server calls with the same commands the [`scripts/`](../scripts) use. The agent
never sees your keys or plaintext, so the zero-trust guarantee the toolkit is built on stays
intact while the agent does the work.

This package is source-available, like the rest of the toolkit: it runs on your machine and
touches your keys, so it must be auditable.

## Security model

Security is enforced by capabilities, not prompts. Assume the agent driving this server may
be prompt-injected or hostile: it can only do what its tools allow. The server exposes two
families of typed tools and nothing else:

1. **Platform tools** call the JuLenny API (ciphertext and metadata only; the platform never
   holds keys or plaintext).
2. **Toolkit tools** run specific `julenny-toolkit` commands locally for the cryptography.

There is no generic shell, command or network tool, and no tool that reads arbitrary files.
Each toolkit tool runs the CLI with a fixed argument list (never a shell string), and every
file it touches is confined to your working folder.

**Blind by design.** Tools return only references and status: file names, ids, ok or failed,
non-secret metadata. They never return plaintext, decrypted results, key bytes or the API
key, in results, errors or logs. `decrypt_result` writes the answer to a file in your working
folder and returns its name; reading it is your choice.

**What the agent can do.** `release` (which lets your partner see a result) and
`decrypt_result` run when the agent calls them; the server does not ask you first. The
permission decides who may see a result, and every release is recorded in the platform's
audit log. If you want to approve each step yourself, use a client that asks before every
tool call, or tell your agent to check with you first.

### Honest scope

This design keeps the agent, the model provider and the JuLenny platform blind to your keys
and plaintext. It does not blind a separately equipped agent: if you attach a shell or
filesystem MCP server to the same agent, that agent can read your local files directly. For
the blind-by-design property to hold, run this server without one. The source is published
so that this can be checked rather than trusted.

## Configuration

Your MCP client starts the server and passes these environment variables:

- `JULENNY_API_KEY` (required): your platform API key (`sk_live_...`). Generate an MCP key in
  the dashboard; it inherits your role and cannot exceed it.
- `JULENNY_API_URL` (optional): the bare base URL, default `https://julenny.net`, with no
  `/api` suffix.
- `JULENNY_WORKDIR` (optional): the working folder. The server reads and writes only inside
  it; absolute paths, `..` and links pointing outside are rejected. It is the same folder
  the scripts use. Default: the folder chosen at install time, otherwise
  `%USERPROFILE%\julenny-workdir` on Windows and `~/julenny-workdir` on Linux.
- `JULENNY_TOOLKIT_BIN` (optional): the path to `julenny-toolkit`, if it is not on your
  `PATH`.

The API key is sent only in the `x-api-key` header. No telemetry, and keys and plaintext are
never logged.

## Installing

The Windows installer and the Linux package both include the server, and on Windows the
installer adds it to Claude Desktop for you. For every other client, see "Using the MCP
server" in the [main README](../README.md).

To build it from source instead:

```bash
cd mcp
npm install
npm run build      # tsc -> dist/
npm start          # node dist/index.js (stdio)
```

## Tools

Start with `next_step`: given a permission, it reports the current stage and the exact tool
to call next.

| Area | Tools |
|---|---|
| Guidance | `next_step` |
| Functions and audit | `list_functions`, `get_function_definition`, `get_audit_log` |
| Collaborations and permissions | `list_collaborations`, `create_collaboration`, `list_permissions_granted`, `list_permissions_received`, `create_permission`, `create_self_test_permission`, `confirm_dataset_size`, `add_executions`, `revoke_permission` |
| Signing and key setup | `signing_keygen`, `register_signing_key`, `keysetup_contribute`, `relin_contribute`, `relin_combine`, `sum_contribute`, `sum_combine`, `derive_rotation_indices`, `rotation_contribute`, `rotation_combine`, `publish_keysetup_message`, `download_keysetup_message`, `wrap_envelope`, `wrap_final_keys_envelope`, `publish_final_keys`, `publish_rotation_key`, `get_rotation_status`, `fetch_joint_public_key`, `verify_keys` |
| Your data | `list_workdir_files`, `encode_recipe`, `encrypt`, `upload`, `declare_input_dataset`, `get_declared_datasets`, `send_result_side`, `list_datasets`, `list_collaboration_datasets`, `inspect` |
| Running | `estimate_execution`, `trigger_execution`, `get_execution_status`, `list_executions` |
| Results | `release`, `download_result`, `download_partial`, `partial_decrypt`, `decrypt_result`, `resolve_matches`, `resolve_rules` |
| Checks | `selftest` |

**Large datasets.** For Joint Record Overlap for Large Datasets, `create_permission` takes
the name of your data file and proposes the smallest dataset size that holds it. Your
partner's agent settles it with `confirm_dataset_size`, which confirms the size or increases
it. The toolkit counts the records locally: the agent learns only the size, never the count.

## The scripts as a reference for agents

The [`scripts/`](../scripts) run the same end-to-end flow with the same CLI commands and
flags these tools use. An agent can read them to learn the phase sequence (key setup,
encrypt, run, release, decrypt) and the arguments each step takes. The scripts and the
tools are kept in step on purpose.

## License

Business Source License 1.1. See [LICENSE](../LICENSE) in the repository root.
