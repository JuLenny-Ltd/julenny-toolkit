# JuLenny FHE Toolkit

The customer-side client for JuLenny, a platform for running computations on encrypted data shared between organizations.

## What it does

Two or more organizations want to compute a joint result over their data (an overlap count, a statistical aggregate, a joint model score, a decision-tree inference) without revealing the underlying records to each other or to the platform running the computation. The JuLenny platform performs that computation on encrypted ciphertexts using Fully Homomorphic Encryption (FHE). This toolkit is what each organization installs on its own machines to:

1. Generate its share of the cryptographic key material.
2. Encrypt local data before uploading it to the platform.
3. Contribute its share to the threshold decryption that reveals the final answer.

The toolkit offers three surfaces for these operations, all performing the identical local cryptographic work: the `julenny-toolkit` command-line tool (for backend automation), a desktop app (graphical), and the `julenny-mcp` MCP server (so an AI agent can drive the same steps).

## The zero-trust guarantee

The platform is designed under a zero-trust assumption: the JuLenny service that runs FHE computations must never be able to decrypt anything. That requires the secret-key material to stay entirely on the participating organizations' machines, and the platform to only ever see ciphertext. The toolkit enforces this structurally:

- **All cryptography lives in an offline core.** The `core/` library and the `cli/` tool that wraps it contain no network code at all - no sockets, no HTTP client, nothing that can reach any host. Every key operation, encryption, and partial decryption happens locally against local files, so secret shares and plaintext never pass through anything that could transmit them. Auditors can confirm this by grepping `cli/` and `core/` for any networking API; there are none.
- **Only ciphertext crosses the network.** Communication with the platform happens over its HTTPS API - driven by your own scripts, the web UI, or the MCP server - and only ever carries ciphertext and encrypted key material. The plaintext-to-ciphertext step always happens first, locally, in the offline core.
- **The MCP server is blind by design.** `julenny-mcp` is an optional driver that lets an agent orchestrate the workflow. It shells out to the `julenny-toolkit` CLI for every cryptographic step and transports the resulting ciphertext to the platform; its tool results are file paths and status only, never plaintext or secret-key bytes. It cannot read what it moves.

The net effect: the party running the computation only ever holds ciphertext, and the secret material that could decrypt it never leaves the offline core on your own machines.

## Source and auditing

The source code in this repository is published so that any participating organization can audit it before installing. Building from source is not the recommended install path - use the `.deb` or the Windows installer from the releases page. But you can read every line of what runs on your machines, and a few properties are worth confirming directly:

- **No network code in the crypto core.** Grep `cli/` and `core/` for socket APIs, HTTP clients, or any networking call - there are none. All platform communication is done by your scripts, the web UI, or the MCP driver, never by the crypto core itself.
- **OpenFHE-only FHE.** Every homomorphic-encryption operation routes through [OpenFHE](https://www.openfhe.org/) primitives. The types in `core/src/crypto/internal.h` are direct aliases of `lbcrypto::*`; no proprietary scheme is implemented anywhere in the toolkit.
- **Standard signing primitives.** The Ed25519 signatures used to authenticate key-exchange envelopes route through OpenSSL's EVP API. No custom signature scheme.

## Installation

### Linux (Debian / Ubuntu)

OpenFHE is statically linked into the binary, so the CLI itself has no unusual runtime dependencies. The package installs the `julenny-toolkit` CLI, the `julenny-mcp` MCP server, and the example scripts.

```bash
sudo apt install ./julenny-toolkit-linux-amd64.deb
julenny-toolkit --version
```

Use `apt install ./file.deb` rather than `dpkg -i`: the example scripts need `jq`, `curl` and `xxd`, which the package declares as dependencies, and apt installs them for you. (`dpkg -i` would leave the package unconfigured until you ran `sudo apt-get install -f`.)

#### The example scripts

The examples are the canonical reference for driving the toolkit from your own pipeline. They install read-only under `/usr/share/julenny-toolkit/examples`. For a copy you can run and edit:

```bash
julenny-toolkit-examples
```

It asks which side of the collaboration this machine is (data owner, data consumer, or both) and where to put the scripts, then copies only that side. Skip it entirely if you only need the CLI or the MCP server. For unattended installs, pass `--role` and `--dest`.

### Windows

Download `julenny-toolkit-setup-windows-amd64.exe` from the releases page and run it. The installer lets you choose any combination of four components:

- the **JuLenny Toolkit** desktop app (graphical UI),
- the **`julenny-toolkit`** command-line tool,
- the **`julenny-mcp`** MCP server, with optional one-click wiring into Claude Desktop,
- the **example scripts**, where the installer asks which side of the collaboration this machine is and where to put them.

It installs per-user; no administrator rights are required. The app appears as **JuLenny Toolkit** in the Start menu.

> **Close Claude Desktop before installing** if you are installing the MCP server. Claude Desktop rewrites its configuration file when it exits, which erases the connector the installer adds. Claude Code is unaffected and can stay open.

> The installer is not yet code-signed, so Windows SmartScreen may show an "unknown publisher" prompt. Choose **More info -> Run anyway** to proceed.

## Using the MCP server

`julenny-mcp` is a standard MCP server speaking the protocol over stdin/stdout. It works with **any MCP client**: Claude Desktop, Claude Code, Cursor, Windsurf, Zed, Continue, VS Code, and anything else that supports MCP.

Only Claude Desktop is configured for you, by the Windows installer. Every other client needs one entry in its own config, using the same shape:

```json
{
  "mcpServers": {
    "JuLenny": {
      "command": "C:\\Users\\<you>\\AppData\\Local\\Programs\\julenny-toolkit\\julenny-mcp.exe",
      "env": {
        "JULENNY_API_KEY": "sk_live_...",
        "JULENNY_API_URL": "https://julenny.net",
        "JULENNY_WORKDIR": "C:\\Users\\<you>\\julenny-workdir"
      }
    }
  }
}
```

On Linux the command is simply `julenny-mcp`, since the `.deb` puts it on your `PATH`.

| Client | Config file |
|---|---|
| Claude Desktop | configured by the installer. Appears under **Settings → Developer**, not Connectors |
| Cursor | `~/.cursor/mcp.json` (global) or `.cursor/mcp.json` (per project) |
| Claude Code | `claude mcp add julenny -- <path-to>/julenny-mcp` |
| VS Code | `.vscode/mcp.json`, which uses a `servers` key rather than `mcpServers` |
| Windsurf, Zed, Continue | their own MCP config; the `mcpServers` shape above applies |

`JULENNY_WORKDIR` is the folder the server reads and writes. It is confined to that folder by design: absolute paths, `..` segments and symlinks pointing outside are all rejected, so the server cannot read anything else on your machine. Put the files you want encrypted inside it and refer to them by name. If the variable is omitted, the default is `%LOCALAPPDATA%\julenny-toolkit\workdir` on Windows and `$XDG_DATA_HOME/julenny-toolkit/workdir` on Linux.

The MCP server never performs cryptography itself. It shells out to the `julenny-toolkit` CLI for every key operation and only ever transports ciphertext, so your keys and plaintext stay on your machine regardless of which client drives it.

## Quick start

The fastest way to see the toolkit in action is to run the end-to-end example. Each example folder represents one organization in a two-party collaboration; you can run them on two machines (one the data owner, one the data consumer) or as two shells on the same machine for local testing.

These scripts drive a **two-party collaboration**: two organizations, each with its own account. They cannot set up a solo run against your own data alone. For that, see [Running a solo self-test](#running-a-solo-self-test) below.

One menu-driven driver runs the whole lifecycle and picks up wherever you left off:

```bash
# Linux, data-owner machine
cd <examples>/joint-record-overlap/acme && ./run.sh

# Linux, data-consumer machine
cd <examples>/joint-record-overlap/beta && ./run.sh
```

```powershell
# Windows, data-owner machine
cd <examples>\joint-record-overlap\acme; .\run.ps1

# Windows, data-consumer machine
cd <examples>\joint-record-overlap\beta; .\run.ps1
```

Every script exists in both forms and does the same work, so the two sides of a collaboration can run on different operating systems. The installer copies only the set your machine can run.

The driver chains the numbered phase scripts (`00-init` through `06-decrypt`), which you can also run individually to follow the protocol step by step. Each is small, commented, and uses only HTTPS plus this toolkit. Read them as the canonical reference for integrating the toolkit into your own pipelines.

Windows needs nothing beyond the toolkit itself: the PowerShell scripts use built-in cmdlets, so there is no `jq` or `curl` to install and no WSL.

See [`examples/README.md`](examples/README.md) for the full phase breakdown, the scenarios available, and the single-machine self-test setup.

## Running a solo self-test

A solo self-test is one organization running a function against its own data, with no partner. The platform calls this an **internal permission**, and it is what a trial account uses. You play both sides: the toolkit generates two key shares locally, you encrypt two of your own files, the platform computes on the ciphertext, and you decrypt the answer yourself.

The quickest route is the MCP server, which can drive the whole sequence and ask you which files to use. Ask your assistant for a self-test and it will create the permission, generate the keys, encrypt, upload, run, decrypt, and hand you the path to the matched records. It gives you a **file path** rather than reading the answer out, because the connector never receives your plaintext or the raw result.

For the full command sequence on Windows and Linux, see the self-test section of the [JuLenny FAQ](https://julenny.net/faq).

Note that a solo run still needs real evaluation keys, since the mathematics is unchanged: any function that multiplies two ciphertexts requires a relinearization key. The toolkit generates these locally and the sequence is scripted in the FAQ.

## What's in this repository

```
cli/        Command-line tool, julenny-toolkit. The primary integration
            surface for backend automation. No network code.
core/       C++ library shared by the CLI and the desktop app.
            Contains all cryptographic logic. No network code.
mcp/        MCP server, julenny-mcp. Lets an AI agent drive the same
            workflow; shells out to the CLI for all crypto and moves
            only ciphertext. Blind by design.
windows/    WinUI 3 desktop application. Same crypto operations as
            the CLI, with a graphical interface.
examples/   End-to-end demo scripts showing a two-party collaboration
            from key setup through joint computation and decryption.
docs/       Build instructions and reference documentation.
```

## Cryptographic background

The toolkit implements the client side of a threshold-FHE protocol built on [OpenFHE](https://www.openfhe.org/). Each participating organization holds an independent secret share. The joint public key is constructed without any single party ever holding the joint secret key. Decryption of any computed result requires every participant to contribute a partial decryption; no proper subset can recover plaintext.

Releases support both the BFV and CKKS schemes, selected per function by the platform's signed function definition. The current crypto contexts are `bfv-default-v1` and `ckks-default-v1`, plus `ckks-tree-v1` for encrypted decision-tree inference. Additional schemes and parameter sets are exposed as the platform grows its function catalog.

## Verifying a release

Every release ships a `SHA256SUMS` file listing the SHA-256 hash of each artifact. Download it alongside your binary and verify before installing:

```bash
sha256sum --check --ignore-missing SHA256SUMS
```

The `--ignore-missing` flag lets you verify just the file(s) you downloaded without errors for absent ones.

## License

Business Source License 1.1 (BUSL-1.1). See [LICENSE](LICENSE).

The license permits any non-production use, including security auditing and inspection. Production use is permitted alongside a paid JuLenny subscription. Three years after each release, that release converts automatically to Apache 2.0 under the Additional Use Grant in the license file.

## Security disclosures

Please report security issues privately to security@julenny.net rather than opening a public issue.
