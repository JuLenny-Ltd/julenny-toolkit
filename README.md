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

The `.deb` is self-contained: OpenFHE is statically linked into the binary, and the only runtime dependencies are standard system libraries already present on any Debian or Ubuntu install. It installs both the `julenny-toolkit` CLI and the `julenny-mcp` MCP server.

```bash
sudo dpkg -i julenny-toolkit-linux-amd64.deb
julenny-toolkit --version
```

### Windows

Download `julenny-toolkit-setup-windows-amd64.exe` from the releases page and run it. The installer lets you choose any combination of three components:

- the **JuLenny Toolkit** desktop app (graphical UI),
- the **`julenny-toolkit`** command-line tool,
- the **`julenny-mcp`** MCP server, with optional one-click wiring into Claude Desktop.

It installs per-user; no administrator rights are required. The app appears as **JuLenny Toolkit** in the Start menu.

> The installer is not yet code-signed, so Windows SmartScreen may show an "unknown publisher" prompt. Choose **More info -> Run anyway** to proceed.

## Quick start

The fastest way to see the toolkit in action is to run the end-to-end example. Each example folder represents one organization in a two-party collaboration; you can run them on two machines (one acting as the data owner, one as the data consumer) or as two shells on the same machine for local testing.

```bash
cd examples/joint-record-overlap

# On the data-owner machine:
cd acme && ./00-init.sh   # ... and follow each numbered script in order

# On the data-consumer machine:
cd beta && ./00-init.sh   # ... and follow each numbered script in order
```

Each script is small, commented, and uses only HTTPS plus this toolkit. Read them as the canonical reference for integrating the toolkit into your own pipelines.

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
