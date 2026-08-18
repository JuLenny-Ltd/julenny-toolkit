# Security Policy

## Reporting a vulnerability

Please report security issues privately to **security@julenny.net** rather than opening a public issue.

Include enough detail to reproduce the problem: affected component (`core`, `cli`, `mcp`, the desktop app, or the platform API), version or commit, and the steps you took. If you have a proof of concept, please attach it.

We aim to acknowledge a report within two business days and to keep you informed while we investigate. If you would like credit in the fix announcement, say so and tell us how you would like to be named.

Please do not disclose publicly until we have had a reasonable opportunity to release a fix.

## Scope

This repository is the **customer-side toolkit**: the offline cryptographic core, the CLI, the MCP server, the desktop app, and the example scripts. Issues in any of those are in scope, and we are particularly interested in:

- anything that could cause secret key material or plaintext to leave the local machine
- anything that could cause the MCP server to return plaintext, secret bytes, or a decrypted result to a calling agent
- weaknesses in the threshold key-generation or partial-decryption protocol as implemented here
- signature verification flaws in the function-definition or key-exchange envelopes

The JuLenny platform API is operated separately from this repository. Reports about it are equally welcome at the same address.

## What this toolkit is designed to guarantee

The platform is built so that the service running the computation can never decrypt anything. Secret key shares stay on participating organisations' machines, and the platform sees only ciphertext. Two properties are worth verifying directly, and we would treat a counter-example as a serious vulnerability:

- **The cryptographic core makes no network calls.** `core/` and `cli/` contain no sockets, HTTP clients, or any networking API.
- **The MCP server is blind.** It shells out to the CLI for every cryptographic operation and returns file paths and status only, never plaintext or key bytes.

## Supported versions

Security fixes are issued for the latest release. Older releases are not patched; upgrade to the current version, which is published on the [releases page](https://github.com/JuLenny-Ltd/julenny-toolkit/releases).
