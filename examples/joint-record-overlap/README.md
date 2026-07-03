# Joint record overlap demo

End-to-end shell-script walkthrough of a two-party JuLenny collaboration. Two organizations - "Acme" (data owner) and "Beta" (data consumer) - each hold a CSV of customer records. They want to compute a privacy-preserving overlap count (how many records appear in both lists) without revealing the underlying records to each other or to the JuLenny platform. The scripts below show every step of that flow, end to end, using only the `julenny-fhe` CLI and standard Unix tools (`curl`, `jq`, `bash`).

Read these scripts as the canonical reference for integrating the toolkit into your own pipelines. Every numbered script is small, commented, and does exactly one logical step.

## Layout

```
examples/joint-record-overlap/
├── README.md                       (this file)
├── acme/                           DATA OWNER side (keysetup lead)
│   ├── _lib.sh
│   ├── run.sh                      one-command driver (dispatches to the numbered scripts)
│   ├── 00-init.sh
│   ├── 01-keysetup-1.sh            pk-share + relin-r1 + sum-r1
│   ├── 02-keysetup-2.sh            relin-r2 (after Beta's bundle 1)
│   ├── 03-finalize-keysetup.sh     combine, hash, upload final keys, sign envelope
│   ├── 04-encrypt.sh               encrypt Acme's CSV, upload as dataset
│   └── 05-release.sh               partial-decrypt + release (after Beta's run-query)
└── beta/                           DATA CONSUMER side (keysetup main)
    ├── _lib.sh
    ├── run.sh                      one-command driver (dispatches to the numbered scripts)
    ├── 00-init.sh
    ├── 01-keysetup-1.sh            joint-pk + relin-r1-continue + sum-r1-continue
    ├── 02-keysetup-2.sh            relin-r2 (after Acme's bundle 2)
    ├── 03-finalize-keysetup.sh     combine, hash, upload final keys, sign envelope
    ├── 04-encrypt.sh               encrypt Beta's CSV, upload as dataset
    ├── 05-run-query.sh             trigger function execution + poll
    └── 06-decrypt.sh               combine partials, reveal plaintext
```

Each side runs only its own folder; they never need scripts from the other side. Cross-party data (key shares, ciphertexts, partial decryptions) is exchanged through the JuLenny platform's API, not directly between the two machines.

## Prerequisites

On each machine (the Acme machine and the Beta machine, which can be the same physical host running two separate shells for testing):

- `julenny-fhe` on PATH. Either install the .deb (`sudo dpkg -i julenny-fhe-linux-amd64.deb`) or place a built binary in `~/bin` and add `~/bin` to PATH. Confirm with `julenny-fhe --version`.
- `jq` 1.6 or newer. On Debian/Ubuntu: `sudo apt-get install jq`. Or download the standalone binary from the jq releases page.
- `curl`, `xxd`, `sha256sum` - standard system tools, present on any current Debian/Ubuntu install.
- A JuLenny API key for each company, beginning with `sk_live_`. Generate one in the platform UI at `/company/api-keys`.
- A CSV file with the records that side intends to contribute, placed somewhere readable by the script user (the default the scripts prompt for is `~/data.csv`).

## Collaborations and permissions

A **collaboration** is a long-lived pairing between two organizations under a shared joint cryptographic key. A **permission** is a specific authorization within a collaboration to run one function over one pair of datasets. A single collaboration can hold many permissions — each new permission inherits the existing joint key, so the multi-round key exchange only happens once per collaboration, not per permission.

In the JuLenny web UI you'll see this as: one entry in `/company/collaborate/` per collaboration, with a list of permissions underneath each. The `Add Permission` button on a collaboration's page creates a new permission against the existing keys without re-running the key exchange.

The scripts in this folder track permissions (permissions). When you run `00-init`, it lets you pick which collaboration and which permission you're working with. If you've added a new permission to an existing collaboration, the keysetup phases auto-skip; the script jumps straight to encryption and execution.

## Platform UI prep (one-time per company, then per collaboration)

Before running any script, complete these steps in the JuLenny web UI:

| What to do | Where | Per |
|---|---|---|
| Generate an API key | `/company/api-keys` → click "Plus" → name it → copy the `sk_live_...` value immediately | each company, once |
| Create a collaboration | `/company/collaborate/new` → wizard (Partner → Function → Terms → Review). After picking a partner, if you already have a collaboration with them the wizard offers "Add to existing collaboration" which skips the key exchange. | one company creates per partner |
| Open the collaboration page | `/company/collaborate/<projectId>` | both companies open |
| Register signing public key | inline on the collaboration page above | each company, once per crypto context |
| Upload encrypted data | via `04-encrypt.sh` below (`/company/fhe-upload` works too) | each side, once per project (reused across permissions) |

The signing-key registration is the one step `00-init.sh` cannot fully automate from the command line. The script generates the keypair, stores the secret half locally, and waits while you upload the public half through the working page. After that, every step is scripted.

## One-command driver: `run.sh`

If you don't want to invoke each numbered script by hand, each side has a `run.sh` that detects where you are in the protocol and runs whatever's next. It stops cleanly whenever it needs the other side to make progress, and prints the condition it's waiting on:

```bash
# Acme machine
cd examples/joint-record-overlap/acme
./run.sh                    # runs as many phases as possible, exits at the first wait
./run.sh --watch            # polls in place instead of exiting
```

```bash
# Beta machine
cd examples/joint-record-overlap/beta
./run.sh
./run.sh --watch
```

`run.sh` simply dispatches to the numbered scripts based on detected state; nothing it does is different from what you'd do by hand. Use it for convenience; use the numbered scripts (below) when you want to learn the protocol step by step or to retry a specific phase.

## Walkthrough: running the demo (step-by-step)

The scripts alternate between sides. The two machines do not need to be online simultaneously - each side can run its scripts and walk away; the other side picks up when ready.

### 1. Initialize each side

```bash
# Acme machine
cd examples/joint-record-overlap/acme
./00-init.sh
# Upload Acme's signing public key via the platform UI when prompted, press Enter to continue.
```

```bash
# Beta machine
cd examples/joint-record-overlap/beta
./00-init.sh
# Same: upload Beta's signing public key, press Enter.
```

`00-init.sh` prompts for the API key, then lets you pick a collaboration from a numbered list (one entry per partner / joint key) and a permission within that collaboration (one entry per permission). It also asks for your input CSV path. Everything gets saved to `~/.julenny-collab/config.env` so later scripts pick it up automatically.

If you're starting a new permission under a collaboration that already has completed keys, this is also where the script learns that fact — subsequent steps will skip the keysetup phases and go straight to encryption.

### 2. Keysetup bundle 1: each side's initial contributions

```bash
# Acme
./01-keysetup-1.sh                      # uploads pk-share + relin-r1 + sum-r1
```

```bash
# Beta (after Acme's 01 finishes)
./01-keysetup-1.sh                      # downloads Acme's shares, uploads Beta's bundle 1
```

### 3. Keysetup bundle 2: each side's round-2 contributions

```bash
# Acme (after Beta's 01)
./02-keysetup-2.sh                      # uploads relin-r2
```

```bash
# Beta (after Acme's 02)
./02-keysetup-2.sh                      # uploads relin-r2
```

### 4. Finalize keysetup

Both sides can run in parallel:

```bash
# Acme
./03-finalize-keysetup.sh
```

```bash
# Beta
./03-finalize-keysetup.sh
```

Each side independently runs the deterministic combines, hashes the resulting joint keys, uploads them to platform-managed object storage, and posts a signed envelope confirming what they uploaded. The platform compares the two parties' SHA-256 hashes; once both match, the permission becomes active.

### 5. Encrypt and upload each side's data

Datasets are scoped to the collaboration (the project), not to individual permissions — so if you already uploaded a dataset under a previous permission in the same collaboration, the new permission sees it automatically. When `04-encrypt.sh` finds an existing dataset for your company, it lists what's there and asks whether to reuse or upload a fresh one. Answer `Y` (default) to skip the upload entirely; answer `n` to encrypt + upload a new dataset.

Both sides in parallel:

```bash
# Acme
./04-encrypt.sh                         # checks for existing dataset; uploads if none, prompts if any
```

```bash
# Beta
./04-encrypt.sh                         # same, for Beta's CSV
```

### 6. Execute the function

```bash
# Beta only (the data consumer triggers execution)
./05-run-query.sh                       # platform schedules the computation, polls until done
```

The script blocks until the platform reports `awaiting-release`, meaning the homomorphic computation is finished and the result ciphertext is waiting for Acme's contribution to the threshold decryption.

### 7. Release: Acme's partial decryption

```bash
# Acme only (the data owner contributes its share of the decryption)
./05-release.sh
```

### 8. Decrypt: Beta's partial + combine + reveal

```bash
# Beta only
./06-decrypt.sh                         # combines partial decryptions, prints the result
```

The plaintext - the overlap count - is printed at the end of step 8. Neither party at any point sees the other's CSV records, and the platform at no point holds key material capable of decrypting on its own.

## What `_lib.sh` provides

Both `acme/_lib.sh` and `beta/_lib.sh` are bash libraries sourced at the top of every numbered script. They expose:

- **`load_session`**: reads `~/.julenny-collab/config.env` and exposes the variables (API key, project / permission / company IDs, paths).
- **`curl_jl`**: wrapper around `curl` that adds the `x-api-key` header on every request.
- **`download_peer_share`, `wait_for_peer_share`, `peer_company_id`, `get_peer_messages`, `get_keysetup_state`**: platform-API helpers used across multiple steps.
- **`wrap_and_upload`**: signs an envelope and posts it (auto-selecting inline payload vs. object-storage upload by size) so each numbered script stays short.
- **Output helpers**: `info`, `success`, `warn`, `err`, `die`, `step`, `wait_msg`.

You never run `_lib.sh` directly. It's purely a library.

## Single-machine variant (self-test)

To run both sides on one host without setting up two machines, override the workdir per shell so each session has its own state:

```bash
# Shell 1 (Acme)
export JL_WORKDIR=$HOME/.julenny-collab-acme
cd examples/joint-record-overlap/acme
./00-init.sh
```

```bash
# Shell 2 (Beta)
export JL_WORKDIR=$HOME/.julenny-collab-beta
cd examples/joint-record-overlap/beta
./00-init.sh
```

The two shells then proceed through the numbered scripts as if they were on separate machines. Useful for end-to-end smoke-testing before deploying to a real two-machine setup.

## Pointing at a non-production deployment

By default, the scripts talk to `https://julenny.net`. To run against a staging or local platform deployment, export the base URL before running `00-init.sh` (the script will pick it up):

```bash
export JULENNY_API_BASE="https://your-staging-host"
./00-init.sh
```

`load_session` re-exports `JULENNY_API_BASE` for every subsequent script, so you only need to set it once per shell session.
