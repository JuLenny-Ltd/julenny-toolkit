# JuLenny FHE Toolkit: Examples

End-to-end, runnable demos of a two-party JuLenny FHE collaboration: two
companies jointly run a fixed function over their **encrypted** inputs, and
neither side (nor the platform) ever sees the other's plaintext. Each demo walks
the whole lifecycle (joint key setup, encryption, the platform compute, and
multi-party threshold decryption) using the `julenny-toolkit` CLI.

## The two parties

Every scenario has two sides, run on two separate machines (or two shells):

| folder | party | platform role | keysetup role |
|---|---|---|---|
| `acme/` | data owner | dataOwner | lead |
| `beta/` | data consumer | queryAnalyst | main |

"Acme" and "Beta" are just demo names. The data owner holds the data being
queried; the data consumer triggers the execution and (by default) sees the
result. Each side keeps its own secret key share locally and never transmits it.

## Layout

```
examples/
  _core/                     Shared driver backing every scenario (below)
  rule-based-cross-match/    Thin scenario: acme/ + beta/ + data + README
  federated-average/         Thin scenario
  negotiation-matrix/        Thin scenario
  decision-tree-inference/   Thin scenario
  joint-record-overlap/      Thin scenario
```

### `_core/`: the shared driver

One implementation backs both sides of every scenario. The side-specific bits
(labels, API view, secret-share filename, role) come from a profile in
`_core/sides/` that's sourced before the shared library.

```
_core/
  run.sh   / run.ps1     One-command driver: menu -> runs the phases in order
  lib.sh   / lib.ps1     Shared helper library (API calls, keysetup, encrypt,
                         release/decrypt dispatch, collaboration creation)
  sides/
    data-owner.env    / .ps1    Profile for the Acme/lead side
    data-consumer.env / .ps1    Profile for the Beta/main side
  lead/                  Data-owner phase scripts (00-init .. 05-release)
  main/                  Data-consumer phase scripts (00-init .. 06-decrypt)
  recipe/                Node helpers for encodingRecipe inputs (shared)
```

Each script has a `.sh` and a `.ps1` form. They are twins: same phases, same
round numbers, same message types, same `config.env` format, so a Linux machine
and a Windows machine can be the two sides of one collaboration.

### Scenario folders: thin bootstraps

Each scenario's `acme/` and `beta/` driver just selects the side and the
scenario's `data/` directory, then hands off to the one in `_core/`. The actual
function (and its count/itemized variant) is chosen interactively at init time,
so one scenario folder can run any function of its family. Each scenario also
carries a `README.md` with its sample data and the hand-verifiable expected
result.

Every scenario is a thin bootstrap over `_core`. There is no per-scenario copy of
the driver, so a fix to the protocol lands in one place for all of them.

## Running a demo

On each party's machine, from that party's side folder.

**Linux:**

```bash
cd examples/<scenario>/acme   # data owner, on Acme's machine
./run.sh

cd examples/<scenario>/beta   # data consumer, on Beta's machine
./run.sh
```

**Windows:**

```powershell
cd examples\<scenario>\acme   # data owner
.\run.ps1

cd examples\<scenario>\beta   # data consumer
.\run.ps1
```

Every script exists in both forms and they do the same work, so the two sides of
a collaboration can be on different operating systems. The installer copies only
the set your machine can run, so you will see `.sh` **or** `.ps1`, not both.

The driver (`run.sh` / `run.ps1`) is menu-driven. The first time it walks you through picking (or
creating) a collaboration and permission, registering your signing key, and
fetching the function definition; on later runs it offers to continue, start a
new test cycle, switch collaboration/permission, or just decrypt the latest
result. "Watch mode" polls the platform and waits at each step that depends on
the other side, so the two operators don't have to hand-synchronize.

Typically run the data owner first (it sets up and then waits to release), then
the data consumer (it encrypts, triggers the execution, and decrypts).

### The phases (numbered scripts)

The driver runs these in order; you can also run them individually. Each exists as `.sh` and `.ps1`.

| phase | script | what it does |
|---|---|---|
| 0 | `00-init` | Pick/create collaboration + permission, register signing key, fetch the function definition |
| 1-2 | `01-keysetup-1`, `02-keysetup-2` | Multi-party joint key generation (skipped if the collaboration's key is already complete) |
| 3 | `03-finalize-keysetup` | Submit/confirm the finalized joint keys |
| 4 | `04-encrypt` | Encode and upload this side's input dataset(s) |
| 4.5 | `04.5-rotation-keysetup` | Rotation-key augmentation, only if the function declares rotation in `requiredEvalKeys`; otherwise a no-op |
| 5 | `05-release` (lead) / `05-run-query` (main) | Owner releases its partial decrypt; consumer triggers the execution |
| 6 | `06-decrypt` (main) | Combine both partial decryptions and reveal the plaintext answer |

## Scenarios

| scenario | functions | scheme | engines | demonstrates |
|---|---|---|---|---|
| `rule-based-cross-match` | `-count`, `-itemized` | CKKS | CPU, GPU | how many / which entries of a shared rule list both private datasets match |
| `federated-average` | `federated-average` | CKKS | CPU | privately average two parties' ML model weight vectors (data-size weighted) |
| `negotiation-matrix` | `-count`, `-itemized` | CKKS | CPU, GPU | how many / which contract-term combinations both sides accept |
| `decision-tree-inference` | `decision-tree-inference` | CKKS | CPU | score one party's private feature vector against the other party's private decision tree |
| `joint-record-overlap` | `-count`, `-itemized` | BFV | CPU | how many / which records two parties have in common |

The `-count` variants return a single number; the `-itemized` variants return
which positions matched. See each scenario's `README.md` for the sample inputs
and the exact expected output.

## For AI agents (MCP)

These scripts double as a reference corpus for AI agents. The JuLenny MCP server
(in [`../mcp`](../mcp)) exposes the same collaboration flow as tools, and it
drives the `julenny-toolkit` CLI with the same commands and flags these scripts use.
An agent can read this folder to learn the exact phase sequence and arguments,
then run the pipeline through the MCP tools. The crypto still happens locally
via the CLI, so keys and plaintext never leave the user's machine. Keeping the
examples and the MCP tools in lockstep is intentional: they are both the human
quick-start and the agent's map.

## Prerequisites

On each party's machine:

- The `julenny-toolkit` CLI on your `PATH` (installed from a release, or built from
  this repo). Confirm with `julenny-toolkit --version`.
- **Linux only:** `jq` 1.6 or newer, plus `curl`, `xxd` and `sha256sum`. The last
  two are standard on any current Debian/Ubuntu install; the `.deb` declares the
  rest as dependencies, so `apt install ./julenny-toolkit-linux-amd64.deb` pulls
  them in.
- **Windows:** nothing extra. The PowerShell scripts use built-in cmdlets for
  everything the bash ones shell out to, so there is no `jq` or `curl` to
  install, and no WSL. Windows PowerShell 5.1 (preinstalled) is enough.
- `node`, on both platforms, but only for scenarios whose function declares an
  `encodingRecipe` (currently `decision-tree-inference`). The scripts fail with a
  clear message if it is needed and missing.
- A platform API key (`sk_live_...`) for your company account.
- Your partner's collaboration ID (`XXXX-XXXX`) if you're creating a new
  collaboration.

Per-collaboration state (config, key shares, downloaded artifacts) lives under
`~/.julenny-collab/`. Your secret key share never leaves your machine.

## Platform UI prep

A few steps happen in the JuLenny web UI rather than in the scripts:

| What | Where | How often |
|---|---|---|
| Generate an API key | `/company/api-keys` | once per company |
| Create a collaboration | `/company/collaborate/new`, or let `00-init` create one | once per partner (reused by later permissions) |
| Register your signing public key | inline on the collaboration page | once per company, per crypto context |

Signing-key registration is the one step `00-init` cannot fully automate. It
generates the keypair and keeps the secret half locally, then waits while you
upload the public half through the UI. Everything after that is scripted.

## Running both sides on one machine

This is a **two-party** collaboration with both organizations driven from one host, which
needs two accounts. It is not the platform's solo self-test (an internal permission for a
single organization); see the main README for that.

To drive both sides on one host, give each shell its own state root. Override
`JL_ROOT`, not `JL_WORKDIR`: `JL_WORKDIR` is derived per collaboration and gets
overwritten as soon as a joint key is selected.

```bash
# Shell 1 (data owner)
export JL_ROOT=$HOME/.julenny-collab-acme
cd examples/<scenario>/acme && ./run.sh
```

```bash
# Shell 2 (data consumer)
export JL_ROOT=$HOME/.julenny-collab-beta
cd examples/<scenario>/beta && ./run.sh
```

On Windows:

```powershell
# Shell 1 (data owner)
$env:JL_ROOT = "$env:USERPROFILE\.julenny-collab-acme"
cd examples\<scenario>\acme; .\run.ps1
```

```powershell
# Shell 2 (data consumer)
$env:JL_ROOT = "$env:USERPROFILE\.julenny-collab-beta"
cd examples\<scenario>\beta; .\run.ps1
```

The two shells then behave as if they were separate machines. Useful for
smoke-testing before setting up a real two-machine run.

## Pointing at a non-production deployment

The scripts default to `https://julenny.net`. Export a different base URL before
running `00-init` and it is picked up and persisted for the session:

```bash
export JULENNY_API_BASE="https://your-staging-host"
```
