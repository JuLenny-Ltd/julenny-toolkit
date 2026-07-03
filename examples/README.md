# JuLenny FHE Toolkit — Examples

End-to-end, runnable demos of a two-party JuLenny FHE collaboration: two
companies jointly run a fixed function over their **encrypted** inputs, and
neither side (nor the platform) ever sees the other's plaintext. Each demo walks
the whole lifecycle — joint key setup, encryption, the platform compute, and
multi-party threshold decryption — using the `julenny-fhe` CLI.

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
  joint-record-overlap/      Older self-contained scenario (full scripts per side)
```

### `_core/` — the shared driver

One implementation backs both sides of every scenario. The side-specific bits
(labels, API view, secret-share filename, role) come from a profile in
`_core/sides/` that's sourced before the shared library.

```
_core/
  run.sh                 One-command driver: menu -> runs the phases in order
  lib.sh                 Shared helper library (API calls, keysetup, encrypt,
                         release/decrypt dispatch, collaboration creation)
  sides/
    data-owner.env       Profile for the Acme/lead side
    data-consumer.env    Profile for the Beta/main side
  lead/                  Data-owner phase scripts (00-init .. 05-release)
  main/                  Data-consumer phase scripts (00-init .. 06-decrypt)
```

### Scenario folders — thin bootstraps

Each scenario's `acme/run.sh` and `beta/run.sh` just select the side and the
scenario's `data/` directory, then hand off to `_core/run.sh`. The actual
function (and its count/itemized variant) is chosen interactively at init time,
so one scenario folder can run any function of its family. Each scenario also
carries a `README.md` with its sample data and the hand-verifiable expected
result.

(`joint-record-overlap/` predates the `_core` refactor and still ships the full
numbered scripts per side. It works the same way; it just isn't a thin
bootstrap.)

## Running a demo

On each party's machine, from that party's side folder:

```bash
cd examples/<scenario>/acme   # data owner, on Acme's machine
./run.sh

cd examples/<scenario>/beta   # data consumer, on Beta's machine
./run.sh
```

`run.sh` is menu-driven. The first time it walks you through picking (or
creating) a collaboration and permission, registering your signing key, and
fetching the function definition; on later runs it offers to continue, start a
new test cycle, switch collaboration/permission, or just decrypt the latest
result. "Watch mode" polls the platform and waits at each step that depends on
the other side, so the two operators don't have to hand-synchronize.

Typically run the data owner first (it sets up and then waits to release), then
the data consumer (it encrypts, triggers the execution, and decrypts).

### The phases (numbered scripts)

`run.sh` runs these in order; you can also run them individually.

| phase | script | what it does |
|---|---|---|
| 0 | `00-init` | Pick/create collaboration + permission, register signing key, fetch the function definition |
| 1-2 | `01-keysetup-1`, `02-keysetup-2` | Multi-party joint key generation (skipped if the collaboration's key is already complete) |
| 3 | `03-finalize-keysetup` | Submit/confirm the finalized joint keys |
| 4 | `04-encrypt` | Encode and upload this side's input dataset(s) |
| 4.5 | `04.5-rotation-keysetup` | Rotation-key augmentation — only if the function declares rotation in `requiredEvalKeys`; otherwise a no-op |
| 5 | `05-release` (lead) / `05-run-query` (main) | Owner releases its partial decrypt; consumer triggers the execution |
| 6 | `06-decrypt` (main) | Combine both partial decryptions and reveal the plaintext answer |

## Scenarios

| scenario | functions | scheme | engines | demonstrates |
|---|---|---|---|---|
| `rule-based-cross-match` | `-count`, `-itemized` | CKKS | CPU, GPU | how many / which entries of a shared rule list both private datasets match |
| `federated-average` | `federated-average` | CKKS | CPU | privately average two parties' ML model weight vectors (data-size weighted) |
| `negotiation-matrix` | `-count`, `-itemized` | CKKS | CPU, GPU | how many / which contract-term combinations both sides accept |
| `joint-record-overlap` | `-count`, `-itemized` | BFV | CPU | how many / which records two parties have in common |

The `-count` variants return a single number; the `-itemized` variants return
which positions matched. See each scenario's `README.md` for the sample inputs
and the exact expected output.

## For AI agents (MCP)

These scripts double as a reference corpus for AI agents. The JuLenny MCP server
(in [`../mcp`](../mcp)) exposes the same collaboration flow as tools, and it
drives the `julenny-fhe` CLI with the same commands and flags these scripts use.
An agent can read this folder to learn the exact phase sequence and arguments,
then run the pipeline through the MCP tools — the crypto still happens locally
via the CLI, so keys and plaintext never leave the user's machine. Keeping the
examples and the MCP tools in lockstep is intentional: they are both the human
quick-start and the agent's map.

## Prerequisites

- The `julenny-fhe` CLI on your `PATH` (built from this repo, or installed from a
  release).
- A platform API key (`sk_live_...`) for your company account.
- Your partner's collaboration ID (`XXXX-XXXX`) if you're creating a new
  collaboration.

Per-collaboration state (config, key shares, downloaded artifacts) lives under
`~/.julenny-collab/`. Your secret key share never leaves your machine.
