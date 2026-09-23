# JuLenny FHE Toolkit: Scripts

End-to-end, runnable demonstrations of a two-party JuLenny FHE collaboration: two
companies jointly run a fixed function over their **encrypted** inputs, and neither
side (nor the platform) ever sees the other's plaintext. They walk the whole
lifecycle - joint key setup, encryption, the platform compute, and multi-party
threshold decryption - using the `julenny-toolkit` CLI and nothing else but HTTPS.

## One command, both sides, every scenario

```bash
./run.sh          # Linux
```
```powershell
.\run.ps1         # Windows
```

That is the whole interface. Run the same thing on both machines. It asks nothing
that the platform already knows: **pick a permission at the first prompt** and that
one choice settles four things.

| what | where it comes from |
|---|---|
| the **function** | pinned on the permission, `-count` or `-itemized` included |
| the **scenario** | the function's family, which selects the sample data |
| your **data role** | the permission's `yourRole`: data owner or data consumer |
| your **keysetup role** | the joint key: lead or main. A *separate* question. |

There used to be ten entry points, a folder per scenario times a folder per side,
and choosing among them was how you declared all four. Every one of those
declarations was a chance to contradict the platform, and a contradiction about the
keysetup role does not fail loudly: it produces the wrong partial decryption and a
wrong answer.

### Two roles, not one

A party has **two** roles in a collaboration, and they are independent:

- the **data role** (owner or consumer) is per PERMISSION. It says whose data goes
  in and who triggers the run.
- the **keysetup role** (lead or main) is per JOINT KEY, fixed once when that key is
  built. It says which half of the key ceremony this machine performs.

They agree in the common case, which is why the phase scripts used to live in
`lead/` and `main/` folders picked by the data role. They stop agreeing as soon as a
collaboration holds a permission created in the other direction, and the folder
layout was then actively wrong: it ran the wrong half of the ceremony, against key
material stored under the other half's filename.

So each phase reads the role that actually governs it: keysetup role for `01`, `02`,
`03` and `04.5`; data role for `00-init` and `04-encrypt`; the permission's
`resultVisibility` for `06-end-of-cycle`. Both roles are read from the platform,
never remembered as a choice.

"Acme" and "Beta" are just demo names for the two parties. Each side keeps its own
secret key share locally and never transmits it.

## Layout

```
scripts/
  run.sh / run.ps1   The entry point. Both sides, every scenario.
  _core/             The driver and the numbered phase scripts (below)
  samples/           Sample data, by scenario and side. INSTALLED INTO THE
                     WORKING FOLDER, not read from here (below).
  README.md          This file: every scenario, its data and its answer.
  SELF-TEST.md       The solo self-test, a different thing (see below).
```

### Sample data lives in the working folder

The installer copies `samples/` to `<workdir>/samples/<scenario>/<side>/`, and that
is the copy the scripts read:

```
<workdir>/samples/joint-record-overlap/data-owner/acme-customers.csv
<workdir>/samples/joint-record-overlap/data-consumer/beta-1match.csv
```

One copy, in the folder the Claude connector also works in, so both surfaces see the
same bytes. It used to sit beside the scripts as a second copy, which is how a stale
fixture came to be run against a fresh one and returned a correct-looking zero.

Reinstalling restores the shipped samples, so an edited one is never stuck. Set
`JL_DATA_DIR` to point the file picker somewhere else entirely.

## The five scenarios

Every one of them runs through the same `./run.sh`. The scenario is not something
you select: it follows from the function your permission pins.

| scenario | functions | scheme | engines | what it computes |
|---|---|---|---|---|
| `joint-record-overlap` | `-count`, `-itemized` | BFV | CPU | how many / which records two parties have in common |
| `rule-based-cross-match` | `-count`, `-itemized` | CKKS | CPU, GPU | how many / which entries of a shared rule list both private datasets match |
| `negotiation-matrix` | `-count`, `-itemized` | CKKS | CPU, GPU | how many / which contract-term combinations both sides accept |
| `federated-average` | `federated-average` | CKKS | CPU | privately average two parties' ML model weight vectors, data-size weighted |
| `decision-tree-inference` | `decision-tree-inference` | CKKS | CPU | score one party's private feature vector against the other party's private decision tree |

Each section below gives the sample data and the answer you should get, so you can
confirm a run end to end by hand.

---

### joint-record-overlap (BFV)

Two organizations each hold a list of customer records and want to know how many
they have in common. **BFV is exact-integer arithmetic**, so there is no
approximation and no thresholding at decrypt: a match is exactly 1, a non-match
exactly 0.

Each row is `name,dob`, and **both fields together** form the matching key.

Data owner: `data-owner/acme-customers.csv`, 75 customer records.
Data consumer: three alternative files, so the same collaboration gives three
different predictable answers.

| consumer file | contents | count | itemized |
|---|---|---|---|
| `beta-0match.csv` | Daniel Klein (1990-07-22), Emma Raffles (1980-03-21) | **0** | all zeros |
| `beta-1match.csv` | Sophia Martinez (1990-07-22) | **1** | 1 at index 0 |
| `beta-2match.csv` | Sophia Martinez (1990-07-22), Amelia White (1989-03-21) | **2** | 1 at indices 0 and 1 |

`beta-0match.csv` is the interesting one. Daniel Klein carries **exactly** Sophia
Martinez's date of birth under a different name, and Emma Raffles carries a date
close to Amelia White's. An implementation matching on date of birth alone would
report a false match; the correct answer is 0. Use this file to confirm the overlap
really is computed over the joined record.

To run it again with a different file, choose "start a NEW test cycle" and pick
another `beta-*.csv` at the encrypt step. The keysetup is reused.

---

### rule-based-cross-match (CKKS)

Each side holds a private indicator over a shared name space; the platform counts
how many entries from a rule list are matched on both sides.

- `rule_pairs` (consumer): a plaintext CSV of the rule list, uploaded raw.
- `left_indicator` (consumer) and `right_indicator` (owner): each side's private
  membership, encrypted.

The encrypted indicators use `indicator-binary` encoding: each name maps to a slot
via an FNV-1a hash (`slot = fnv1a_64(name) % slotCount`), pinned identically on both
sides, so no shared dictionary is ever exchanged.

This is the scenario that needs **rotation keys**, so phase 4.5 does real work here.
The rotation index set is derived by the platform from the bound plaintext data, and
phase 4.5 re-derives it locally and refuses to continue if the two disagree.

---

### negotiation-matrix (CKKS)

A buyer and a supplier privately discover whether their contract terms overlap, and
on which exact combinations. Each side encrypts a binary indicator vector over a
shared grid; the platform multiplies them element-wise, so a slot is 1 only where
BOTH put a 1.

- Buyer (`data-owner/acceptance_matrix.txt`): Quantity=5000, Price 12..14,
  Delivery 1-2 weeks, giving 1s at indices **{12,13,15,16,18,19}**.
- Supplier (`data-consumer/offer_vector.txt`): exactly Quantity=5000, Price=13,
  Delivery=2 weeks, a 1 at index **16**.

The product is 1 only at index 16, so the matched deal is **5000 units, $13, 2
weeks**: `-count` gives **1**, `-itemized` gives ~1.0 at index 16 and ~0.0 elsewhere.

`data-consumer/offer_vector_nomatch.txt` offers Price=15 / Delivery=3 weeks, index
23, which the buyer does not accept: count 0 and an all-zero match vector.

---

### federated-average (CKKS)

Two parties privately combine locally-trained model weights into one global model:

    global_weights = scale_a * weights_a + scale_b * weights_b

A linear circuit only: no ciphertext-ciphertext multiplication, no rotations, no
evaluation keys at all, so phases 02 and 4.5 do nothing.

Both parties trained the same 16-parameter fraud-detection model on their own
customers. The owner trained on 8,000 records and the consumer on 2,000, so the
data-size-weighted scales are `0.8` and `0.2` (the two `scale_*.txt` files, uploaded
as plaintext). Weight files are one float per line, 16 lines each.

Expected `global_weights`, first 16 slots, up to CKKS noise of about 1e-6:

```
 0.77  -0.34   0.14   1.19  -0.65   0.44   0.07  -1.06
 0.69   0.12  -0.37   0.94   0.39  -0.56   0.19   0.66
```

Remaining slots ~0.

---

### decision-tree-inference (CKKS)

One party scores its private feature vector against the other party's private
decision tree. This is the scenario where **both** sides' secrets are structural:
the owner contributes `features`, the consumer contributes the tree itself. In every
other scenario the "model" is a public function; here it is ciphertext. It runs on
its own crypto context, `ckks-tree-v1`.

- Owner (`data-owner/features.json`): `x = [0.6, 0.7]`.
- Consumer (`data-consumer/tree.json`): the tree.

Expected decrypted prediction **`[0.167801, 0.832199]`**, so `argmax = class 1`.

By hand, with hard comparisons: `f0 = 0.6` is not `< 0.0` so go right, then
`f1 = 0.7` is not `< 0.4` so go right again, landing on leaf `[0.05, 0.95]`. The
soft-if output is a smoothed version of that leaf, pulled toward the other leaves in
proportion to how close each comparison ran to its threshold. Class 1 wins either
way.

Two encodings of the same `x` ship, and they are not interchangeable:

- `features.json` feeds the function's **`encodingRecipe`**, which maps over the
  array and emits one broadcast ciphertext per feature. This is the current path,
  and the one to use. It needs `node` on the owner's machine.
- `features.txt` is the flat one-value-per-line form, for encrypting directly with
  `julenny-toolkit crypto encrypt --schema packed-real`.

---

### `_core/`: the shared driver

One implementation backs both sides of every scenario. There is ONE numbered set of
phase scripts, and each phase branches internally on whichever role governs it. The
side-specific bits (labels, API view, default secret-share filename) come from a
profile in `_core/sides/`, which the shared library loads for you.

```
_core/
  driver.sh / driver.ps1  The menu-driven driver: runs the phases in order.
                          ../run.sh is a one-line wrapper over it.
  lib.sh    / lib.ps1     Shared helper library (API calls, keysetup, encrypt,
                          release/decrypt dispatch, collaboration creation)
  00-init .. 06-end-of-cycle    The numbered phase scripts. One set, both sides.
  sides/
    data-owner.env    / .ps1    Profile for the data-owner side
    data-consumer.env / .ps1    Profile for the data-consumer side
  recipe/                 Node helpers for encodingRecipe inputs (shared)
```

Each script has a `.sh` and a `.ps1` form. They are twins: same phases, same
round numbers, same message types, same `config.env` format, so a Linux machine
and a Windows machine can be the two sides of one collaboration.

### The phases (numbered scripts)

The driver runs these in order; you can also run them individually. Each exists as `.sh` and `.ps1`.

| phase | script | what it does |
|---|---|---|
| 0 | `00-init` | Pick/create collaboration + permission, register signing key, fetch the function definition |
| 1-2 | `01-keysetup-1`, `02-keysetup-2` | Multi-party joint key generation (skipped if the collaboration's key is already complete) |
| 3 | `03-finalize-keysetup` | Submit/confirm the finalized joint keys |
| 4 | `04-encrypt` | Encode and upload this side's input dataset(s) |
| 4.5 | `04.5-rotation-keysetup` | Rotation-key augmentation, only if the function declares rotation in `requiredEvalKeys`; otherwise a no-op |
| 5 | `05-run-query` (data consumer only) | Trigger the execution |
| 6 | `06-end-of-cycle` (both sides) | This machine's part in revealing the answer. The viewer combines both partial decryptions and sees the plaintext; the releaser contributes its partial and never does. Which one you are comes from the permission's `resultVisibility`. |

## For AI agents (MCP)

These scripts double as a reference corpus for AI agents. The JuLenny MCP server
(in [`../mcp`](../mcp)) exposes the same collaboration flow as tools, and it
drives the `julenny-toolkit` CLI with the same commands and flags these scripts use.
An agent can read this folder to learn the exact phase sequence and arguments,
then run the pipeline through the MCP tools. The crypto still happens locally
via the CLI, so keys and plaintext never leave the user's machine. Keeping the
scripts and the MCP tools in lockstep is intentional: they are both the human
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

Per-collaboration state (config, key shares, downloaded artifacts) lives in your
working folder, under `collabs/<jointKeyId>/`. That folder is `~/julenny-workdir`
(`%USERPROFILE%\julenny-workdir` on Windows) unless you chose another one when you
installed, and it is **the same folder the connector uses**, so a collaboration can
be started here and continued from Claude. Your secret key share never leaves your
machine.

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

Each root needs its own copy of the sample data, because the samples live under the
root (`$JL_ROOT/samples/`). Copy them once per root before you start:

```bash
cp -R scripts/samples $HOME/julenny-workdir-acme/samples
cp -R scripts/samples $HOME/julenny-workdir-beta/samples
```

The two shells then run the SAME command. Neither names a side; each picks its own
permission, and that is what makes one the owner and the other the consumer.

```bash
# Shell 1
export JL_ROOT=$HOME/julenny-workdir-acme
cd ~/julenny-scripts && ./run.sh
```

```bash
# Shell 2
export JL_ROOT=$HOME/julenny-workdir-beta
cd ~/julenny-scripts && ./run.sh
```

On Windows:

```powershell
$scripts = "$env:USERPROFILE\Documents\julenny-scripts"
Copy-Item -Recurse "$scripts\samples" "$env:USERPROFILE\julenny-workdir-acme\samples"
Copy-Item -Recurse "$scripts\samples" "$env:USERPROFILE\julenny-workdir-beta\samples"
```

```powershell
# Shell 1
$env:JL_ROOT = "$env:USERPROFILE\julenny-workdir-acme"
cd "$env:USERPROFILE\Documents\julenny-scripts"; .\run.ps1
```

```powershell
# Shell 2
$env:JL_ROOT = "$env:USERPROFILE\julenny-workdir-beta"
cd "$env:USERPROFILE\Documents\julenny-scripts"; .\run.ps1
```

The two shells then behave as if they were separate machines. Useful for
smoke-testing before setting up a real two-machine run.

## Pointing at a non-production deployment

The scripts default to `https://julenny.net`. Export a different base URL before
running `00-init` and it is picked up and persisted for the session:

```bash
export JULENNY_API_BASE="https://your-staging-host"
```
