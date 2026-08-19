# Running a self-test on any function

A self-test is one organization running a function against its own data, with no
partner. The platform calls this an **internal permission**. You play both sides:
the toolkit generates two key shares locally, you provide both inputs, the platform
computes on ciphertext, and you decrypt the answer yourself.

Every function ships sample data with a **known answer**, listed below. That matters
more than it sounds. A self-test that merely completes tells you the pipeline ran; it
does not tell you the result is *correct*. Partial data corruption produces a run that
succeeds and returns a plausible-but-wrong number, and without a reference answer there
is no way to tell the two apart. Check your result against the expected value here.

If the numbers match, the whole chain is verified end to end: encoding, the joint keys,
the platform's circuit, and threshold decryption.

## Which functions need which keys

A self-test has to build every evaluation key itself, because there is no partner to
exchange rounds with. How much work that is depends on the function. Start at the top.

| Function | Scheme | Evaluation keys | Solo effort |
|---|---|---|---|
| `federated-average` | CKKS | none | lowest - no evaluation keys at all |
| `joint-record-overlap-itemized` | BFV | relinearization | one key protocol |
| `negotiation-matrix-itemized` | CKKS | relinearization | one key protocol |
| `decision-tree-inference` | CKKS | relinearization | one key protocol |
| `joint-record-overlap-count` | BFV | relinearization, sum | two key protocols |
| `negotiation-matrix-count` | CKKS | relinearization, sum | two key protocols |
| `rule-based-cross-match-count` | CKKS | relinearization, sum, rotation | three, plus rotation indices |
| `rule-based-cross-match-itemized` | CKKS | relinearization, sum, rotation | three, plus rotation indices |

Every context runs at **128-bit classical security** (`HEStd_128_classic`), whichever
function you pick: `bfv-default-v1` (16,384 slots), `ckks-default-v1` (8,192 slots) and
`ckks-tree-v1` (32,768 slots, deeper for decision trees).

Read `requiredEvalKeys` off the signed function definition rather than this table when
you automate anything: the definition is authoritative, and **building a key the
definition does not ask for is as wrong as skipping one it does**.

The trap worth repeating: an internal permission reports its keysetup COMPLETE at
creation while holding **no keys**. The maths still needs them. Any function that
multiplies two ciphertexts needs a relinearization key, and if it is missing the run
fails *inside the engine* after a credit has already been spent. Only
`federated-average` is exempt, because it never multiplies two ciphertexts.

## Expected answers

All paths are relative to `examples/`. Both sides' data is yours in a self-test, so
"acme" and "beta" here are just the two roles, not two companies.

### `federated-average`

| Input | File |
|---|---|
| `weights_a` | `federated-average/acme/data/acme_model_weights.txt` |
| `weights_b` | `federated-average/beta/data/beta_model_weights.txt` |
| `scale_a` | `federated-average/beta/data/scale_a.txt` (`0.8`) |
| `scale_b` | `federated-average/beta/data/scale_b.txt` (`0.2`) |

Sixteen weights per side. The result is the elementwise weighted mean,
`scale_a x weights_a + scale_b x weights_b`:

```
0.77, -0.34, 0.14, 1.19, -0.65, 0.44, 0.07, -1.06,
0.69, 0.12, -0.37, 0.94, 0.39, -0.56, 0.19, 0.66
```

CKKS is approximate, so expect small deviations in the last decimals. Anything
agreeing to about four decimal places is a pass. This is the only function whose
answer you can check with a calculator, which makes it the best first self-test.

### `joint-record-overlap-count` and `-itemized`

`dataset_a` is `joint-record-overlap/acme/data/acme-customers.csv` (76 records).
Pick any of three files for `dataset_b`; the name states the answer.

| `dataset_b` | Records | Expected count | Expected records (itemized) |
|---|---|---|---|
| `beta/data/beta-0match.csv` | 2 | `0` | none |
| `beta/data/beta-1match.csv` | 1 | `1` | `Sophia Martinez,1990-07-22` |
| `beta/data/beta-2match.csv` | 2 | `2` | `Amelia White,1989-03-21`, `Sophia Martinez,1990-07-22` |

Both CSVs need a header row: the definition sets `skipHeader`, so the first line is
always discarded. Records are hashed into slots, so expected false matches are roughly
`(rows_a x rows_b) / slots`. There are never false negatives.

The `-itemized` variant returns which of *your own* records matched, resolved locally
by re-hashing your CSV. `resolve_matches` reports matched rows and distinct records
separately: if your file lists the same record twice, both rows are reported and both
are genuine, which is not the same thing as a false positive.

**Do not edit these CSVs in a spreadsheet.** Excel silently rewrites dates, strips
leading zeros from identifiers, and changes quoting. Every one of those changes the
record's hash, so it stops matching the other side and the overlap comes back thin
with nothing flagged.

### `negotiation-matrix-count` and `-itemized`

| Input | File |
|---|---|
| `acceptance_matrix` | `negotiation-matrix/acme/data/acceptance_matrix.txt` |
| `offer_vector` | `negotiation-matrix/beta/data/offer_vector.txt` |

Both are 24 positions, one `0` or `1` per line, where the slot is the line position.
Both sides must enumerate the term grid identically.

| `offer_vector` | Expected count | Expected positions (itemized) |
|---|---|---|
| `offer_vector.txt` | `1` | position `16` |
| `offer_vector_nomatch.txt` | `0` | none |

Run the no-match file too. A function that returns a plausible answer for overlapping
data but cannot return a clean zero is not actually working.

### `rule-based-cross-match-count` and `-itemized`

| Input | File | Owner |
|---|---|---|
| `rule_pairs` | `rule-based-cross-match/beta/data/restriction_ingredient_pairs.txt` | queryAnalyst, **plaintext** |
| `left_indicator` | `rule-based-cross-match/beta/data/beta_restrictions.txt` | queryAnalyst |
| `right_indicator` | `rule-based-cross-match/acme/data/acme_ingredients.txt` | dataOwner |

77 rule pairs, 3 restrictions, 3 ingredients. A pair counts when its left name is in
the restriction list *and* its right name is in the ingredient list.

**Expected count: `1`** - `peanut allergy,peanuts`. It is the only pair whose both
halves are present.

`rule_pairs` is a plaintext input, uploaded as-is: it defines the question, not the
data. Upload it as **plaintext** (`kind=plaintext`), not as ciphertext, or declaring it
fails with `Input "rule_pairs" expects plaintext data, but dataset ... is encrypted`. The
same applies to `scale_a` and `scale_b` on federated-average.

The rule list also drives the rotation index set, so `crypto derive-rotation-indices`
must be run over the same file before the rotation keys are built. Declaring it is what
tells the platform which indices to expect, so declare it BEFORE building rotation keys.

### `decision-tree-inference`

| Input | File | Owner |
|---|---|---|
| `model` | `decision-tree-inference/golden/tree.json` | queryAnalyst |
| `features` | `decision-tree-inference/acme/data/features.json` | dataOwner |

Height-2 tree, 2 features, 2 classes, soft-if degree 16, already normalized to
`[-1, 1]`. Sample `x = [0.6, 0.7]`.

**Expected prediction: `[0.167801, 0.832199]`**, so `argmax` is class `1`.

Both inputs are encrypted bundles built by `encode_recipe` from the cleartext JSON;
they are not single ciphertexts. Use `features.json`, not `golden/features.txt` - the
`.txt` is a human-readable copy with comment lines, and the recipe parses JSON, so it
fails on the leading `#`. Both files describe the same sample. Features and thresholds must both be scaled to
`[-1, 1]` with the same parameters, because the soft-if polynomial only approximates
a step function on that range and diverges outside it.

## When the answer is wrong

A mismatch is informative, not just a failure:

- **Zero when you expected a match** - the two sides encoded differently. Check that
  both files went through the same schema, the header handling matches, and that
  nothing rewrote one file's formatting.
- **A number in the right shape but wrong** - usually a key problem. The commonest
  cause is registering a round-1 contribution as the final relinearization key: the
  platform accepts it, the run succeeds, and the answer is garbage.
- **Right on `federated-average`, wrong elsewhere** - points at the evaluation keys
  rather than the joint key, since federated-average is the one function that needs
  none.
- **Small deviations in the last decimals on any CKKS function** - expected. That is
  approximate arithmetic, not an error.

## Afterwards

Your two secret shares and your signing secret are left in the working folder.
Together the shares reconstruct the joint key, so delete them when a throwaway test
is finished.
