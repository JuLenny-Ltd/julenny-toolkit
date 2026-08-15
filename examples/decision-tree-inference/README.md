# Decision Tree Inference example (CKKS)

One party scores its private feature vector against the other party's private
decision tree. Neither the features nor the model are revealed, to each other or
to the platform.

This is the scenario where **both** sides' secrets are structural: Acme (data
owner) contributes the `features` input, and Beta (data consumer) contributes the
`model` input, the decision tree itself. In the other scenarios the "model" is a
public function; here it is ciphertext.

Function: `decision-tree-inference`, **CKKS** on context `ckks-tree-v1`, CPU
engine.

## Why the tree is evaluated as a polynomial

A decision tree is a pile of `if feature < threshold` branches, and an FHE
circuit cannot branch on an encrypted value: the comparison result is itself
ciphertext, and inspecting it would require the secret key. So every comparison
is replaced by a **soft-if**, a degree-16 polynomial approximation of the step
function, and *both* sides of every branch are always evaluated. The leaf
contributions are then combined weighted by how strongly each path "fired".

This is why the output is not a crisp leaf value but a smoothed one, and why the
tree ships with `"degree": 16` baked into the data: the approximation degree is
part of the circuit, not a runtime choice.

## The sample tree

From `beta/data/tree.json`: height 2, 2 features, 2 classes, thresholds already
normalized to `[-1, 1]`.

```
                  f0 < 0.0 ?
                 /          \
         f1 < -0.3 ?        f1 < 0.4 ?
          /      \           /      \
   [.90,.10] [.20,.80] [.70,.30] [.05,.95]
```

## Sample data and expected result

- **Acme** (`acme/data/features.json`, dataOwner): `x = [0.6, 0.7]`.
- **Beta** (`beta/data/tree.json`, queryAnalyst): the tree above.

Expected decrypted prediction: **`[0.167801, 0.832199]`**, so `argmax = class 1`.

Sanity check by hand: with hard comparisons, `f0 = 0.6` is not `< 0.0` (go
right), then `f1 = 0.7` is not `< 0.4` (go right again), landing on leaf
`[0.05, 0.95]`. The soft-if output is a smoothed version of that leaf, pulled
toward the other leaves in proportion to how close each comparison ran to its
threshold. Class 1 wins either way.

`golden/` holds byte-identical reference copies of both inputs, so you can
confirm a run used the unmodified golden sample.

## `features.json` vs `features.txt`

Two encodings of the same `x = [0.6, 0.7]` are provided:

- `features.json` is the input to the function's **`encodingRecipe`**, which maps
  over the `features` array and emits one broadcast ciphertext per feature. This
  is the current (v2) path.
- `features.txt` is the flat one-value-per-line form, for encrypting directly
  with `julenny-fhe crypto encrypt --schema packed-real`.

## Running it

`acme/run.sh` on the data-owner machine, `beta/run.sh` on the data-consumer
machine.

**This scenario requires `node`** on the data-owner side. The `features` input is
a recipe-driven encrypted bundle, and `_core/recipe/recipe-encode.mjs` runs the
`encodingRecipe`. The script stops with a clear message if `node` is not on
`PATH`. No other scenario needs it.

`ckks-tree-v1` is a different crypto context from the `ckks-default-v1` used by
`rule-based-cross-match` and `negotiation-matrix`, so this scenario needs its own
collaboration and its own joint keysetup. It cannot reuse theirs.

See [`../README.md`](../README.md) for prerequisites, the phase-by-phase
breakdown, and the single-machine self-test setup.
