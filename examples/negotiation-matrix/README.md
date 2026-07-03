# Encrypted Negotiation Matrix example (CKKS)

A buyer (Acme) and a supplier (Beta) privately discover whether their contract
terms overlap, and on which exact combinations, without revealing their full
positions. Each side encrypts a binary indicator vector over a shared grid (the
"Common Table"); the platform multiplies the two encrypted vectors element-wise.
A slot is 1 only where BOTH put a 1 - a mutually acceptable deal.

Two variants share the same inputs:

- `negotiation-matrix-count` (ops `mul-ct -> relinearize -> sum-slots`, output
  scalar): "is there a deal, and on how many combinations?"
- `negotiation-matrix-itemized` (ops `mul-ct -> relinearize`, output vector):
  "which exact combinations match?"

Both are **CKKS** on `ckks-default-v1` (the same context as
rule-based-cross-match), so they run on **both** the CPU and GPU engines and
**reuse an existing CKKS collaboration** - no fresh keysetup. `requiredEvalKeys`:
count needs `[relinearization, sum]`, itemized needs `[relinearization]`; no
rotation.

## The Common Table (both sides must use this identical grid)

| variable | values | index |
|---|---|---|
| Quantity (units) | 1000, 5000 | q_idx 0..1 |
| Price per unit | 12, 13, 14, 15 | p_idx 0..3 |
| Delivery (weeks) | 1, 2, 3 | d_idx 0..2 |

Flatten row-major: `index = (q_idx*4 + p_idx)*3 + d_idx`, length 24. Each input
file is one 0/1 per line; the line position (comments/blank lines skipped) is the
grid index. The files are annotated with each index's meaning.

## Ranges become bins, not comparisons

CKKS has no cheap `<`/`>`, so a *range* is expressed by setting a 1 at every grid
cell it covers. The buyer's "Price 12..14, Delivery 1-2 weeks" is just multiple
1s. To the user it reads like a range; to the math it's exact slot matching.

## Sample data

- **Buyer** (`acme/data/acceptance_matrix.txt`, dataOwner): Quantity=5000, Price
  12..14, Delivery 1-2 weeks -> 1s at indices **{12,13,15,16,18,19}**.
- **Supplier** (`beta/data/offer_vector.txt`, queryAnalyst): exactly
  Quantity=5000, Price=13, Delivery=2 weeks -> 1 at index **16**.
- The product is 1 only at index 16 -> the matched deal is **5000 units, $13,
  2 weeks**.

Expected results:

- `negotiation-matrix-count` -> **match_count = 1**
- `negotiation-matrix-itemized` -> ~1.0 at index 16, ~0.0 elsewhere

A no-match supplier file (`beta/data/offer_vector_nomatch.txt`, offers Price=15 /
Delivery=3 weeks -> index 23, which the buyer does not accept) gives count = 0 and
an all-zero match vector.

## CKKS thresholding

CKKS is approximate, so decrypted slots are ~1.0 for a match and ~0.0 otherwise.
The toolkit rounds at decrypt (a slot counts as a match when its value >= 0.5,
match_count = round(sum)). The gap between match and no-match is far larger than
the noise, so this is robust.

## Running it

`acme/run.sh` on the data-owner machine, `beta/run.sh` on the data-consumer
machine; pick the count or itemized variant at 00-init time. Because it's CKKS on
`ckks-default-v1`, create the permission under your existing CKKS collaboration to
reuse the joint key. No rotation keys, so phase 4.5 is skipped.
