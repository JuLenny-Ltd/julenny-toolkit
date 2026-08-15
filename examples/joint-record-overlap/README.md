# Joint Record Overlap example (BFV)

Two organizations each hold a list of customer records and want to know how many
they have in common, without either side revealing its list and without the
platform ever seeing a plaintext record. Acme (data owner) holds a customer
table; Beta (data consumer) holds a shorter list and asks how much of it Acme
already has.

Two variants share the same inputs:

- `joint-record-overlap-count` (output scalar): "how many records appear in both
  lists?"
- `joint-record-overlap-itemized` (output vector): "which of my records does the
  other side also have?"

Both are **BFV**, which is exact-integer arithmetic, so there is no
approximation and no thresholding at decrypt: a match is exactly 1 and a
non-match is exactly 0. BFV runs on the **CPU** engine.

## Matching is on the whole record, not one field

Each row is `name,dob`, and both fields together form the matching key. This is
what the sample data is built to demonstrate.

## Sample data

**Acme** (`acme/data/acme-customers.csv`, dataOwner): 75 customer records.

**Beta** (`beta/data/*.csv`, queryAnalyst): three alternative input files, so you
can run the same collaboration three times and get three different, predictable
answers.

| file | contents | expected count | expected itemized |
|---|---|---|---|
| `beta-0match.csv` | Daniel Klein (1990-07-22), Emma Raffles (1980-03-21) | **0** | all zeros |
| `beta-1match.csv` | Sophia Martinez (1990-07-22) | **1** | 1 at index 0 |
| `beta-2match.csv` | Sophia Martinez (1990-07-22), Amelia White (1989-03-21) | **2** | 1 at indices 0 and 1 |

`beta-0match.csv` is the interesting one. Daniel Klein carries **exactly** Sophia
Martinez's date of birth (1990-07-22) under a different name, and Emma Raffles
carries a date close to Amelia White's (1980-03-21 against 1989-03-21). An
implementation that matched on date of birth alone would report a false match on
the first record; the correct answer is 0. Use this file to confirm the overlap
really is computed over the joined record.

`beta-1match.csv` and `beta-2match.csv` contain records copied verbatim from
Acme's table, so their matches are exact.

## Running it

`acme/run.sh` on the data-owner machine, `beta/run.sh` on the data-consumer
machine; pick the count or itemized variant at 00-init time.

Because this is BFV and the other scenarios are CKKS, it needs its **own
collaboration** with its own joint key: a BFV function cannot reuse a CKKS
collaboration's keys. Expect the full keysetup (phases 1 to 3) on the first run.
No rotation keys are required, so phase 4.5 is a no-op.

To try a different expected answer, run `run.sh` again and choose "start a new
test cycle", then pick a different `beta-*.csv` at the encrypt step. The keysetup
is reused; only the dataset changes.

See [`../README.md`](../README.md) for prerequisites, the phase-by-phase
breakdown, and the single-machine self-test setup.
