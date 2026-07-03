# Federated Average (FedAvg) example

Two parties privately combine locally-trained model weights into one global
model. Acme (data owner) contributes its encrypted weight vector; Beta (data
consumer) contributes its own encrypted weight vector plus two plaintext
scaling factors. The platform computes

    global_weights = scale_a * weights_a + scale_b * weights_b

without either side ever seeing the other's weights. Linear circuit only:
no ciphertext-ciphertext multiplication, no rotations, no extra eval keys.

## Inputs (function-def `federated-average`, CKKS)

| input     | role         | side | encoding           | sample file                   |
|-----------|--------------|------|--------------------|-------------------------------|
| scale_a   | queryAnalyst | Beta | plaintext-scalar   | `beta/data/scale_a.txt`       |
| scale_b   | queryAnalyst | Beta | plaintext-scalar   | `beta/data/scale_b.txt`       |
| weights_a | dataOwner    | Acme | packed-real-vector | `acme/data/acme_model_weights.txt` |
| weights_b | queryAnalyst | Beta | packed-real-vector | `beta/data/beta_model_weights.txt` |

## The sample data

Story: both parties trained the same 16-parameter fraud-detection model on
their own customer data. Acme trained on 8,000 records, Beta on 2,000, so the
data-size-weighted scales are

    scale_a = 8000 / (8000 + 2000) = 0.8
    scale_b = 2000 / (8000 + 2000) = 0.2

Weight files are one float per line (16 lines each).

## Expected result

With the sample data, the decrypted `global_weights` (first 16 slots) should
be, up to CKKS approximation noise (~1e-6 or better):

```
 0.77  -0.34   0.14   1.19  -0.65   0.44   0.07  -1.06
 0.69   0.12  -0.37   0.94   0.39  -0.56   0.19   0.66
```

(slot i = 0.8 * acme[i] + 0.2 * beta[i]; remaining slots ~0.)

## Running it

Same flow as the other scenarios: `acme/run.sh` on the data-owner machine,
`beta/run.sh` on the data-consumer machine; the function/version is picked at
00-init time. `requiredEvalKeys` is empty, so phase 4.5 (rotation keys) is
skipped automatically.

> **Status note:** the CLI's `crypto encrypt` does not yet implement the
> `weight-vector` / `packed-real-vector` encoding (only `indicator-hash`).
> The two scale inputs upload fine via the plaintext branch; the weight
> vectors need the new CLI encode branch before this example runs end-to-end.
