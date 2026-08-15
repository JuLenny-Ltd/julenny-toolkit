# Sample BFV Ciphertext Fixture

A pre-generated FHE encryption that the platform's wrapper service
(and any other OpenFHE-based implementation) can use as a
deserialization test fixture.

## Files

- `public_key.bin` - OpenFHE `PublicKey<DCRTPoly>`, cereal-binary
  serialized.
- `secret_key.bin` - OpenFHE `PrivateKey<DCRTPoly>`, cereal-binary
  serialized. **TEST KEY ONLY.** Knowingly committed to the public
  repo for cross-implementation testing. Never use these bytes for
  anything that processes real data.
- `ciphertext.bin` - OpenFHE `Ciphertext<DCRTPoly>`, cereal-binary
  serialized. Encrypts a packed-int vector under `public_key.bin`.
- `metadata.json` - context spec parameters, plaintext values used,
  file sizes, and step-by-step verification instructions.

## How it was generated

```sh
julenny-toolkit crypto dump-sample --output-dir third_party/fixtures/sample-ciphertext
```

Reproducible on demand: regenerate whenever the crypto context spec
changes. Fresh random keys each run; the ciphertext is freshly
encrypted but encodes the same `metadata.plaintext.values`.

## How to use it

See `metadata.json` for the full verification steps. In summary:

1. Build an OpenFHE `CryptoContext` with the parameters in
   `contextSpec` (BFV, plaintextModulus=65537, multDepth=4,
   securityLevel=HEStd_128_classic).
2. Deserialize the three `.bin` files into `PublicKey`, `PrivateKey`,
   and `Ciphertext` respectively.
3. Decrypt the ciphertext with the secret key.
4. Verify the first 8 packed slots equal `plaintext.values` from
   `metadata.json`.

If decryption recovers the expected values, your implementation is
wire-compatible with the JuLenny FHE Toolkit's serialization for the
`bfv-default-v1` context.
