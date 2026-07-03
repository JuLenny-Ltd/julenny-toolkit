#ifndef FHE_TOOLKIT_REGISTRY_SIGNATURE_H
#define FHE_TOOLKIT_REGISTRY_SIGNATURE_H

// Ed25519 signature verification (RFC 8032).
//
// Uses OpenSSL's EVP_PKEY_ED25519 primitive. The wire format matches the
// platform-side TypeScript implementation:
//   - Public key:  32 raw bytes
//   - Signature:   64 raw bytes (R || S)
//   - Message:     arbitrary bytes (typically canonical JSON of the
//                  function definition with the registry block stripped)
//
// Cross-language interop is verified by tests/registry/signature_test.cpp
// using the signed fixture shipped from the platform repo.

#include <cstddef>
#include <span>

#include <nlohmann/json.hpp>

namespace fhe_toolkit::registry {

// Verifies a raw Ed25519 signature.
//
// Returns true if the signature is valid for `message` under `public_key`.
// Returns false on:
//   - invalid signature
//   - wrong key sizes (must be 32 bytes pk, 64 bytes sig)
//   - any OpenSSL failure
bool verify_ed25519(std::span<const std::byte> public_key,
                    std::span<const std::byte> message,
                    std::span<const std::byte> signature);

// Verifies a function definition's registry signature.
//
// Steps:
//   1. Compute the canonical JSON of the function definition with the
//      "registry" block stripped.
//   2. Decode the base64 signature from fn_def["registry"]["signature"].
//   3. Verify the signature against the canonical bytes under `public_key`.
//
// Returns true on a valid signature, false on any failure including:
//   - missing or malformed registry block
//   - malformed signature encoding
//   - invalid signature
bool verify_function_definition_signature(const nlohmann::json& fn_def,
                                          std::span<const std::byte> public_key);

}  // namespace fhe_toolkit::registry

#endif
