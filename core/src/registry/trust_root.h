#ifndef FHE_TOOLKIT_REGISTRY_TRUST_ROOT_H
#define FHE_TOOLKIT_REGISTRY_TRUST_ROOT_H

// Pinned trust root for function-definition signature verification.
//
// The platform registry's Ed25519 public key is compiled into the toolkit so
// verification never fetches-and-trusts the key from the same server whose
// definitions it is verifying. Rotating the key is a toolkit release.

#include <cstddef>
#include <span>

namespace fhe_toolkit::registry {

// The pinned platform registry Ed25519 public key (32 raw bytes).
// Hex: 8f421fa667a2f6702e425b6be1b2f3604e1a7fbf57a01415d7951b4ce477d836
std::span<const std::byte> registry_public_key();

}  // namespace fhe_toolkit::registry

#endif
