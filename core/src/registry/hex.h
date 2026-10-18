#ifndef FHE_TOOLKIT_REGISTRY_HEX_H
#define FHE_TOOLKIT_REGISTRY_HEX_H

// Hex encoding/decoding for byte arrays.
// Used by signature verification (keys + signatures arrive hex-encoded from
// the platform side) and by tests comparing bytes to fixture values.

#include <cstddef>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace fhe_toolkit::registry {

// Encodes bytes as lowercase hex. Always succeeds.
std::string hex_encode(std::span<const std::byte> bytes);

// Decodes lowercase or uppercase hex to bytes. Returns nullopt on:
//   - odd-length input
//   - non-hex characters
std::optional<std::vector<std::byte>> hex_decode(std::string_view hex);

}  // namespace fhe_toolkit::registry

#endif
