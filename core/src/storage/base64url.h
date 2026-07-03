#ifndef FHE_TOOLKIT_STORAGE_BASE64URL_H
#define FHE_TOOLKIT_STORAGE_BASE64URL_H

// URL-safe base64 (RFC 4648 §5) without padding.
// Used for encoding arbitrary string keys into filesystem-safe filenames.

#include <cstddef>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace fhe_toolkit::storage {

// Encodes bytes to base64url (no padding). Always succeeds.
std::string base64url_encode(std::span<const std::byte> bytes);

// Convenience overload for string inputs.
std::string base64url_encode(std::string_view text);

// Decodes base64url back to bytes. Returns nullopt on malformed input.
std::optional<std::vector<std::byte>> base64url_decode(std::string_view encoded);

// Decodes base64url to a string (assumes UTF-8). Returns nullopt on malformed input.
std::optional<std::string> base64url_decode_to_string(std::string_view encoded);

}  // namespace fhe_toolkit::storage

#endif
