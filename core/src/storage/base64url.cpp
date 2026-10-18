#include "base64url.h"

#include <array>
#include <cstdint>

namespace fhe_toolkit::storage {

namespace {

constexpr std::string_view kAlphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

// Reverse lookup: ASCII byte -> base64url index, or 0xff for invalid.
constexpr std::array<uint8_t, 256> make_decode_table() {
    std::array<uint8_t, 256> table{};
    for (auto& v : table) v = 0xff;
    for (size_t i = 0; i < kAlphabet.size(); ++i) {
        table[static_cast<uint8_t>(kAlphabet[i])] = static_cast<uint8_t>(i);
    }
    return table;
}

constexpr auto kDecodeTable = make_decode_table();

}  // namespace

std::string base64url_encode(std::span<const std::byte> bytes) {
    std::string out;
    out.reserve((bytes.size() * 4 + 2) / 3);

    size_t i = 0;
    while (i + 3 <= bytes.size()) {
        uint32_t v = (static_cast<uint32_t>(bytes[i]) << 16) |
                     (static_cast<uint32_t>(bytes[i + 1]) << 8) |
                     static_cast<uint32_t>(bytes[i + 2]);
        out.push_back(kAlphabet[(v >> 18) & 0x3f]);
        out.push_back(kAlphabet[(v >> 12) & 0x3f]);
        out.push_back(kAlphabet[(v >> 6) & 0x3f]);
        out.push_back(kAlphabet[v & 0x3f]);
        i += 3;
    }

    const size_t remaining = bytes.size() - i;
    if (remaining == 1) {
        uint32_t v = static_cast<uint32_t>(bytes[i]) << 16;
        out.push_back(kAlphabet[(v >> 18) & 0x3f]);
        out.push_back(kAlphabet[(v >> 12) & 0x3f]);
    } else if (remaining == 2) {
        uint32_t v = (static_cast<uint32_t>(bytes[i]) << 16) |
                     (static_cast<uint32_t>(bytes[i + 1]) << 8);
        out.push_back(kAlphabet[(v >> 18) & 0x3f]);
        out.push_back(kAlphabet[(v >> 12) & 0x3f]);
        out.push_back(kAlphabet[(v >> 6) & 0x3f]);
    }

    return out;
}

std::string base64url_encode(std::string_view text) {
    return base64url_encode(std::span<const std::byte>(
        reinterpret_cast<const std::byte*>(text.data()), text.size()));
}

std::optional<std::vector<std::byte>> base64url_decode(std::string_view encoded) {
    if (encoded.size() % 4 == 1) return std::nullopt;  // Invalid length.

    std::vector<std::byte> out;
    out.reserve((encoded.size() * 3) / 4);

    uint32_t v = 0;
    int bits = 0;
    for (char c : encoded) {
        const uint8_t idx = kDecodeTable[static_cast<uint8_t>(c)];
        if (idx == 0xff) return std::nullopt;
        v = (v << 6) | idx;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<std::byte>((v >> bits) & 0xff));
        }
    }
    return out;
}

std::optional<std::string> base64url_decode_to_string(std::string_view encoded) {
    auto bytes = base64url_decode(encoded);
    if (!bytes) return std::nullopt;
    std::string s;
    s.reserve(bytes->size());
    for (auto b : *bytes) s.push_back(static_cast<char>(b));
    return s;
}

}  // namespace fhe_toolkit::storage
