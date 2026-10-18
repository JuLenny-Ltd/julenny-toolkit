#include "registry/hex.h"

#include <array>
#include <cstdint>

namespace fhe_toolkit::registry {

namespace {

constexpr std::array<int8_t, 256> make_decode_table() {
    std::array<int8_t, 256> t{};
    for (auto& v : t) v = -1;
    for (int i = 0; i < 10; ++i) t[static_cast<size_t>('0' + i)] = static_cast<int8_t>(i);
    for (int i = 0; i < 6;  ++i) t[static_cast<size_t>('a' + i)] = static_cast<int8_t>(10 + i);
    for (int i = 0; i < 6;  ++i) t[static_cast<size_t>('A' + i)] = static_cast<int8_t>(10 + i);
    return t;
}

constexpr auto kDecode = make_decode_table();

}  // namespace

std::string hex_encode(std::span<const std::byte> bytes) {
    static const char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (auto b : bytes) {
        const auto v = static_cast<unsigned char>(b);
        out.push_back(hex[v >> 4]);
        out.push_back(hex[v & 0x0f]);
    }
    return out;
}

std::optional<std::vector<std::byte>> hex_decode(std::string_view hex) {
    if (hex.size() % 2 != 0) return std::nullopt;
    std::vector<std::byte> out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        const int8_t hi = kDecode[static_cast<unsigned char>(hex[i])];
        const int8_t lo = kDecode[static_cast<unsigned char>(hex[i + 1])];
        if (hi < 0 || lo < 0) return std::nullopt;
        out.push_back(static_cast<std::byte>((hi << 4) | lo));
    }
    return out;
}

}  // namespace fhe_toolkit::registry
