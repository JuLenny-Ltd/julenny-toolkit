#include "registry/trust_root.h"

#include <array>

namespace fhe_toolkit::registry {

namespace {

// 8f421fa667a2f6702e425b6be1b2f3604e1a7fbf57a01415d7951b4ce477d836
constexpr std::array<unsigned char, 32> kRegistryPublicKey = {
    0x8f, 0x42, 0x1f, 0xa6, 0x67, 0xa2, 0xf6, 0x70,
    0x2e, 0x42, 0x5b, 0x6b, 0xe1, 0xb2, 0xf3, 0x60,
    0x4e, 0x1a, 0x7f, 0xbf, 0x57, 0xa0, 0x14, 0x15,
    0xd7, 0x95, 0x1b, 0x4c, 0xe4, 0x77, 0xd8, 0x36,
};

}  // namespace

std::span<const std::byte> registry_public_key() {
    return std::as_bytes(
        std::span<const unsigned char>(kRegistryPublicKey.data(),
                                       kRegistryPublicKey.size()));
}

}  // namespace fhe_toolkit::registry
