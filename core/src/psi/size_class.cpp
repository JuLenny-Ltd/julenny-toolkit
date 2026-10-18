#include "psi/size_class.h"

#include <array>

namespace fhe_toolkit::psi {

namespace {

// Solved once with the toolkit's solver (see size_class.h). 128K and up need sharding and are not
// offered yet.
constexpr std::array<SizeClass, 7> kSizeClasses{{
    { "1K",   1024, 256,   19, 8, 1, 1 },
    { "2K",   2048, 32768,  5, 8, 1, 1 },
    { "4K",   4096, 32768,  6, 8, 1, 1 },
    { "8K",   8192, 32768,  8, 8, 1, 1 },
    { "16K", 16384, 32768,  9, 8, 1, 1 },
    { "32K", 32768, 32768, 12, 8, 1, 1 },
    { "64K", 65536, 32768, 16, 8, 1, 1 },
}};

}  // namespace

std::span<const SizeClass> size_classes() {
    return kSizeClasses;
}

const SizeClass* size_class(std::string_view id) {
    for (const auto& c : kSizeClasses) {
        if (c.id == id) return &c;
    }
    return nullptr;
}

const SizeClass* smallest_size_class_for(std::uint64_t distinct_records) {
    for (const auto& c : kSizeClasses) {
        if (distinct_records <= c.max_records) return &c;
    }
    return nullptr;
}

}  // namespace fhe_toolkit::psi
