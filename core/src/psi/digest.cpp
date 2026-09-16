#include "psi/digest.h"

#include <openssl/evp.h>

#include <algorithm>
#include <bit>
#include <memory>
#include <stdexcept>
#include <string>

namespace fhe_toolkit::psi {

namespace {

struct EvpMdCtxDeleter {
    void operator()(EVP_MD_CTX* c) const noexcept { if (c) EVP_MD_CTX_free(c); }
};
using EvpMdCtxPtr = std::unique_ptr<EVP_MD_CTX, EvpMdCtxDeleter>;

// Fetched once: in OpenSSL 3 an implicit fetch on every EVP_DigestInit_ex2 is a
// measurable cost at 10^7 records. The EVP_MD is reference-counted and lives
// for the process, so it is deliberately never freed.
const EVP_MD* sha256_md() {
    static const EVP_MD* md = [] {
        EVP_MD* fetched = EVP_MD_fetch(nullptr, "SHA256", nullptr);
        if (!fetched) throw std::runtime_error("EVP_MD_fetch(SHA256) failed");
        return fetched;
    }();
    return md;
}

Digest sha256_parts(std::initializer_list<std::string_view> parts) {
    EvpMdCtxPtr ctx{ EVP_MD_CTX_new() };
    if (!ctx) throw std::runtime_error("EVP_MD_CTX_new failed");
    if (EVP_DigestInit_ex2(ctx.get(), sha256_md(), nullptr) != 1) {
        throw std::runtime_error("EVP_DigestInit_ex2 failed (SHA-256)");
    }
    for (auto part : parts) {
        if (EVP_DigestUpdate(ctx.get(), part.data(), part.size()) != 1) {
            throw std::runtime_error("EVP_DigestUpdate failed (SHA-256)");
        }
    }
    Digest out{};
    unsigned int len = 0;
    if (EVP_DigestFinal_ex(ctx.get(), out.data(), &len) != 1 || len != out.size()) {
        throw std::runtime_error("EVP_DigestFinal_ex failed (SHA-256)");
    }
    return out;
}

}  // namespace

Digest sha256(std::string_view bytes) {
    return sha256_parts({ bytes });
}

Digest record_digest(std::string_view domain_separator, std::string_view record) {
    if (domain_separator.empty()) {
        throw std::invalid_argument("PSI domain separator must not be empty");
    }
    if (domain_separator.find('\0') != std::string_view::npos) {
        throw std::invalid_argument("PSI domain separator must not contain a NUL byte");
    }
    constexpr std::string_view terminator{ "\0", 1 };
    return sha256_parts({ domain_separator, terminator, record });
}

std::uint32_t address(const Digest& d) noexcept {
    return  static_cast<std::uint32_t>(d[0])
         | (static_cast<std::uint32_t>(d[1]) << 8)
         | (static_cast<std::uint32_t>(d[2]) << 16)
         | (static_cast<std::uint32_t>(d[3]) << 24);
}

std::uint32_t position(const Digest& d, std::uint64_t cells) {
    if (cells == 0 || cells > max_cells || !std::has_single_bit(cells)) {
        throw std::invalid_argument("PSI cell count must be a power of two in [1, 2^32], got "
                                    + std::to_string(cells));
    }
    return static_cast<std::uint32_t>(address(d) & (cells - 1));
}

std::uint16_t limb(const Digest& d, unsigned j) {
    if (j >= max_limbs) {
        throw std::out_of_range("PSI limb index " + std::to_string(j) + " out of range (max "
                                + std::to_string(max_limbs - 1) + ")");
    }
    const std::size_t at = signature_offset + 2 * std::size_t{j};
    return static_cast<std::uint16_t>(d[at] | (d[at + 1] << 8));
}

std::vector<std::uint16_t> signature(const Digest& d, unsigned limbs) {
    if (limbs == 0 || limbs > max_limbs) {
        throw std::invalid_argument("PSI signature needs 1.." + std::to_string(max_limbs)
                                    + " limbs from one SHA-256 digest, got "
                                    + std::to_string(limbs));
    }
    std::vector<std::uint16_t> out(limbs);
    for (unsigned j = 0; j < limbs; ++j) out[j] = limb(d, j);
    return out;
}

std::size_t dedupe(std::vector<Digest>& digests) {
    std::sort(digests.begin(), digests.end());
    const auto first_dup = std::unique(digests.begin(), digests.end());
    const auto removed = static_cast<std::size_t>(digests.end() - first_dup);
    digests.erase(first_dup, digests.end());
    return removed;
}

}  // namespace fhe_toolkit::psi
