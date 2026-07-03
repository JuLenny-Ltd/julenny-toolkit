#ifndef FHE_TOOLKIT_CRYPTO_CIPHERTEXT_H
#define FHE_TOOLKIT_CRYPTO_CIPHERTEXT_H

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace fhe_toolkit::crypto {

class Context;

// A BFV packed plaintext: a vector of int64_t encoded into one of OpenFHE's
// SIMD-style "slots". Up to ring_dimension/2 slots are available (OpenFHE
// determines ring dimension from the security level + multiplicative depth).
// Trailing slots beyond the encoded length are zero-padded.
class PlaintextPacked {
public:
    PlaintextPacked();
    ~PlaintextPacked();
    PlaintextPacked(const PlaintextPacked&) = delete;
    PlaintextPacked& operator=(const PlaintextPacked&) = delete;
    PlaintextPacked(PlaintextPacked&&) noexcept;
    PlaintextPacked& operator=(PlaintextPacked&&) noexcept;

    bool empty() const noexcept;

    // BFV: returns the integer values held in the plaintext. After decryption
    // the size equals the context's slot count (much larger than the original
    // encoded length); trailing values are zero unless the ciphertext was
    // computed on rather than just round-tripped.
    std::vector<int64_t> values() const;

    // CKKS: returns the real-number values. CKKS is approximate, so decrypted
    // values are close to but not exactly equal to the originally encoded
    // values (typically within 1e-3 after a few homomorphic operations).
    std::vector<double> real_values() const;

private:
    friend class Context;
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// A BFV ciphertext.
class Ciphertext {
public:
    Ciphertext();
    ~Ciphertext();
    Ciphertext(const Ciphertext&) = delete;
    Ciphertext& operator=(const Ciphertext&) = delete;
    Ciphertext(Ciphertext&&) noexcept;
    Ciphertext& operator=(Ciphertext&&) noexcept;

    bool empty() const noexcept;

    std::vector<std::byte> serialize() const;
    static Ciphertext deserialize(const Context& ctx, std::span<const std::byte> bytes);

    // Diagnostic: human-readable dump of this ciphertext's metadata and its
    // EMBEDDED crypto context parameters (the ones cross-component
    // "ValidateCiphertext: not generated with the same crypto context"
    // failures hinge on). Does not validate against any local context.
    std::string describe() const;

private:
    friend class Context;
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace fhe_toolkit::crypto

#endif
