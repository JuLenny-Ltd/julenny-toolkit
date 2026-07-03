#ifndef FHE_TOOLKIT_CRYPTO_KEYS_H
#define FHE_TOOLKIT_CRYPTO_KEYS_H

#include <cstddef>
#include <memory>
#include <span>
#include <vector>

namespace fhe_toolkit::crypto {

class Context;

// Public half of a BFV keypair. PImpl over OpenFHE's PublicKey<DCRTPoly>.
class PublicKey {
public:
    PublicKey();
    ~PublicKey();
    PublicKey(const PublicKey&) = delete;
    PublicKey& operator=(const PublicKey&) = delete;
    PublicKey(PublicKey&&) noexcept;
    PublicKey& operator=(PublicKey&&) noexcept;

    bool empty() const noexcept;

    // Serialize to opaque bytes (cereal binary format).
    std::vector<std::byte> serialize() const;

    // Reconstruct from bytes produced by serialize().
    // `ctx` is required because keys are bound to their parent CryptoContext.
    static PublicKey deserialize(const Context& ctx, std::span<const std::byte> bytes);

private:
    friend class Context;
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// Secret half of a BFV keypair. Symmetric to PublicKey.
// IMPORTANT: serialize() output is sensitive material. It must be stored in
// the customer's secret-storage adapter (filesystem-encrypted, KMS, HSM)
// and never transmitted to the platform.
class SecretKey {
public:
    SecretKey();
    ~SecretKey();
    SecretKey(const SecretKey&) = delete;
    SecretKey& operator=(const SecretKey&) = delete;
    SecretKey(SecretKey&&) noexcept;
    SecretKey& operator=(SecretKey&&) noexcept;

    bool empty() const noexcept;

    std::vector<std::byte> serialize() const;
    static SecretKey deserialize(const Context& ctx, std::span<const std::byte> bytes);

private:
    friend class Context;
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

struct KeyPair {
    PublicKey public_key;
    SecretKey secret_key;

    KeyPair() = default;
    KeyPair(KeyPair&&) noexcept = default;
    KeyPair& operator=(KeyPair&&) noexcept = default;
    KeyPair(const KeyPair&) = delete;
    KeyPair& operator=(const KeyPair&) = delete;
};

}  // namespace fhe_toolkit::crypto

#endif
