#ifndef FHE_TOOLKIT_CRYPTO_SIGNING_H
#define FHE_TOOLKIT_CRYPTO_SIGNING_H

// Ed25519 signing primitives used by the rev 5 trust model. Each company
// has an Ed25519 signing keypair (separate from their FHE keys); every
// keysetup contribution and partial decryption produced by the customer's
// crypto app is signed with the secret half, and the receiving party (and
// the platform) verifies against the registered public half before
// consuming the contribution.
//
// Implemented on top of OpenSSL (1.1.1+) so we add no new dependency. The
// 32-byte seed-and-public-key representation is the standard Ed25519
// wire format and is interchangeable with libsodium, Python's
// cryptography, Go's ed25519 package, etc.

#include <array>
#include <cstddef>
#include <span>
#include <vector>

namespace fhe_toolkit::signing {

// Standard Ed25519 sizes.
constexpr std::size_t public_key_bytes = 32;
constexpr std::size_t secret_key_bytes = 32;  // the 32-byte seed
constexpr std::size_t signature_bytes  = 64;

struct SigningPublicKey {
    std::array<std::byte, public_key_bytes> bytes{};
};

struct SigningSecretKey {
    std::array<std::byte, secret_key_bytes> bytes{};
};

struct SigningKeyPair {
    SigningPublicKey public_key;
    SigningSecretKey secret_key;
};

struct Signature {
    std::array<std::byte, signature_bytes> bytes{};
};

// Generate a fresh Ed25519 keypair using OpenSSL's RAND_bytes.
SigningKeyPair generate_keypair();

// Derive the public key from the seed. Pure derivation; no randomness.
// Useful when the customer has only the secret seed file and needs to
// reconstruct the public key.
SigningPublicKey derive_public_key(const SigningSecretKey& sk);

// Sign a message. Returns the 64-byte signature.
Signature sign(const SigningSecretKey& sk, std::span<const std::byte> message);

// Verify a signature. Returns true iff valid.
bool verify(const SigningPublicKey& pk,
            std::span<const std::byte> message,
            const Signature& sig);

// Bytes <-> typed wrappers. Throw std::invalid_argument on wrong size.
SigningPublicKey load_public_key(std::span<const std::byte> bytes);
SigningSecretKey load_secret_key(std::span<const std::byte> bytes);
Signature        load_signature(std::span<const std::byte> bytes);

}  // namespace fhe_toolkit::signing

#endif
