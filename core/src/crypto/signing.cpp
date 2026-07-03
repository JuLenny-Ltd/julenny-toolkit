#include "crypto/signing.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <memory>
#include <stdexcept>

namespace fhe_toolkit::signing {

namespace {

// Custom deleter for EVP_PKEY so we can use unique_ptr without leaking.
struct EvpPkeyDeleter {
    void operator()(EVP_PKEY* p) const noexcept { if (p) EVP_PKEY_free(p); }
};
using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;

struct EvpMdCtxDeleter {
    void operator()(EVP_MD_CTX* c) const noexcept { if (c) EVP_MD_CTX_free(c); }
};
using EvpMdCtxPtr = std::unique_ptr<EVP_MD_CTX, EvpMdCtxDeleter>;

// Build an EVP_PKEY from raw private-key bytes (the 32-byte Ed25519 seed).
EvpPkeyPtr make_pkey_from_secret(const SigningSecretKey& sk) {
    EvpPkeyPtr pkey{ EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr,
        reinterpret_cast<const unsigned char*>(sk.bytes.data()),
        sk.bytes.size()) };
    if (!pkey) throw std::runtime_error("EVP_PKEY_new_raw_private_key failed (Ed25519)");
    return pkey;
}

EvpPkeyPtr make_pkey_from_public(const SigningPublicKey& pk) {
    EvpPkeyPtr pkey{ EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519, nullptr,
        reinterpret_cast<const unsigned char*>(pk.bytes.data()),
        pk.bytes.size()) };
    if (!pkey) throw std::runtime_error("EVP_PKEY_new_raw_public_key failed (Ed25519)");
    return pkey;
}

}  // namespace

SigningKeyPair generate_keypair() {
    SigningSecretKey sk;
    if (RAND_bytes(reinterpret_cast<unsigned char*>(sk.bytes.data()),
                   static_cast<int>(sk.bytes.size())) != 1) {
        throw std::runtime_error("RAND_bytes failed when generating Ed25519 seed");
    }
    SigningKeyPair kp;
    kp.secret_key = sk;
    kp.public_key = derive_public_key(sk);
    return kp;
}

SigningPublicKey derive_public_key(const SigningSecretKey& sk) {
    auto pkey = make_pkey_from_secret(sk);
    SigningPublicKey pk;
    std::size_t len = pk.bytes.size();
    if (EVP_PKEY_get_raw_public_key(pkey.get(),
                                     reinterpret_cast<unsigned char*>(pk.bytes.data()),
                                     &len) != 1 || len != pk.bytes.size()) {
        throw std::runtime_error("EVP_PKEY_get_raw_public_key failed (Ed25519)");
    }
    return pk;
}

Signature sign(const SigningSecretKey& sk, std::span<const std::byte> message) {
    auto pkey = make_pkey_from_secret(sk);
    EvpMdCtxPtr ctx{ EVP_MD_CTX_new() };
    if (!ctx) throw std::runtime_error("EVP_MD_CTX_new failed");

    // Ed25519 uses no pre-hash; the digest argument must be nullptr.
    if (EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, pkey.get()) != 1) {
        throw std::runtime_error("EVP_DigestSignInit failed (Ed25519)");
    }

    Signature sig;
    std::size_t sig_len = sig.bytes.size();
    if (EVP_DigestSign(ctx.get(),
                       reinterpret_cast<unsigned char*>(sig.bytes.data()), &sig_len,
                       reinterpret_cast<const unsigned char*>(message.data()),
                       message.size()) != 1) {
        throw std::runtime_error("EVP_DigestSign failed (Ed25519)");
    }
    if (sig_len != sig.bytes.size()) {
        throw std::runtime_error("Ed25519 signature length mismatch (expected 64 bytes)");
    }
    return sig;
}

bool verify(const SigningPublicKey& pk,
            std::span<const std::byte> message,
            const Signature& sig) {
    auto pkey = make_pkey_from_public(pk);
    EvpMdCtxPtr ctx{ EVP_MD_CTX_new() };
    if (!ctx) throw std::runtime_error("EVP_MD_CTX_new failed");

    if (EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, pkey.get()) != 1) {
        throw std::runtime_error("EVP_DigestVerifyInit failed (Ed25519)");
    }

    int rv = EVP_DigestVerify(ctx.get(),
                              reinterpret_cast<const unsigned char*>(sig.bytes.data()),
                              sig.bytes.size(),
                              reinterpret_cast<const unsigned char*>(message.data()),
                              message.size());
    // EVP_DigestVerify returns 1 = valid, 0 = invalid, <0 = other error.
    if (rv < 0) throw std::runtime_error("EVP_DigestVerify error (not just invalid)");
    return rv == 1;
}

SigningPublicKey load_public_key(std::span<const std::byte> bytes) {
    if (bytes.size() != public_key_bytes) {
        throw std::invalid_argument("Ed25519 public key must be exactly 32 bytes");
    }
    SigningPublicKey pk;
    std::copy(bytes.begin(), bytes.end(), pk.bytes.begin());
    return pk;
}

SigningSecretKey load_secret_key(std::span<const std::byte> bytes) {
    if (bytes.size() != secret_key_bytes) {
        throw std::invalid_argument("Ed25519 secret key (seed) must be exactly 32 bytes");
    }
    SigningSecretKey sk;
    std::copy(bytes.begin(), bytes.end(), sk.bytes.begin());
    return sk;
}

Signature load_signature(std::span<const std::byte> bytes) {
    if (bytes.size() != signature_bytes) {
        throw std::invalid_argument("Ed25519 signature must be exactly 64 bytes");
    }
    Signature s;
    std::copy(bytes.begin(), bytes.end(), s.bytes.begin());
    return s;
}

}  // namespace fhe_toolkit::signing
