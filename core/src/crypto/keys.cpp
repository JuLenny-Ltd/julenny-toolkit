#include "crypto/keys.h"
#include "crypto/context.h"
#include "internal.h"

#include <cstring>
#include <sstream>
#include <stdexcept>

#include <key/key-ser.h>
#include <ciphertext-ser.h>
#include <cryptocontext-ser.h>
#include <scheme/bfvrns/bfvrns-ser.h>
#include <scheme/ckksrns/ckksrns-ser.h>

namespace fhe_toolkit::crypto {

namespace {

std::vector<std::byte> str_to_bytes(const std::string& s) {
    std::vector<std::byte> out(s.size());
    if (!s.empty()) std::memcpy(out.data(), s.data(), s.size());
    return out;
}

}  // namespace

// ---------------- PublicKey ----------------

PublicKey::PublicKey() = default;
PublicKey::~PublicKey() = default;
PublicKey::PublicKey(PublicKey&&) noexcept = default;
PublicKey& PublicKey::operator=(PublicKey&&) noexcept = default;

bool PublicKey::empty() const noexcept {
    return !impl_ || !impl_->key;
}

std::vector<std::byte> PublicKey::serialize() const {
    if (empty()) throw std::runtime_error("cannot serialize empty PublicKey");
    std::stringstream ss;
    lbcrypto::Serial::Serialize(impl_->key, ss, lbcrypto::SerType::BINARY);
    return str_to_bytes(ss.str());
}

PublicKey PublicKey::deserialize(const Context& /*ctx*/, std::span<const std::byte> bytes) {
    std::stringstream ss;
    ss.write(reinterpret_cast<const char*>(bytes.data()),
             static_cast<std::streamsize>(bytes.size()));

    PublicKey pk;
    pk.impl_ = std::make_unique<Impl>();
    lbcrypto::Serial::Deserialize(pk.impl_->key, ss, lbcrypto::SerType::BINARY);
    if (!pk.impl_->key) {
        throw std::runtime_error("PublicKey deserialization produced a null key");
    }
    return pk;
}

// ---------------- SecretKey ----------------

SecretKey::SecretKey() = default;
SecretKey::~SecretKey() = default;
SecretKey::SecretKey(SecretKey&&) noexcept = default;
SecretKey& SecretKey::operator=(SecretKey&&) noexcept = default;

bool SecretKey::empty() const noexcept {
    return !impl_ || !impl_->key;
}

std::vector<std::byte> SecretKey::serialize() const {
    if (empty()) throw std::runtime_error("cannot serialize empty SecretKey");
    std::stringstream ss;
    lbcrypto::Serial::Serialize(impl_->key, ss, lbcrypto::SerType::BINARY);
    return str_to_bytes(ss.str());
}

SecretKey SecretKey::deserialize(const Context& /*ctx*/, std::span<const std::byte> bytes) {
    std::stringstream ss;
    ss.write(reinterpret_cast<const char*>(bytes.data()),
             static_cast<std::streamsize>(bytes.size()));

    SecretKey sk;
    sk.impl_ = std::make_unique<Impl>();
    lbcrypto::Serial::Deserialize(sk.impl_->key, ss, lbcrypto::SerType::BINARY);
    if (!sk.impl_->key) {
        throw std::runtime_error("SecretKey deserialization produced a null key");
    }
    return sk;
}

}  // namespace fhe_toolkit::crypto
