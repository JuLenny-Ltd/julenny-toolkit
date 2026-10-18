#include "crypto/eval_keys.h"
#include "crypto/context.h"
#include "internal.h"

#include <cstring>
#include <sstream>
#include <stdexcept>

#include <ciphertext-ser.h>
#include <cryptocontext-ser.h>
#include <key/key-ser.h>
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

// ---------------- EvalKey ----------------

EvalKey::EvalKey() = default;
EvalKey::~EvalKey() = default;
EvalKey::EvalKey(EvalKey&&) noexcept = default;
EvalKey& EvalKey::operator=(EvalKey&&) noexcept = default;

bool EvalKey::empty() const noexcept {
    return !impl_ || !impl_->key;
}

std::vector<std::byte> EvalKey::serialize() const {
    if (empty()) throw std::runtime_error("cannot serialize empty EvalKey");
    std::stringstream ss;
    lbcrypto::Serial::Serialize(impl_->key, ss, lbcrypto::SerType::BINARY);
    return str_to_bytes(ss.str());
}

EvalKey EvalKey::deserialize(const Context& /*ctx*/, std::span<const std::byte> bytes) {
    std::stringstream ss;
    ss.write(reinterpret_cast<const char*>(bytes.data()),
             static_cast<std::streamsize>(bytes.size()));
    EvalKey out;
    out.impl_ = std::make_unique<Impl>();
    lbcrypto::Serial::Deserialize(out.impl_->key, ss, lbcrypto::SerType::BINARY);
    if (!out.impl_->key) {
        throw std::runtime_error("EvalKey deserialization produced a null key");
    }
    return out;
}

// ---------------- SumKeyMap ----------------

SumKeyMap::SumKeyMap() = default;
SumKeyMap::~SumKeyMap() = default;
SumKeyMap::SumKeyMap(SumKeyMap&&) noexcept = default;
SumKeyMap& SumKeyMap::operator=(SumKeyMap&&) noexcept = default;

bool SumKeyMap::empty() const noexcept {
    return !impl_ || !impl_->keys || impl_->keys->empty();
}

std::vector<std::byte> SumKeyMap::serialize() const {
    if (empty()) throw std::runtime_error("cannot serialize empty SumKeyMap");
    std::stringstream ss;
    lbcrypto::Serial::Serialize(impl_->keys, ss, lbcrypto::SerType::BINARY);
    return str_to_bytes(ss.str());
}

SumKeyMap SumKeyMap::deserialize(const Context& /*ctx*/, std::span<const std::byte> bytes) {
    std::stringstream ss;
    ss.write(reinterpret_cast<const char*>(bytes.data()),
             static_cast<std::streamsize>(bytes.size()));
    SumKeyMap out;
    out.impl_ = std::make_unique<Impl>();
    lbcrypto::Serial::Deserialize(out.impl_->keys, ss, lbcrypto::SerType::BINARY);
    if (!out.impl_->keys || out.impl_->keys->empty()) {
        throw std::runtime_error("SumKeyMap deserialization produced an empty map");
    }
    return out;
}

// ---------------- RotationKeyMap ----------------

RotationKeyMap::RotationKeyMap() = default;
RotationKeyMap::~RotationKeyMap() = default;
RotationKeyMap::RotationKeyMap(RotationKeyMap&&) noexcept = default;
RotationKeyMap& RotationKeyMap::operator=(RotationKeyMap&&) noexcept = default;

bool RotationKeyMap::empty() const noexcept {
    return !impl_ || !impl_->keys || impl_->keys->empty();
}

std::vector<std::byte> RotationKeyMap::serialize() const {
    if (empty()) throw std::runtime_error("cannot serialize empty RotationKeyMap");
    std::stringstream ss;
    lbcrypto::Serial::Serialize(impl_->keys, ss, lbcrypto::SerType::BINARY);
    return str_to_bytes(ss.str());
}

RotationKeyMap RotationKeyMap::deserialize(const Context& /*ctx*/, std::span<const std::byte> bytes) {
    std::stringstream ss;
    ss.write(reinterpret_cast<const char*>(bytes.data()),
             static_cast<std::streamsize>(bytes.size()));
    RotationKeyMap out;
    out.impl_ = std::make_unique<Impl>();
    lbcrypto::Serial::Deserialize(out.impl_->keys, ss, lbcrypto::SerType::BINARY);
    if (!out.impl_->keys || out.impl_->keys->empty()) {
        throw std::runtime_error("RotationKeyMap deserialization produced an empty map");
    }
    return out;
}

}  // namespace fhe_toolkit::crypto
