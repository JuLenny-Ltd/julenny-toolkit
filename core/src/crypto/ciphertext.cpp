#include "crypto/ciphertext.h"
#include "crypto/context.h"
#include "internal.h"

#include <cstring>
#include <sstream>
#include <stdexcept>

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

// ---------------- PlaintextPacked ----------------

PlaintextPacked::PlaintextPacked() = default;
PlaintextPacked::~PlaintextPacked() = default;
PlaintextPacked::PlaintextPacked(PlaintextPacked&&) noexcept = default;
PlaintextPacked& PlaintextPacked::operator=(PlaintextPacked&&) noexcept = default;

bool PlaintextPacked::empty() const noexcept {
    return !impl_ || !impl_->pt;
}

std::vector<int64_t> PlaintextPacked::values() const {
    if (empty()) throw std::runtime_error("cannot read values from empty PlaintextPacked");
    return impl_->pt->GetPackedValue();
}

std::vector<double> PlaintextPacked::real_values() const {
    if (empty()) throw std::runtime_error("cannot read values from empty PlaintextPacked");
    return impl_->pt->GetRealPackedValue();
}

// ---------------- Ciphertext ----------------

Ciphertext::Ciphertext() = default;
Ciphertext::~Ciphertext() = default;
Ciphertext::Ciphertext(Ciphertext&&) noexcept = default;
Ciphertext& Ciphertext::operator=(Ciphertext&&) noexcept = default;

bool Ciphertext::empty() const noexcept {
    return !impl_ || !impl_->ct;
}

std::vector<std::byte> Ciphertext::serialize() const {
    if (empty()) throw std::runtime_error("cannot serialize empty Ciphertext");
    std::stringstream ss;
    lbcrypto::Serial::Serialize(impl_->ct, ss, lbcrypto::SerType::BINARY);
    return str_to_bytes(ss.str());
}

std::string Ciphertext::describe() const {
    if (empty()) throw std::runtime_error("cannot describe empty Ciphertext");
    const auto& ct = impl_->ct;
    std::ostringstream os;
    os << "encodingType:   " << ct->GetEncodingType() << "\n";
    os << "keyTag:         " << ct->GetKeyTag() << "\n";
    os << "level:          " << ct->GetLevel() << "\n";
    os << "noiseScaleDeg:  " << ct->GetNoiseScaleDeg() << "\n";
    os << "scalingFactor:  " << ct->GetScalingFactor() << "\n";
    os << "slots:          " << ct->GetSlots() << "\n";
    os << "polys:          " << ct->GetElements().size() << "\n";
    if (!ct->GetElements().empty()) {
        os << "towers/poly:    " << ct->GetElements()[0].GetNumOfElements() << "\n";
    }
    auto cc = ct->GetCryptoContext();
    if (cc) {
        os << "ringDimension:  " << cc->GetRingDimension() << "\n";
        os << "embedded cryptoParameters:\n" << *cc->GetCryptoParameters();
    } else {
        os << "embedded crypto context: (none)\n";
    }
    return os.str();
}

Ciphertext Ciphertext::deserialize(const Context& /*ctx*/, std::span<const std::byte> bytes) {
    std::stringstream ss;
    ss.write(reinterpret_cast<const char*>(bytes.data()),
             static_cast<std::streamsize>(bytes.size()));

    Ciphertext ct;
    ct.impl_ = std::make_unique<Impl>();
    lbcrypto::Serial::Deserialize(ct.impl_->ct, ss, lbcrypto::SerType::BINARY);
    if (!ct.impl_->ct) {
        throw std::runtime_error("Ciphertext deserialization produced a null ciphertext");
    }
    return ct;
}

}  // namespace fhe_toolkit::crypto
