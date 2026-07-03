#include "crypto/context.h"
#include "crypto/keys.h"
#include "crypto/ciphertext.h"
#include "crypto/eval_keys.h"
#include "internal.h"

#include <cstring>
#include <sstream>

#include <ciphertext-ser.h>
#include <cryptocontext-ser.h>
#include <scheme/bfvrns/bfvrns-ser.h>
#include <scheme/ckksrns/ckksrns-ser.h>

#include <map>
#include <memory>
#include <stdexcept>
#include <string>

namespace fhe_toolkit::crypto {

namespace {

void apply_security_level(auto& params, const CryptoContextSpec& spec) {
    if (spec.security_level == "HEStd_128_classic") {
        params.SetSecurityLevel(lbcrypto::HEStd_128_classic);
    } else if (spec.security_level == "HEStd_192_classic") {
        params.SetSecurityLevel(lbcrypto::HEStd_192_classic);
    } else if (spec.security_level == "HEStd_256_classic") {
        params.SetSecurityLevel(lbcrypto::HEStd_256_classic);
    } else {
        throw std::runtime_error("unknown security level: " + spec.security_level);
    }
}

// Apply key_switch_technique. Required for CKKS multi-party joint-key gen
// to produce a context that's deterministically reproducible across parties;
// without an explicit value, OpenFHE's default differs by build/scheme and
// the resulting joint key fails ValidateKey() during encrypt.
void apply_key_switch_technique(auto& params, const CryptoContextSpec& spec) {
    if (spec.key_switch_technique == "HYBRID") {
        params.SetKeySwitchTechnique(lbcrypto::HYBRID);
    } else if (spec.key_switch_technique == "BV") {
        params.SetKeySwitchTechnique(lbcrypto::BV);
    } else {
        throw std::runtime_error("unknown key switch technique: " + spec.key_switch_technique);
    }
}

// Apply multiparty_mode. NOTE: OpenFHE only exposes this setter on the BFV
// (BFVRNS) params class - CKKS's CCParams<CryptoContextCKKSRNS> deliberately
// throws ("This function is not available for CKKSRNS") because CKKS multi-
// party is hardwired to NOISE_FLOODING_MULTIPARTY internally and offers no
// toggle. So this helper is only safe to call from build_bfv_context.
void apply_multiparty_mode_bfv(auto& params, const CryptoContextSpec& spec) {
    if (spec.multiparty_mode == "NOISE_FLOODING_MULTIPARTY") {
        params.SetMultipartyMode(lbcrypto::NOISE_FLOODING_MULTIPARTY);
    } else if (spec.multiparty_mode == "FIXED_NOISE_MULTIPARTY") {
        params.SetMultipartyMode(lbcrypto::FIXED_NOISE_MULTIPARTY);
    } else {
        throw std::runtime_error("unknown multiparty mode: " + spec.multiparty_mode);
    }
}

void enable_features(OpenFheContext& cc) {
    cc->Enable(lbcrypto::PKE);
    cc->Enable(lbcrypto::KEYSWITCH);
    cc->Enable(lbcrypto::LEVELEDSHE);
    cc->Enable(lbcrypto::MULTIPARTY);
    cc->Enable(lbcrypto::ADVANCEDSHE);
}

OpenFheContext build_bfv_context(const CryptoContextSpec& spec) {
    lbcrypto::CCParams<lbcrypto::CryptoContextBFVRNS> params;
    params.SetPlaintextModulus(spec.plaintext_modulus);
    params.SetMultiplicativeDepth(spec.multiplicative_depth);
    apply_security_level(params, spec);
    apply_key_switch_technique(params, spec);
    apply_multiparty_mode_bfv(params, spec);
    if (spec.ring_dimension > 0) params.SetRingDim(spec.ring_dimension);
    if (spec.batch_size > 0)     params.SetBatchSize(spec.batch_size);

    auto cc = lbcrypto::GenCryptoContext(params);
    enable_features(cc);
    return cc;
}

OpenFheContext build_ckks_context(const CryptoContextSpec& spec) {
    lbcrypto::CCParams<lbcrypto::CryptoContextCKKSRNS> params;
    params.SetMultiplicativeDepth(spec.multiplicative_depth);
    params.SetScalingModSize(spec.scaling_mod_size);
    params.SetFirstModSize(spec.first_mod_size);

    if (spec.scaling_technique == "FLEXIBLEAUTO") {
        params.SetScalingTechnique(lbcrypto::FLEXIBLEAUTO);
    } else if (spec.scaling_technique == "FIXEDAUTO") {
        params.SetScalingTechnique(lbcrypto::FIXEDAUTO);
    } else if (spec.scaling_technique == "FIXEDMANUAL") {
        params.SetScalingTechnique(lbcrypto::FIXEDMANUAL);
    } else {
        throw std::runtime_error("unknown scaling technique: " + spec.scaling_technique);
    }

    apply_security_level(params, spec);
    apply_key_switch_technique(params, spec);
    // SetMultipartyMode is BFV-only (OpenFHE throws for CKKSRNS). For CKKS
    // threshold the equivalent is SetDecryptionNoiseMode + SetNoiseEstimate,
    // and these MUST byte-match the wrapper's eval context or ciphertexts fail
    // to deserialize at compute. The wrapper sets NOISE_FLOODING_DECRYPT plus
    // the spec's noiseEstimate; mirror it exactly here.
    params.SetDecryptionNoiseMode(lbcrypto::NOISE_FLOODING_DECRYPT);
    params.SetNoiseEstimate(spec.noise_estimate);

    if (spec.ring_dimension > 0) params.SetRingDim(spec.ring_dimension);
    if (spec.batch_size > 0)     params.SetBatchSize(spec.batch_size);

    auto cc = lbcrypto::GenCryptoContext(params);
    enable_features(cc);
    return cc;
}

}  // namespace

std::optional<CryptoContextSpec> get_crypto_context_spec(std::string_view id) {
    if (id == "bfv-default-v1") {
        CryptoContextSpec s;
        s.id = "bfv-default-v1";
        s.scheme = "BFV";
        s.plaintext_modulus = 65537;
        s.security_level = "HEStd_128_classic";
        s.multiplicative_depth = 4;
        return s;
    }
    if (id == "ckks-default-v1") {
        CryptoContextSpec s;
        s.id = "ckks-default-v1";
        s.scheme = "CKKS";
        s.scaling_mod_size = 50;
        s.first_mod_size = 60;
        s.scaling_technique = "FLEXIBLEAUTO";
        s.security_level = "HEStd_128_classic";
        s.multiplicative_depth = 4;
        s.ring_dimension = 16384;
        s.key_switch_technique = "HYBRID";
        s.multiparty_mode = "NOISE_FLOODING_MULTIPARTY";
        s.noise_estimate = 20.0;  // must match wrapper's ckks-default-v1 SetNoiseEstimate
        return s;
    }
    if (id == "ckks-tree-v1") {
        // Deep CKKS context for decision-tree-inference (soft-if mux tree).
        // MUST byte-match the wrapper's ckks-tree-v1 eval context or compute
        // fails / the golden sample diverges. Source of truth (platform side):
        // backend/schemas/seed-data/ckks-tree-v1.json.
        CryptoContextSpec s;
        s.id = "ckks-tree-v1";
        s.scheme = "CKKS";
        s.scaling_mod_size = 50;
        s.first_mod_size = 60;
        s.scaling_technique = "FLEXIBLEAUTO";
        s.security_level = "HEStd_128_classic";
        s.multiplicative_depth = 13;
        s.ring_dimension = 65536;
        s.key_switch_technique = "HYBRID";
        s.multiparty_mode = "NOISE_FLOODING_MULTIPARTY";
        s.noise_estimate = 30.0;  // must match wrapper's ckks-tree-v1 SetNoiseEstimate
        return s;
    }
    return std::nullopt;
}

Context::Context(CryptoContextSpec spec)
    : impl_(std::make_unique<Impl>()), spec_(std::move(spec)) {
    if (spec_.scheme == "BFV") {
        impl_->cc = build_bfv_context(spec_);
    } else if (spec_.scheme == "CKKS") {
        impl_->cc = build_ckks_context(spec_);
    } else {
        throw std::runtime_error("unsupported scheme: " + spec_.scheme);
    }
}

Context::~Context() = default;
Context::Context(Context&&) noexcept = default;
Context& Context::operator=(Context&&) noexcept = default;

// --- Single-party ---

KeyPair Context::generate_keypair() const {
    auto native = impl_->cc->KeyGen();
    KeyPair kp;
    kp.public_key.impl_ = std::make_unique<PublicKey::Impl>();
    kp.public_key.impl_->key = native.publicKey;
    kp.secret_key.impl_ = std::make_unique<SecretKey::Impl>();
    kp.secret_key.impl_->key = native.secretKey;
    return kp;
}

PlaintextPacked Context::encode_packed(const std::vector<int64_t>& values) const {
    PlaintextPacked pt;
    pt.impl_ = std::make_unique<PlaintextPacked::Impl>();
    pt.impl_->pt = impl_->cc->MakePackedPlaintext(values);
    return pt;
}

PlaintextPacked Context::encode_ckks_packed(const std::vector<double>& values) const {
    if (spec_.scheme != "CKKS") {
        throw std::runtime_error("encode_ckks_packed called on non-CKKS context: " + spec_.scheme);
    }
    PlaintextPacked pt;
    pt.impl_ = std::make_unique<PlaintextPacked::Impl>();
    pt.impl_->pt = impl_->cc->MakeCKKSPackedPlaintext(values);
    return pt;
}

Ciphertext Context::encrypt(const PublicKey& pk, const PlaintextPacked& pt) const {
    if (pk.empty()) throw std::runtime_error("cannot encrypt with empty PublicKey");
    if (pt.empty()) throw std::runtime_error("cannot encrypt empty PlaintextPacked");
    Ciphertext ct;
    ct.impl_ = std::make_unique<Ciphertext::Impl>();
    ct.impl_->ct = impl_->cc->Encrypt(pk.impl_->key, pt.impl_->pt);
    return ct;
}

std::vector<std::byte> Context::serialize_ciphertext_vector(
    const std::vector<Ciphertext>& cts) const {
    if (cts.empty()) throw std::runtime_error("serialize_ciphertext_vector: empty vector");
    std::vector<OpenFheCiphertext> raw;
    raw.reserve(cts.size());
    for (const auto& c : cts) {
        if (c.empty()) {
            throw std::runtime_error("serialize_ciphertext_vector: empty ciphertext in vector");
        }
        raw.push_back(c.impl_->ct);
    }
    std::stringstream ss;
    lbcrypto::Serial::Serialize(raw, ss, lbcrypto::SerType::BINARY);
    const std::string str = ss.str();
    std::vector<std::byte> out(str.size());
    if (!str.empty()) std::memcpy(out.data(), str.data(), str.size());
    return out;
}

PlaintextPacked Context::decrypt(const SecretKey& sk, const Ciphertext& ct) const {
    if (sk.empty()) throw std::runtime_error("cannot decrypt with empty SecretKey");
    if (ct.empty()) throw std::runtime_error("cannot decrypt empty Ciphertext");
    PlaintextPacked pt;
    pt.impl_ = std::make_unique<PlaintextPacked::Impl>();
    impl_->cc->Decrypt(sk.impl_->key, ct.impl_->ct, &pt.impl_->pt);
    return pt;
}

// --- Multi-party keygen + decryption ---

KeyPair Context::multiparty_keygen() const { return generate_keypair(); }

KeyPair Context::multiparty_keygen(const PublicKey& prev_joint_pk) const {
    if (prev_joint_pk.empty()) throw std::runtime_error("multiparty_keygen: prev_joint_pk is empty");
    auto native = impl_->cc->MultipartyKeyGen(prev_joint_pk.impl_->key);
    KeyPair kp;
    kp.public_key.impl_ = std::make_unique<PublicKey::Impl>();
    kp.public_key.impl_->key = native.publicKey;
    kp.secret_key.impl_ = std::make_unique<SecretKey::Impl>();
    kp.secret_key.impl_->key = native.secretKey;
    return kp;
}

Ciphertext Context::partial_decrypt_lead(const SecretKey& sk, const Ciphertext& ct) const {
    if (sk.empty()) throw std::runtime_error("partial_decrypt_lead: empty SecretKey");
    if (ct.empty()) throw std::runtime_error("partial_decrypt_lead: empty Ciphertext");
    std::vector<OpenFheCiphertext> in = { ct.impl_->ct };
    auto out = impl_->cc->MultipartyDecryptLead(in, sk.impl_->key);
    if (out.empty()) throw std::runtime_error("MultipartyDecryptLead returned empty vector");
    Ciphertext partial;
    partial.impl_ = std::make_unique<Ciphertext::Impl>();
    partial.impl_->ct = out[0];
    return partial;
}

Ciphertext Context::partial_decrypt_main(const SecretKey& sk, const Ciphertext& ct) const {
    if (sk.empty()) throw std::runtime_error("partial_decrypt_main: empty SecretKey");
    if (ct.empty()) throw std::runtime_error("partial_decrypt_main: empty Ciphertext");
    std::vector<OpenFheCiphertext> in = { ct.impl_->ct };
    auto out = impl_->cc->MultipartyDecryptMain(in, sk.impl_->key);
    if (out.empty()) throw std::runtime_error("MultipartyDecryptMain returned empty vector");
    Ciphertext partial;
    partial.impl_ = std::make_unique<Ciphertext::Impl>();
    partial.impl_->ct = out[0];
    return partial;
}

PlaintextPacked Context::combine_partials(
    const std::vector<const Ciphertext*>& partials) const {
    if (partials.size() < 2) throw std::runtime_error("combine_partials: need at least 2");
    std::vector<OpenFheCiphertext> in;
    in.reserve(partials.size());
    for (const auto* p : partials) {
        if (!p || p->empty()) throw std::runtime_error("combine_partials: null or empty partial");
        in.push_back(p->impl_->ct);
    }
    PlaintextPacked pt;
    pt.impl_ = std::make_unique<PlaintextPacked::Impl>();
    impl_->cc->MultipartyDecryptFusion(in, &pt.impl_->pt);
    return pt;
}

// --- 2-party local setup helper (T2.7.b) ---

void Context::setup_joint_eval_keys_2party(const KeyPair& partyA, const KeyPair& partyB) {
    if (partyA.public_key.empty() || partyA.secret_key.empty() ||
        partyB.public_key.empty() || partyB.secret_key.empty()) {
        throw std::runtime_error("setup_joint_eval_keys_2party: both parties' keys required");
    }
    auto& cc = impl_->cc;
    const auto& skA = partyA.secret_key.impl_->key;
    const auto& skB = partyB.secret_key.impl_->key;
    const auto& jointPk = partyB.public_key.impl_->key;
    const std::string joint_tag = jointPk->GetKeyTag();

    auto evalMultA = cc->KeySwitchGen(skA, skA);
    auto evalMultB = cc->MultiKeySwitchGen(skB, skB, evalMultA);
    auto evalMultAB = cc->MultiAddEvalKeys(evalMultA, evalMultB, joint_tag);
    auto evalMultAAB = cc->MultiMultEvalKey(skA, evalMultAB, joint_tag);
    auto evalMultBAB = cc->MultiMultEvalKey(skB, evalMultAB, joint_tag);
    auto evalMultFinal = cc->MultiAddEvalMultKeys(evalMultAAB, evalMultBAB,
                                                   evalMultAB->GetKeyTag());
    cc->InsertEvalMultKey({evalMultFinal});

    cc->EvalSumKeyGen(skA);
    auto evalSumKeysA = std::make_shared<std::map<uint32_t, OpenFheEvalKey>>(
        cc->GetEvalSumKeyMap(skA->GetKeyTag()));
    auto evalSumKeysB = cc->MultiEvalSumKeyGen(skB, evalSumKeysA, joint_tag);
    auto evalSumKeysJoin = cc->MultiAddEvalSumKeys(evalSumKeysA, evalSumKeysB, joint_tag);
    cc->InsertEvalSumKey(evalSumKeysJoin);
}

// --- Protocol-driven relin key generation (T2.7.c) ---

EvalKey Context::relin_round1_initial(const SecretKey& sk) const {
    if (sk.empty()) throw std::runtime_error("relin_round1_initial: empty sk");
    EvalKey out;
    out.impl_ = std::make_unique<EvalKey::Impl>();
    out.impl_->key = impl_->cc->KeySwitchGen(sk.impl_->key, sk.impl_->key);
    return out;
}

EvalKey Context::relin_round1_continue(const SecretKey& sk, const EvalKey& prev) const {
    if (sk.empty()) throw std::runtime_error("relin_round1_continue: empty sk");
    if (prev.empty()) throw std::runtime_error("relin_round1_continue: empty prev");
    EvalKey out;
    out.impl_ = std::make_unique<EvalKey::Impl>();
    out.impl_->key = impl_->cc->MultiKeySwitchGen(sk.impl_->key, sk.impl_->key, prev.impl_->key);
    return out;
}

EvalKey Context::relin_combine_round1(const EvalKey& a, const EvalKey& b,
                                       const PublicKey& joint_pk) const {
    if (a.empty() || b.empty()) throw std::runtime_error("relin_combine_round1: empty input");
    if (joint_pk.empty()) throw std::runtime_error("relin_combine_round1: empty joint_pk");
    EvalKey out;
    out.impl_ = std::make_unique<EvalKey::Impl>();
    out.impl_->key = impl_->cc->MultiAddEvalKeys(a.impl_->key, b.impl_->key,
                                                  joint_pk.impl_->key->GetKeyTag());
    return out;
}

EvalKey Context::relin_round2(const SecretKey& sk, const EvalKey& combined,
                               const PublicKey& joint_pk) const {
    if (sk.empty() || combined.empty() || joint_pk.empty()) {
        throw std::runtime_error("relin_round2: empty input");
    }
    EvalKey out;
    out.impl_ = std::make_unique<EvalKey::Impl>();
    out.impl_->key = impl_->cc->MultiMultEvalKey(sk.impl_->key, combined.impl_->key,
                                                  joint_pk.impl_->key->GetKeyTag());
    return out;
}

EvalKey Context::relin_combine_round2(const EvalKey& a, const EvalKey& b,
                                       const EvalKey& combined_round1) const {
    if (a.empty() || b.empty() || combined_round1.empty()) {
        throw std::runtime_error("relin_combine_round2: empty input");
    }
    EvalKey out;
    out.impl_ = std::make_unique<EvalKey::Impl>();
    out.impl_->key = impl_->cc->MultiAddEvalMultKeys(a.impl_->key, b.impl_->key,
                                                      combined_round1.impl_->key->GetKeyTag());
    return out;
}

void Context::install_relin_key(const EvalKey& final_key) {
    if (final_key.empty()) throw std::runtime_error("install_relin_key: empty key");
    impl_->cc->InsertEvalMultKey({final_key.impl_->key});
}

// --- Protocol-driven sum key generation (T2.7.c) ---

SumKeyMap Context::sum_round1_initial(const SecretKey& sk) const {
    if (sk.empty()) throw std::runtime_error("sum_round1_initial: empty sk");
    impl_->cc->EvalSumKeyGen(sk.impl_->key);
    SumKeyMap out;
    out.impl_ = std::make_unique<SumKeyMap::Impl>();
    out.impl_->keys = std::make_shared<std::map<uint32_t, OpenFheEvalKey>>(
        impl_->cc->GetEvalSumKeyMap(sk.impl_->key->GetKeyTag()));
    return out;
}

SumKeyMap Context::sum_round1_continue(const SecretKey& sk, const SumKeyMap& prev,
                                        const PublicKey& joint_pk) const {
    if (sk.empty() || prev.empty() || joint_pk.empty()) {
        throw std::runtime_error("sum_round1_continue: empty input");
    }
    SumKeyMap out;
    out.impl_ = std::make_unique<SumKeyMap::Impl>();
    out.impl_->keys = impl_->cc->MultiEvalSumKeyGen(sk.impl_->key, prev.impl_->keys,
                                                     joint_pk.impl_->key->GetKeyTag());
    return out;
}

SumKeyMap Context::sum_combine(const SumKeyMap& a, const SumKeyMap& b,
                                const PublicKey& joint_pk) const {
    if (a.empty() || b.empty() || joint_pk.empty()) {
        throw std::runtime_error("sum_combine: empty input");
    }
    SumKeyMap out;
    out.impl_ = std::make_unique<SumKeyMap::Impl>();
    out.impl_->keys = impl_->cc->MultiAddEvalSumKeys(a.impl_->keys, b.impl_->keys,
                                                      joint_pk.impl_->key->GetKeyTag());
    return out;
}

void Context::install_sum_keys(const SumKeyMap& final_map) {
    if (final_map.empty()) throw std::runtime_error("install_sum_keys: empty map");
    impl_->cc->InsertEvalSumKey(final_map.impl_->keys);
}

// --- Protocol-driven rotation key generation (Phase B / CKKS prep) ---
// Mirrors the sum-key protocol but for a caller-supplied set of indices.

RotationKeyMap Context::rotation_round1_initial(const SecretKey& sk,
                                                 const std::vector<int32_t>& indices) const {
    if (sk.empty()) throw std::runtime_error("rotation_round1_initial: empty sk");
    if (indices.empty()) throw std::runtime_error("rotation_round1_initial: indices empty");
    // Initial party: generate the at-index keys into the context, then pull
    // the resulting map out for sharing with peers.
    impl_->cc->EvalAtIndexKeyGen(sk.impl_->key, indices);
    RotationKeyMap out;
    out.impl_ = std::make_unique<RotationKeyMap::Impl>();
    out.impl_->keys = std::make_shared<std::map<uint32_t, OpenFheEvalKey>>(
        impl_->cc->GetEvalAutomorphismKeyMap(sk.impl_->key->GetKeyTag()));
    return out;
}

RotationKeyMap Context::rotation_round1_continue(const SecretKey& sk,
                                                  const RotationKeyMap& prev,
                                                  const std::vector<int32_t>& indices,
                                                  const PublicKey& joint_pk) const {
    if (sk.empty() || prev.empty() || joint_pk.empty()) {
        throw std::runtime_error("rotation_round1_continue: empty input");
    }
    if (indices.empty()) throw std::runtime_error("rotation_round1_continue: indices empty");
    RotationKeyMap out;
    out.impl_ = std::make_unique<RotationKeyMap::Impl>();
    out.impl_->keys = impl_->cc->MultiEvalAtIndexKeyGen(
        sk.impl_->key, prev.impl_->keys, indices,
        joint_pk.impl_->key->GetKeyTag());
    return out;
}

RotationKeyMap Context::rotation_combine(const RotationKeyMap& a, const RotationKeyMap& b,
                                          const PublicKey& joint_pk) const {
    if (a.empty() || b.empty() || joint_pk.empty()) {
        throw std::runtime_error("rotation_combine: empty input");
    }
    RotationKeyMap out;
    out.impl_ = std::make_unique<RotationKeyMap::Impl>();
    out.impl_->keys = impl_->cc->MultiAddEvalAutomorphismKeys(
        a.impl_->keys, b.impl_->keys,
        joint_pk.impl_->key->GetKeyTag());
    return out;
}

void Context::install_rotation_keys(const RotationKeyMap& final_map) {
    if (final_map.empty()) throw std::runtime_error("install_rotation_keys: empty map");
    impl_->cc->InsertEvalAutomorphismKey(final_map.impl_->keys);
}

// --- Homomorphic ops ---

Ciphertext Context::eval_mult(const Ciphertext& a, const Ciphertext& b) const {
    if (a.empty() || b.empty()) throw std::runtime_error("eval_mult: empty ciphertext input");
    Ciphertext out;
    out.impl_ = std::make_unique<Ciphertext::Impl>();
    out.impl_->ct = impl_->cc->EvalMult(a.impl_->ct, b.impl_->ct);
    return out;
}

Ciphertext Context::eval_sum(const Ciphertext& a, uint32_t batch_size) const {
    if (a.empty()) throw std::runtime_error("eval_sum: empty ciphertext input");
    if (batch_size == 0) throw std::runtime_error("eval_sum: batch_size must be > 0");
    Ciphertext out;
    out.impl_ = std::make_unique<Ciphertext::Impl>();
    out.impl_->ct = impl_->cc->EvalSum(a.impl_->ct, batch_size);
    return out;
}

Ciphertext Context::eval_rotate(const Ciphertext& a, int32_t index) const {
    if (a.empty()) throw std::runtime_error("eval_rotate: empty ciphertext input");
    Ciphertext out;
    out.impl_ = std::make_unique<Ciphertext::Impl>();
    out.impl_->ct = impl_->cc->EvalAtIndex(a.impl_->ct, index);
    return out;
}

}  // namespace fhe_toolkit::crypto
