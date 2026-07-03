#ifndef FHE_TOOLKIT_CRYPTO_CONTEXT_H
#define FHE_TOOLKIT_CRYPTO_CONTEXT_H

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace fhe_toolkit::crypto {

class PublicKey;
class SecretKey;
class PlaintextPacked;
class Ciphertext;
class EvalKey;
class SumKeyMap;
class RotationKeyMap;
struct KeyPair;

struct CryptoContextSpec {
    std::string id;
    std::string scheme;             // "BFV" or "CKKS"

    // Shared.
    std::string security_level = "HEStd_128_classic";
    uint32_t multiplicative_depth = 4;
    uint32_t ring_dimension = 0;    // 0 = let OpenFHE pick
    uint32_t batch_size = 0;        // 0 = max for the ring
    std::string multiparty_mode = "NOISE_FLOODING_MULTIPARTY";
    std::string key_switch_technique = "HYBRID";

    // BFV-only.
    uint64_t plaintext_modulus = 65537;

    // CKKS-only.
    uint32_t scaling_mod_size = 50;
    uint32_t first_mod_size = 60;
    std::string scaling_technique = "FLEXIBLEAUTO";
    double noise_estimate = 0.0;    // CKKS NOISE_FLOODING_DECRYPT estimate; must match wrapper
};

std::optional<CryptoContextSpec> get_crypto_context_spec(std::string_view id);

class Context {
public:
    explicit Context(CryptoContextSpec spec);
    ~Context();

    Context(const Context&) = delete;
    Context& operator=(const Context&) = delete;
    Context(Context&&) noexcept;
    Context& operator=(Context&&) noexcept;

    // --- Single-party ---
    KeyPair generate_keypair() const;
    PlaintextPacked encode_packed(const std::vector<int64_t>& values) const;        // BFV
    PlaintextPacked encode_ckks_packed(const std::vector<double>& values) const;    // CKKS
    Ciphertext      encrypt(const PublicKey& pk, const PlaintextPacked& pt) const;
    PlaintextPacked decrypt(const SecretKey& sk, const Ciphertext& ct) const;

    // Serialize a whole vector of ciphertexts into ONE cereal BINARY archive
    // (a single Serial::Serialize call), returning the raw archive bytes.
    // Required by the decision-tree model bundle: separately-serialized
    // ciphertexts collide on cereal pointer IDs, so the wrapper needs them
    // archived together. Vector order is preserved.
    std::vector<std::byte> serialize_ciphertext_vector(
        const std::vector<Ciphertext>& cts) const;

    // --- Joint key generation + decryption ---
    KeyPair multiparty_keygen() const;
    KeyPair multiparty_keygen(const PublicKey& prev_joint_pk) const;
    Ciphertext partial_decrypt_lead(const SecretKey& sk, const Ciphertext& ct) const;
    Ciphertext partial_decrypt_main(const SecretKey& sk, const Ciphertext& ct) const;
    PlaintextPacked combine_partials(const std::vector<const Ciphertext*>& partials) const;

    // --- Local 2-party setup (T2.7.b) - test helper, both secrets accessible ---
    void setup_joint_eval_keys_2party(const KeyPair& partyA, const KeyPair& partyB);

    // --- Protocol-driven joint eval keys (T2.7.c) ---
    //
    // RELINEARIZATION KEY (3 sub-rounds):
    //
    // Round 1a: each party's initial contribution
    //   - Initial party (no prior input):     relin_round1_initial(sk)
    //   - Subsequent party (chains on prev):  relin_round1_continue(sk, prev)
    //
    // Round 1b: combine all parties' Round 1a contributions
    //   (deterministic; every party computes the same result)
    //   - relin_combine_round1(a, b, joint_pk)
    //
    // Round 2: each party's final contribution using the combined round 1
    //   - relin_round2(sk, combined_round1, joint_pk)
    //
    // Round 2b: final combine
    //   - relin_combine_round2(a, b, combined_round1)
    //
    // Install: install_relin_key(final)
    EvalKey relin_round1_initial(const SecretKey& sk) const;
    EvalKey relin_round1_continue(const SecretKey& sk, const EvalKey& prev) const;
    EvalKey relin_combine_round1(const EvalKey& a, const EvalKey& b,
                                  const PublicKey& joint_pk) const;
    EvalKey relin_round2(const SecretKey& sk, const EvalKey& combined,
                         const PublicKey& joint_pk) const;
    EvalKey relin_combine_round2(const EvalKey& a, const EvalKey& b,
                                  const EvalKey& combined_round1) const;
    void install_relin_key(const EvalKey& final_key);

    // SUM KEY (2 sub-rounds):
    //
    // Round 1: each party's contribution
    //   - Initial:     sum_round1_initial(sk)
    //   - Subsequent:  sum_round1_continue(sk, prev, joint_pk)
    //
    // Round 2: combine
    //   - sum_combine(a, b, joint_pk)
    //
    // Install: install_sum_keys(final)
    SumKeyMap sum_round1_initial(const SecretKey& sk) const;
    SumKeyMap sum_round1_continue(const SecretKey& sk, const SumKeyMap& prev,
                                   const PublicKey& joint_pk) const;
    SumKeyMap sum_combine(const SumKeyMap& a, const SumKeyMap& b,
                          const PublicKey& joint_pk) const;
    void install_sum_keys(const SumKeyMap& final_map);

    // ROTATION KEY (2 sub-rounds, mirrors sum-key protocol but for a
    // caller-supplied set of rotation indices). Used by functions whose
    // FHE circuit applies rotations (e.g. CKKS pipelines), declared via
    // the function-def's requiredEvalKeys = ["rotation", ...].
    //
    // Round 1: each party's contribution for the given indices
    //   - Initial:     rotation_round1_initial(sk, indices)
    //   - Subsequent:  rotation_round1_continue(sk, prev, indices, joint_pk)
    //
    // Round 2: combine
    //   - rotation_combine(a, b, joint_pk)
    //
    // Install: install_rotation_keys(final)
    RotationKeyMap rotation_round1_initial(const SecretKey& sk,
                                            const std::vector<int32_t>& indices) const;
    RotationKeyMap rotation_round1_continue(const SecretKey& sk,
                                             const RotationKeyMap& prev,
                                             const std::vector<int32_t>& indices,
                                             const PublicKey& joint_pk) const;
    RotationKeyMap rotation_combine(const RotationKeyMap& a, const RotationKeyMap& b,
                                     const PublicKey& joint_pk) const;
    void install_rotation_keys(const RotationKeyMap& final_map);

    // --- Homomorphic operations (require eval keys installed) ---
    Ciphertext eval_mult(const Ciphertext& a, const Ciphertext& b) const;
    Ciphertext eval_sum(const Ciphertext& a, uint32_t batch_size) const;
    // EvalAtIndex: cyclic rotation of slot vector by `index`. Positive index
    // rotates LEFT (e.g. index=1 maps slot[i] -> slot[i-1]). Requires the
    // rotation key for `index` to be installed (via install_rotation_keys
    // or setup_joint_eval_keys_2party). Same name in OpenFHE is EvalRotate
    // for CKKS / EvalAtIndex for BFV; both delegate to the same primitive.
    Ciphertext eval_rotate(const Ciphertext& a, int32_t index) const;

    const CryptoContextSpec& spec() const noexcept { return spec_; }

private:
    friend class PublicKey;
    friend class SecretKey;
    friend class PlaintextPacked;
    friend class Ciphertext;
    friend class EvalKey;
    friend class SumKeyMap;

    struct Impl;
    std::unique_ptr<Impl> impl_;
    CryptoContextSpec spec_;
};

}  // namespace fhe_toolkit::crypto

#endif
