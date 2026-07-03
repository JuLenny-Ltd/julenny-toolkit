#ifndef FHE_TOOLKIT_CRYPTO_EVAL_KEYS_H
#define FHE_TOOLKIT_CRYPTO_EVAL_KEYS_H

// Wrapper types for joint evaluation keys produced by the multi-party
// protocol. Used both as intermediate round messages (exchanged via the
// platform's keysetup endpoints) and as final joint eval keys (installed
// into a Context to enable EvalMult / EvalSum).

#include <cstddef>
#include <memory>
#include <span>
#include <vector>

namespace fhe_toolkit::crypto {

class Context;

// Wraps an OpenFHE EvalKey<DCRTPoly>. Used at every stage of the
// joint relinearization key protocol (round 1, combined, round 2,
// final). Serializable for transit through the platform.
class EvalKey {
public:
    EvalKey();
    ~EvalKey();
    EvalKey(const EvalKey&) = delete;
    EvalKey& operator=(const EvalKey&) = delete;
    EvalKey(EvalKey&&) noexcept;
    EvalKey& operator=(EvalKey&&) noexcept;

    bool empty() const noexcept;

    std::vector<std::byte> serialize() const;
    static EvalKey deserialize(const Context& ctx, std::span<const std::byte> bytes);

private:
    friend class Context;
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// Wraps OpenFHE's joint sum-key map (shared_ptr<map<uint32_t, EvalKey>>).
// Used for the joint sum-key protocol. Serializable for transit.
class SumKeyMap {
public:
    SumKeyMap();
    ~SumKeyMap();
    SumKeyMap(const SumKeyMap&) = delete;
    SumKeyMap& operator=(const SumKeyMap&) = delete;
    SumKeyMap(SumKeyMap&&) noexcept;
    SumKeyMap& operator=(SumKeyMap&&) noexcept;

    bool empty() const noexcept;

    std::vector<std::byte> serialize() const;
    static SumKeyMap deserialize(const Context& ctx, std::span<const std::byte> bytes);

private:
    friend class Context;
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// Wraps OpenFHE's joint rotation-key map (shared_ptr<map<uint32_t, EvalKey>>).
// Structurally identical to SumKeyMap but semantically distinct: rotation
// keys are produced by EvalAtIndexKeyGen / MultiEvalAtIndexKeyGen for a
// specific set of rotation indices (positive or negative shifts), while sum
// keys are produced by EvalSumKeyGen for the power-of-two automorphisms
// needed by EvalSum. Both serialize via OpenFHE's automorphism-key path.
class RotationKeyMap {
public:
    RotationKeyMap();
    ~RotationKeyMap();
    RotationKeyMap(const RotationKeyMap&) = delete;
    RotationKeyMap& operator=(const RotationKeyMap&) = delete;
    RotationKeyMap(RotationKeyMap&&) noexcept;
    RotationKeyMap& operator=(RotationKeyMap&&) noexcept;

    bool empty() const noexcept;

    std::vector<std::byte> serialize() const;
    static RotationKeyMap deserialize(const Context& ctx, std::span<const std::byte> bytes);

private:
    friend class Context;
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace fhe_toolkit::crypto

#endif
