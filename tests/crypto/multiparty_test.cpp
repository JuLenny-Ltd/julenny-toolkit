#include <catch2/catch_test_macros.hpp>

#include <cmath>
#include <vector>

#include "crypto/context.h"
#include "crypto/keys.h"
#include "crypto/ciphertext.h"

using namespace fhe_toolkit::crypto;

namespace {

// CKKS is approximate; post-decrypt values are real-valued with noise that
// grows with depth. These tolerances are wide enough for one EvalMult or one
// EvalAtIndex on ckks-default-v1 without being so wide that real bugs slip.
constexpr double CKKS_TOL_NOOP   = 1e-3;   // encode + encrypt + decrypt only
constexpr double CKKS_TOL_ONE_OP = 1e-1;   // one EvalMult / EvalRotate
constexpr double CKKS_TOL_DEPTH  = 1.0;    // multiple ops, conservative

inline bool approx_eq(double a, double b, double tol) {
    return std::abs(a - b) <= tol;
}

}  // namespace

TEST_CASE("Multiparty BFV: 2-party encrypt-decrypt round trip",
          "[crypto][multiparty]") {
    Context ctx(*get_crypto_context_spec("bfv-default-v1"));

    // Round 1: party A generates initial keypair.
    auto kpA = ctx.multiparty_keygen();
    REQUIRE_FALSE(kpA.public_key.empty());
    REQUIRE_FALSE(kpA.secret_key.empty());

    // Round 2: party B generates keypair on top of A's public key.
    auto kpB = ctx.multiparty_keygen(kpA.public_key);
    REQUIRE_FALSE(kpB.public_key.empty());
    REQUIRE_FALSE(kpB.secret_key.empty());

    // The joint public key is B's pk (which incorporates A's contribution).
    const auto& joint_pk = kpB.public_key;

    SECTION("small vector round-trips through joint key + partial decrypt") {
        const std::vector<int64_t> input = {7, 11, 13, 17, 19};
        auto pt = ctx.encode_packed(input);
        auto ct = ctx.encrypt(joint_pk, pt);
        REQUIRE_FALSE(ct.empty());

        // Each party computes its partial decryption.
        // Party A takes the lead role; B does main.
        auto partial_A = ctx.partial_decrypt_lead(kpA.secret_key, ct);
        auto partial_B = ctx.partial_decrypt_main(kpB.secret_key, ct);
        REQUIRE_FALSE(partial_A.empty());
        REQUIRE_FALSE(partial_B.empty());

        // Combine both partials -> recover plaintext.
        auto decoded = ctx.combine_partials({&partial_A, &partial_B});
        REQUIRE_FALSE(decoded.empty());

        auto values = decoded.values();
        REQUIRE(values.size() >= input.size());
        for (size_t i = 0; i < input.size(); ++i) {
            REQUIRE(values[i] == input[i]);
        }
    }

    SECTION("role-swapped lead/main also works") {
        const std::vector<int64_t> input = {-3, 0, 5, 200};
        auto pt = ctx.encode_packed(input);
        auto ct = ctx.encrypt(joint_pk, pt);

        // Swap: B takes the lead this time.
        auto partial_B = ctx.partial_decrypt_lead(kpB.secret_key, ct);
        auto partial_A = ctx.partial_decrypt_main(kpA.secret_key, ct);

        auto decoded = ctx.combine_partials({&partial_A, &partial_B});
        auto values = decoded.values();
        for (size_t i = 0; i < input.size(); ++i) {
            REQUIRE(values[i] == input[i]);
        }
    }

    SECTION("a single party's partial cannot recover the plaintext") {
        const std::vector<int64_t> input = {42, 1337};
        auto pt = ctx.encode_packed(input);
        auto ct = ctx.encrypt(joint_pk, pt);

        // Try to decrypt with only one party's secret key (no fusion).
        // OpenFHE's single-party decrypt should produce garbage or fail.
        try {
            auto bad_pt = ctx.decrypt(kpA.secret_key, ct);
            auto values = bad_pt.values();
            // If it didn't throw, the values should not match the original.
            bool any_match = false;
            for (size_t i = 0; i < input.size(); ++i) {
                if (values[i] == input[i]) { any_match = true; break; }
            }
            REQUIRE_FALSE(any_match);
        } catch (const std::exception&) {
            SUCCEED("single-party decrypt threw, which is fine");
        }
    }
}

TEST_CASE("Multiparty BFV: error handling", "[crypto][multiparty]") {
    Context ctx(*get_crypto_context_spec("bfv-default-v1"));

    SECTION("multiparty_keygen(prev) rejects an empty PublicKey") {
        PublicKey empty_pk;
        REQUIRE_THROWS_AS(ctx.multiparty_keygen(empty_pk), std::runtime_error);
    }

    SECTION("partial_decrypt with empty key throws") {
        auto kpA = ctx.multiparty_keygen();
        auto kpB = ctx.multiparty_keygen(kpA.public_key);
        auto pt = ctx.encode_packed({1});
        auto ct = ctx.encrypt(kpB.public_key, pt);

        SecretKey empty_sk;
        REQUIRE_THROWS_AS(ctx.partial_decrypt_lead(empty_sk, ct), std::runtime_error);
        REQUIRE_THROWS_AS(ctx.partial_decrypt_main(empty_sk, ct), std::runtime_error);
    }

    SECTION("combine_partials rejects fewer than 2 partials") {
        auto kpA = ctx.multiparty_keygen();
        auto kpB = ctx.multiparty_keygen(kpA.public_key);
        auto pt = ctx.encode_packed({1});
        auto ct = ctx.encrypt(kpB.public_key, pt);
        auto partial_A = ctx.partial_decrypt_lead(kpA.secret_key, ct);

        REQUIRE_THROWS_AS(ctx.combine_partials({&partial_A}), std::runtime_error);
        REQUIRE_THROWS_AS(ctx.combine_partials({}), std::runtime_error);
    }
}

TEST_CASE("Multiparty BFV: joint relin key enables EvalMult round-trip",
          "[crypto][multiparty][evalkeys]") {
    Context ctx(*get_crypto_context_spec("bfv-default-v1"));
    auto kpA = ctx.multiparty_keygen();
    auto kpB = ctx.multiparty_keygen(kpA.public_key);
    ctx.setup_joint_eval_keys_2party(kpA, kpB);

    const auto& joint_pk = kpB.public_key;

    SECTION("ciphertext-ciphertext multiplication round-trips") {
        const std::vector<int64_t> a_vals = {5, 7, 11, 13, 1};
        const std::vector<int64_t> b_vals = {3, 4, 5,  6,  100};
        auto pt_a = ctx.encode_packed(a_vals);
        auto pt_b = ctx.encode_packed(b_vals);
        auto ct_a = ctx.encrypt(joint_pk, pt_a);
        auto ct_b = ctx.encrypt(joint_pk, pt_b);

        auto ct_mult = ctx.eval_mult(ct_a, ct_b);
        REQUIRE_FALSE(ct_mult.empty());

        auto pA = ctx.partial_decrypt_lead(kpA.secret_key, ct_mult);
        auto pB = ctx.partial_decrypt_main(kpB.secret_key, ct_mult);
        auto decoded = ctx.combine_partials({&pA, &pB});

        auto values = decoded.values();
        REQUIRE(values[0] == 15);    // 5 * 3
        REQUIRE(values[1] == 28);    // 7 * 4
        REQUIRE(values[2] == 55);    // 11 * 5
        REQUIRE(values[3] == 78);    // 13 * 6
        REQUIRE(values[4] == 100);   // 1 * 100
    }

    SECTION("nested multiplications respect the configured depth") {
        // x * x * x with x = 4. multiplicative_depth=4 allows this.
        std::vector<int64_t> x_vals = {4};
        auto pt = ctx.encode_packed(x_vals);
        auto ct = ctx.encrypt(joint_pk, pt);

        auto x2 = ctx.eval_mult(ct, ct);      // 16
        auto x3 = ctx.eval_mult(x2, ct);      // 64

        auto pA = ctx.partial_decrypt_lead(kpA.secret_key, x3);
        auto pB = ctx.partial_decrypt_main(kpB.secret_key, x3);
        auto decoded = ctx.combine_partials({&pA, &pB});
        REQUIRE(decoded.values()[0] == 64);
    }
}

TEST_CASE("Multiparty BFV: joint sum key enables EvalSum",
          "[crypto][multiparty][evalkeys]") {
    Context ctx(*get_crypto_context_spec("bfv-default-v1"));
    auto kpA = ctx.multiparty_keygen();
    auto kpB = ctx.multiparty_keygen(kpA.public_key);
    ctx.setup_joint_eval_keys_2party(kpA, kpB);

    SECTION("sum of first 4 slots returned in slot 0") {
        const std::vector<int64_t> input = {1, 2, 3, 4};
        auto pt = ctx.encode_packed(input);
        auto ct = ctx.encrypt(kpB.public_key, pt);
        auto ct_sum = ctx.eval_sum(ct, 4);

        auto pA = ctx.partial_decrypt_lead(kpA.secret_key, ct_sum);
        auto pB = ctx.partial_decrypt_main(kpB.secret_key, ct_sum);
        auto decoded = ctx.combine_partials({&pA, &pB});
        REQUIRE(decoded.values()[0] == 10);  // 1+2+3+4
    }

    SECTION("sum of first 8 slots") {
        const std::vector<int64_t> input = {10, 20, 30, 40, 50, 60, 70, 80};
        auto pt = ctx.encode_packed(input);
        auto ct = ctx.encrypt(kpB.public_key, pt);
        auto ct_sum = ctx.eval_sum(ct, 8);

        auto pA = ctx.partial_decrypt_lead(kpA.secret_key, ct_sum);
        auto pB = ctx.partial_decrypt_main(kpB.secret_key, ct_sum);
        auto decoded = ctx.combine_partials({&pA, &pB});
        REQUIRE(decoded.values()[0] == 360);  // sum 10..80 step 10
    }
}

TEST_CASE("Multiparty BFV: combined mult + sum (search-text shape)",
          "[crypto][multiparty][evalkeys]") {
    Context ctx(*get_crypto_context_spec("bfv-default-v1"));
    auto kpA = ctx.multiparty_keygen();
    auto kpB = ctx.multiparty_keygen(kpA.public_key);
    ctx.setup_joint_eval_keys_2party(kpA, kpB);

    // Roughly the shape of search-text's outer loop:
    //   ct_indicator = ct_a * ct_b  (encrypted equality indicator stand-in)
    //   ct_count = sum_slots(ct_indicator)
    const std::vector<int64_t> a_vals = {1, 0, 1, 1, 0, 1, 0, 1};   // hits
    const std::vector<int64_t> b_vals = {1, 1, 1, 1, 1, 1, 1, 1};   // mask
    auto pt_a = ctx.encode_packed(a_vals);
    auto pt_b = ctx.encode_packed(b_vals);
    auto ct_a = ctx.encrypt(kpB.public_key, pt_a);
    auto ct_b = ctx.encrypt(kpB.public_key, pt_b);

    auto ct_indicator = ctx.eval_mult(ct_a, ct_b);
    auto ct_count = ctx.eval_sum(ct_indicator, 8);

    auto pA = ctx.partial_decrypt_lead(kpA.secret_key, ct_count);
    auto pB = ctx.partial_decrypt_main(kpB.secret_key, ct_count);
    auto decoded = ctx.combine_partials({&pA, &pB});

    // Expected count of 1s in a_vals = 5
    REQUIRE(decoded.values()[0] == 5);
}

#include "crypto/eval_keys.h"

TEST_CASE("Protocol-driven joint relin key: 2-party round-trip",
          "[crypto][multiparty][protocol]") {
    Context ctx(*get_crypto_context_spec("bfv-default-v1"));

    // Round 1 keygen
    auto kpA = ctx.multiparty_keygen();
    auto kpB = ctx.multiparty_keygen(kpA.public_key);
    const auto& joint_pk = kpB.public_key;

    // Relin protocol: 3 sub-rounds, per-party operations only.
    // Each party only sees their own secret share.

    // Round 1a: each party's initial contribution
    auto relA1 = ctx.relin_round1_initial(kpA.secret_key);
    auto relB1 = ctx.relin_round1_continue(kpB.secret_key, relA1);

    // Round 1b: combine (deterministic; both parties compute the same)
    auto relCombined1 = ctx.relin_combine_round1(relA1, relB1, joint_pk);

    // Round 2a: each party's final contribution
    auto relA2 = ctx.relin_round2(kpA.secret_key, relCombined1, joint_pk);
    auto relB2 = ctx.relin_round2(kpB.secret_key, relCombined1, joint_pk);

    // Round 2b: final combine
    auto relFinal = ctx.relin_combine_round2(relA2, relB2, relCombined1);

    // Install into context
    ctx.install_relin_key(relFinal);

    // Sum keys also needed for any non-trivial computation; do them via protocol too.
    auto sumA1 = ctx.sum_round1_initial(kpA.secret_key);
    auto sumB1 = ctx.sum_round1_continue(kpB.secret_key, sumA1, joint_pk);
    auto sumFinal = ctx.sum_combine(sumA1, sumB1, joint_pk);
    ctx.install_sum_keys(sumFinal);

    SECTION("EvalMult works after protocol-driven setup") {
        auto pt_a = ctx.encode_packed({5, 7, 11});
        auto pt_b = ctx.encode_packed({3, 4, 5});
        auto ct_a = ctx.encrypt(joint_pk, pt_a);
        auto ct_b = ctx.encrypt(joint_pk, pt_b);
        auto ct_mult = ctx.eval_mult(ct_a, ct_b);

        auto pA = ctx.partial_decrypt_lead(kpA.secret_key, ct_mult);
        auto pB = ctx.partial_decrypt_main(kpB.secret_key, ct_mult);
        auto decoded = ctx.combine_partials({&pA, &pB});

        auto values = decoded.values();
        REQUIRE(values[0] == 15);
        REQUIRE(values[1] == 28);
        REQUIRE(values[2] == 55);
    }

    SECTION("EvalSum works after protocol-driven setup") {
        auto pt = ctx.encode_packed({1, 2, 3, 4});
        auto ct = ctx.encrypt(joint_pk, pt);
        auto ct_sum = ctx.eval_sum(ct, 4);

        auto pA = ctx.partial_decrypt_lead(kpA.secret_key, ct_sum);
        auto pB = ctx.partial_decrypt_main(kpB.secret_key, ct_sum);
        auto decoded = ctx.combine_partials({&pA, &pB});
        REQUIRE(decoded.values()[0] == 10);
    }

    SECTION("Combined mult + sum after protocol-driven setup") {
        auto pt_a = ctx.encode_packed({1, 0, 1, 1, 0, 1, 0, 1});
        auto pt_b = ctx.encode_packed({1, 1, 1, 1, 1, 1, 1, 1});
        auto ct_a = ctx.encrypt(joint_pk, pt_a);
        auto ct_b = ctx.encrypt(joint_pk, pt_b);

        auto ct_indicator = ctx.eval_mult(ct_a, ct_b);
        auto ct_count = ctx.eval_sum(ct_indicator, 8);

        auto pA = ctx.partial_decrypt_lead(kpA.secret_key, ct_count);
        auto pB = ctx.partial_decrypt_main(kpB.secret_key, ct_count);
        auto decoded = ctx.combine_partials({&pA, &pB});
        REQUIRE(decoded.values()[0] == 5);
    }
}

TEST_CASE("EvalKey serialize / deserialize round-trip preserves usability",
          "[crypto][multiparty][protocol][serialization]") {
    Context ctx(*get_crypto_context_spec("bfv-default-v1"));
    auto kpA = ctx.multiparty_keygen();
    auto kpB = ctx.multiparty_keygen(kpA.public_key);
    const auto& joint_pk = kpB.public_key;

    // Run round-1a for both parties locally
    auto relA1 = ctx.relin_round1_initial(kpA.secret_key);
    auto relB1 = ctx.relin_round1_continue(kpB.secret_key, relA1);

    SECTION("EvalKey bytes -> deserialize -> usable in subsequent rounds") {
        auto a_bytes = relA1.serialize();
        auto b_bytes = relB1.serialize();
        REQUIRE_FALSE(a_bytes.empty());
        REQUIRE_FALSE(b_bytes.empty());

        auto a_restored = EvalKey::deserialize(ctx, a_bytes);
        auto b_restored = EvalKey::deserialize(ctx, b_bytes);
        REQUIRE_FALSE(a_restored.empty());
        REQUIRE_FALSE(b_restored.empty());

        // Continue the protocol with restored keys instead of originals.
        auto combined = ctx.relin_combine_round1(a_restored, b_restored, joint_pk);
        auto relA2 = ctx.relin_round2(kpA.secret_key, combined, joint_pk);
        auto relB2 = ctx.relin_round2(kpB.secret_key, combined, joint_pk);
        auto final_key = ctx.relin_combine_round2(relA2, relB2, combined);
        ctx.install_relin_key(final_key);

        // Sum keys (necessary for ADVANCEDSHE eval)
        auto sA1 = ctx.sum_round1_initial(kpA.secret_key);
        auto sB1 = ctx.sum_round1_continue(kpB.secret_key, sA1, joint_pk);
        ctx.install_sum_keys(ctx.sum_combine(sA1, sB1, joint_pk));

        // Verify EvalMult works
        auto pt = ctx.encode_packed({6, 0, 0});
        auto ct = ctx.encrypt(joint_pk, pt);
        auto ct_sq = ctx.eval_mult(ct, ct);
        auto pA = ctx.partial_decrypt_lead(kpA.secret_key, ct_sq);
        auto pB = ctx.partial_decrypt_main(kpB.secret_key, ct_sq);
        auto decoded = ctx.combine_partials({&pA, &pB});
        REQUIRE(decoded.values()[0] == 36);
    }
}

TEST_CASE("SumKeyMap serialize / deserialize round-trip preserves usability",
          "[crypto][multiparty][protocol][serialization]") {
    Context ctx(*get_crypto_context_spec("bfv-default-v1"));
    auto kpA = ctx.multiparty_keygen();
    auto kpB = ctx.multiparty_keygen(kpA.public_key);
    const auto& joint_pk = kpB.public_key;

    auto sumA1 = ctx.sum_round1_initial(kpA.secret_key);
    auto bytes = sumA1.serialize();
    REQUIRE_FALSE(bytes.empty());

    auto restored = SumKeyMap::deserialize(ctx, bytes);
    REQUIRE_FALSE(restored.empty());

    auto sumB1 = ctx.sum_round1_continue(kpB.secret_key, restored, joint_pk);
    auto final_sum = ctx.sum_combine(restored, sumB1, joint_pk);
    ctx.install_sum_keys(final_sum);

    // Relin keys via the local helper (we just need them present for EvalMult)
    // - alternative: do them via protocol too; sum is what we're testing here.
    // For pure EvalSum we don't strictly need relin, so skip it.
    auto pt = ctx.encode_packed({10, 20, 30, 40});
    auto ct = ctx.encrypt(joint_pk, pt);
    auto ct_sum = ctx.eval_sum(ct, 4);
    auto pA = ctx.partial_decrypt_lead(kpA.secret_key, ct_sum);
    auto pB = ctx.partial_decrypt_main(kpB.secret_key, ct_sum);
    auto decoded = ctx.combine_partials({&pA, &pB});
    REQUIRE(decoded.values()[0] == 100);
}

// ============================================================
// CKKS multiparty coverage
//
// Added in 0.5.4. The 0.5.0 - 0.5.2 release window shipped CKKS bugs because
// the multiparty test suite was BFV-only:
//   - 0.5.1: SetMultipartyMode threw at context construction for CKKSRNS;
//     would have been caught by any test that simply constructed a
//     ckks-default-v1 context.
//   - 0.5.2: cereal type-id mismatch on deserialize, traced to the CLI silently
//     defaulting --context-spec to bfv-default-v1; would have been caught by
//     a CKKS serialize/deserialize round-trip.
//
// These cases cover the construction + protocol surface for CKKS, plus the
// rotation-key path that rule-based-cross-match's pair-indicator-sum op depends
// on. The rotation test is the one the CLI selftest doesn't yet cover (it
// installs rotation keys but doesn't exercise EvalAtIndex).
// ============================================================

TEST_CASE("Multiparty CKKS: context construction succeeds for ckks-default-v1",
          "[crypto][multiparty][ckks]") {
    REQUIRE_NOTHROW(Context(*get_crypto_context_spec("ckks-default-v1")));
}

TEST_CASE("Multiparty CKKS: 2-party encrypt-decrypt round trip",
          "[crypto][multiparty][ckks]") {
    Context ctx(*get_crypto_context_spec("ckks-default-v1"));
    auto kpA = ctx.multiparty_keygen();
    REQUIRE_FALSE(kpA.public_key.empty());
    REQUIRE_FALSE(kpA.secret_key.empty());

    auto kpB = ctx.multiparty_keygen(kpA.public_key);
    REQUIRE_FALSE(kpB.public_key.empty());
    REQUIRE_FALSE(kpB.secret_key.empty());

    const auto& joint_pk = kpB.public_key;

    SECTION("small real vector round-trips") {
        const std::vector<double> input = {1.5, 2.25, -3.0, 4.125, 0.0};
        auto pt = ctx.encode_ckks_packed(input);
        auto ct = ctx.encrypt(joint_pk, pt);
        REQUIRE_FALSE(ct.empty());

        auto partial_A = ctx.partial_decrypt_lead(kpA.secret_key, ct);
        auto partial_B = ctx.partial_decrypt_main(kpB.secret_key, ct);
        REQUIRE_FALSE(partial_A.empty());
        REQUIRE_FALSE(partial_B.empty());

        auto decoded = ctx.combine_partials({&partial_A, &partial_B});
        REQUIRE_FALSE(decoded.empty());

        auto values = decoded.real_values();
        REQUIRE(values.size() >= input.size());
        for (size_t i = 0; i < input.size(); ++i) {
            REQUIRE(approx_eq(values[i], input[i], CKKS_TOL_NOOP));
        }
    }

    SECTION("indicator-style 0/1 vector round-trips cleanly") {
        std::vector<double> input(16, 0.0);
        input[3] = 1.0;
        input[7] = 1.0;
        input[11] = 1.0;
        auto pt = ctx.encode_ckks_packed(input);
        auto ct = ctx.encrypt(joint_pk, pt);

        auto pA = ctx.partial_decrypt_lead(kpA.secret_key, ct);
        auto pB = ctx.partial_decrypt_main(kpB.secret_key, ct);
        auto decoded = ctx.combine_partials({&pA, &pB});

        auto values = decoded.real_values();
        for (size_t i = 0; i < input.size(); ++i) {
            REQUIRE(approx_eq(values[i], input[i], CKKS_TOL_NOOP));
        }
    }
}

TEST_CASE("Multiparty CKKS: joint relin key enables EvalMult",
          "[crypto][multiparty][ckks][evalkeys]") {
    Context ctx(*get_crypto_context_spec("ckks-default-v1"));
    auto kpA = ctx.multiparty_keygen();
    auto kpB = ctx.multiparty_keygen(kpA.public_key);
    ctx.setup_joint_eval_keys_2party(kpA, kpB);

    const auto& joint_pk = kpB.public_key;

    const std::vector<double> a_vals = {1.0, 0.0, 1.0, 1.0, 0.0};
    const std::vector<double> b_vals = {1.0, 1.0, 0.0, 1.0, 1.0};
    auto pt_a = ctx.encode_ckks_packed(a_vals);
    auto pt_b = ctx.encode_ckks_packed(b_vals);
    auto ct_a = ctx.encrypt(joint_pk, pt_a);
    auto ct_b = ctx.encrypt(joint_pk, pt_b);

    auto ct_mult = ctx.eval_mult(ct_a, ct_b);
    REQUIRE_FALSE(ct_mult.empty());

    auto pA = ctx.partial_decrypt_lead(kpA.secret_key, ct_mult);
    auto pB = ctx.partial_decrypt_main(kpB.secret_key, ct_mult);
    auto decoded = ctx.combine_partials({&pA, &pB});

    auto values = decoded.real_values();
    REQUIRE(approx_eq(values[0], 1.0, CKKS_TOL_ONE_OP));
    REQUIRE(approx_eq(values[1], 0.0, CKKS_TOL_ONE_OP));
    REQUIRE(approx_eq(values[2], 0.0, CKKS_TOL_ONE_OP));
    REQUIRE(approx_eq(values[3], 1.0, CKKS_TOL_ONE_OP));
    REQUIRE(approx_eq(values[4], 0.0, CKKS_TOL_ONE_OP));
}

TEST_CASE("Multiparty CKKS: joint rotation key enables EvalAtIndex",
          "[crypto][multiparty][ckks][evalkeys][rotation]") {
    Context ctx(*get_crypto_context_spec("ckks-default-v1"));
    auto kpA = ctx.multiparty_keygen();
    auto kpB = ctx.multiparty_keygen(kpA.public_key);
    ctx.setup_joint_eval_keys_2party(kpA, kpB);

    const auto& joint_pk = kpB.public_key;

    const std::vector<double> input = {10.0, 20.0, 30.0, 40.0, 50.0};
    auto pt = ctx.encode_ckks_packed(input);
    auto ct = ctx.encrypt(joint_pk, pt);

    auto ct_rot = ctx.eval_rotate(ct, 1);
    REQUIRE_FALSE(ct_rot.empty());

    auto pA = ctx.partial_decrypt_lead(kpA.secret_key, ct_rot);
    auto pB = ctx.partial_decrypt_main(kpB.secret_key, ct_rot);
    auto decoded = ctx.combine_partials({&pA, &pB});

    auto values = decoded.real_values();
    REQUIRE(approx_eq(values[0], 20.0, CKKS_TOL_ONE_OP));
    REQUIRE(approx_eq(values[1], 30.0, CKKS_TOL_ONE_OP));
    REQUIRE(approx_eq(values[2], 40.0, CKKS_TOL_ONE_OP));
    REQUIRE(approx_eq(values[3], 50.0, CKKS_TOL_ONE_OP));
}

TEST_CASE("Multiparty CKKS: protocol-driven rotation keys + EvalAtIndex",
          "[crypto][multiparty][ckks][protocol][rotation]") {
    Context ctx(*get_crypto_context_spec("ckks-default-v1"));
    auto kpA = ctx.multiparty_keygen();
    auto kpB = ctx.multiparty_keygen(kpA.public_key);
    const auto& joint_pk = kpB.public_key;

    ctx.setup_joint_eval_keys_2party(kpA, kpB);

    const std::vector<int32_t> indices = {1, 3, 7};
    auto rotA = ctx.rotation_round1_initial(kpA.secret_key, indices);
    auto rotB = ctx.rotation_round1_continue(kpB.secret_key, rotA, indices, joint_pk);
    auto rotFinal = ctx.rotation_combine(rotA, rotB, joint_pk);
    ctx.install_rotation_keys(rotFinal);

    const std::vector<double> input = {100.0, 200.0, 300.0, 400.0,
                                        500.0, 600.0, 700.0, 800.0,
                                        900.0, 1000.0};
    auto pt = ctx.encode_ckks_packed(input);
    auto ct = ctx.encrypt(joint_pk, pt);

    SECTION("rotate by 1") {
        auto ct_rot = ctx.eval_rotate(ct, 1);
        auto pA = ctx.partial_decrypt_lead(kpA.secret_key, ct_rot);
        auto pB = ctx.partial_decrypt_main(kpB.secret_key, ct_rot);
        auto vals_pt = ctx.combine_partials({&pA, &pB});
        auto vals = vals_pt.real_values();
        REQUIRE(approx_eq(vals[0], 200.0, CKKS_TOL_ONE_OP));
        REQUIRE(approx_eq(vals[1], 300.0, CKKS_TOL_ONE_OP));
    }
    SECTION("rotate by 3") {
        auto ct_rot = ctx.eval_rotate(ct, 3);
        auto pA = ctx.partial_decrypt_lead(kpA.secret_key, ct_rot);
        auto pB = ctx.partial_decrypt_main(kpB.secret_key, ct_rot);
        auto vals_pt = ctx.combine_partials({&pA, &pB});
        auto vals = vals_pt.real_values();
        REQUIRE(approx_eq(vals[0], 400.0, CKKS_TOL_ONE_OP));
        REQUIRE(approx_eq(vals[1], 500.0, CKKS_TOL_ONE_OP));
    }
    SECTION("rotate by 7") {
        auto ct_rot = ctx.eval_rotate(ct, 7);
        auto pA = ctx.partial_decrypt_lead(kpA.secret_key, ct_rot);
        auto pB = ctx.partial_decrypt_main(kpB.secret_key, ct_rot);
        auto vals_pt = ctx.combine_partials({&pA, &pB});
        auto vals = vals_pt.real_values();
        REQUIRE(approx_eq(vals[0], 800.0, CKKS_TOL_ONE_OP));
        REQUIRE(approx_eq(vals[1], 900.0, CKKS_TOL_ONE_OP));
    }
}

TEST_CASE("Multiparty CKKS: rotation_combine is byte-deterministic",
          "[crypto][multiparty][ckks][rotation][serialization]") {
    Context ctx(*get_crypto_context_spec("ckks-default-v1"));
    auto kpA = ctx.multiparty_keygen();
    auto kpB = ctx.multiparty_keygen(kpA.public_key);
    const auto& joint_pk = kpB.public_key;

    const std::vector<int32_t> indices = {2, 5};
    auto rotA = ctx.rotation_round1_initial(kpA.secret_key, indices);
    auto rotB = ctx.rotation_round1_continue(kpB.secret_key, rotA, indices, joint_pk);

    auto combine_once  = ctx.rotation_combine(rotA, rotB, joint_pk).serialize();
    auto combine_twice = ctx.rotation_combine(rotA, rotB, joint_pk).serialize();
    REQUIRE(combine_once == combine_twice);
}

TEST_CASE("Multiparty CKKS: PublicKey + SecretKey serialize / deserialize",
          "[crypto][multiparty][ckks][serialization]") {
    Context ctx(*get_crypto_context_spec("ckks-default-v1"));
    auto kpA = ctx.multiparty_keygen();
    auto kpB = ctx.multiparty_keygen(kpA.public_key);

    auto pk_bytes = kpB.public_key.serialize();
    auto sk_bytes = kpA.secret_key.serialize();
    REQUIRE_FALSE(pk_bytes.empty());
    REQUIRE_FALSE(sk_bytes.empty());

    auto pk_restored = PublicKey::deserialize(ctx, pk_bytes);
    auto sk_restored = SecretKey::deserialize(ctx, sk_bytes);
    REQUIRE_FALSE(pk_restored.empty());
    REQUIRE_FALSE(sk_restored.empty());

    auto pt = ctx.encode_ckks_packed({3.14, 2.72, 1.41});
    auto ct = ctx.encrypt(pk_restored, pt);

    auto partial_A = ctx.partial_decrypt_lead(sk_restored, ct);
    auto partial_B = ctx.partial_decrypt_main(kpB.secret_key, ct);
    auto decoded = ctx.combine_partials({&partial_A, &partial_B});
    auto vals = decoded.real_values();
    REQUIRE(approx_eq(vals[0], 3.14, CKKS_TOL_NOOP));
    REQUIRE(approx_eq(vals[1], 2.72, CKKS_TOL_NOOP));
    REQUIRE(approx_eq(vals[2], 1.41, CKKS_TOL_NOOP));
}
