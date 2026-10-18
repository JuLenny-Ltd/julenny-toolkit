#include <catch2/catch_test_macros.hpp>

#include "crypto/context.h"
#include "crypto/keys.h"
#include "crypto/ciphertext.h"

using namespace fhe_toolkit::crypto;

TEST_CASE("encode -> encrypt -> decrypt round-trip", "[crypto][ciphertext]") {
    Context ctx(*get_crypto_context_spec("bfv-default-v1"));
    auto kp = ctx.generate_keypair();

    SECTION("small integer vector round-trips") {
        std::vector<int64_t> original = {1, 2, 3, 4, 5};
        auto pt = ctx.encode_packed(original);
        REQUIRE_FALSE(pt.empty());

        auto ct = ctx.encrypt(kp.public_key, pt);
        REQUIRE_FALSE(ct.empty());

        auto decoded = ctx.decrypt(kp.secret_key, ct);
        REQUIRE_FALSE(decoded.empty());

        auto values = decoded.values();
        REQUIRE(values.size() >= original.size());
        for (size_t i = 0; i < original.size(); ++i) {
            REQUIRE(values[i] == original[i]);
        }
    }

    SECTION("large integer vector round-trips") {
        std::vector<int64_t> original;
        for (int64_t i = 0; i < 100; ++i) original.push_back(i * 37 + 1);
        auto pt = ctx.encode_packed(original);
        auto ct = ctx.encrypt(kp.public_key, pt);
        auto decoded = ctx.decrypt(kp.secret_key, ct);
        auto values = decoded.values();
        for (size_t i = 0; i < original.size(); ++i) {
            REQUIRE(values[i] == original[i]);
        }
    }

    SECTION("zeros round-trip") {
        std::vector<int64_t> original = {0, 0, 0, 0};
        auto pt = ctx.encode_packed(original);
        auto ct = ctx.encrypt(kp.public_key, pt);
        auto decoded = ctx.decrypt(kp.secret_key, ct);
        auto values = decoded.values();
        for (size_t i = 0; i < original.size(); ++i) {
            REQUIRE(values[i] == 0);
        }
    }

    SECTION("Ciphertext serialize -> deserialize -> decrypt preserves plaintext") {
        std::vector<int64_t> original = {10, 20, 30, 40, 50};
        auto pt = ctx.encode_packed(original);
        auto ct1 = ctx.encrypt(kp.public_key, pt);

        auto bytes = ct1.serialize();
        REQUIRE_FALSE(bytes.empty());

        auto ct2 = Ciphertext::deserialize(ctx, bytes);
        REQUIRE_FALSE(ct2.empty());

        auto decoded = ctx.decrypt(kp.secret_key, ct2);
        auto values = decoded.values();
        for (size_t i = 0; i < original.size(); ++i) {
            REQUIRE(values[i] == original[i]);
        }
    }

    SECTION("encrypt with empty PublicKey throws") {
        auto pt = ctx.encode_packed({1, 2, 3});
        PublicKey empty_pk;
        REQUIRE_THROWS_AS(ctx.encrypt(empty_pk, pt), std::runtime_error);
    }

    SECTION("decrypt with empty SecretKey throws") {
        auto pt = ctx.encode_packed({1, 2, 3});
        auto ct = ctx.encrypt(kp.public_key, pt);
        SecretKey empty_sk;
        REQUIRE_THROWS_AS(ctx.decrypt(empty_sk, ct), std::runtime_error);
    }

    SECTION("decrypt with wrong SecretKey does not recover the original") {
        std::vector<int64_t> original = {42, 1337, 65000};
        auto pt = ctx.encode_packed(original);
        auto ct = ctx.encrypt(kp.public_key, pt);

        auto kp2 = ctx.generate_keypair();
        // OpenFHE may return garbage values or set an error status on the
        // plaintext rather than throwing. Either way the recovered values
        // must not match the originals.
        try {
            auto decoded = ctx.decrypt(kp2.secret_key, ct);
            auto values = decoded.values();
            bool any_match = false;
            for (size_t i = 0; i < original.size(); ++i) {
                if (values[i] == original[i]) { any_match = true; break; }
            }
            REQUIRE_FALSE(any_match);
        } catch (const std::exception&) {
            SUCCEED("decrypt threw with wrong key");
        }
    }
}
