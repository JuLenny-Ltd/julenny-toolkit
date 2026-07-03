#include <catch2/catch_test_macros.hpp>

#include "crypto/context.h"
#include "crypto/keys.h"

using namespace fhe_toolkit::crypto;

TEST_CASE("CryptoContextSpec lookup", "[crypto][context]") {
    auto spec = get_crypto_context_spec("bfv-default-v1");
    REQUIRE(spec.has_value());
    REQUIRE(spec->scheme == "BFV");
    REQUIRE(spec->plaintext_modulus == 65537);

    REQUIRE_FALSE(get_crypto_context_spec("nonexistent").has_value());
}

TEST_CASE("Context construction with unsupported scheme throws", "[crypto][context]") {
    CryptoContextSpec bad;
    bad.id = "bogus";
    // Pick a scheme name that is genuinely unsupported. Original version of
    // this test used "CKKS" and relied on a coincidental throw inside
    // SetMultipartyMode (since removed in 0.5.2 when CKKS keysetup actually
    // started working). The intent was always "scheme not in the dispatch
    // table"; "TFHE" satisfies that intent without relying on a side-effect.
    bad.scheme = "TFHE";
    REQUIRE_THROWS_AS(Context(bad), std::runtime_error);
}

TEST_CASE("Generate keypair and round-trip serialization", "[crypto][keys]") {
    Context ctx(*get_crypto_context_spec("bfv-default-v1"));
    auto kp = ctx.generate_keypair();

    SECTION("freshly generated keys are non-empty") {
        REQUIRE_FALSE(kp.public_key.empty());
        REQUIRE_FALSE(kp.secret_key.empty());
    }

    // NOTE: OpenFHE binary serialization is not byte-deterministic, so we
    // can't assert bytes1 == bytes2 after a serialize->deserialize->serialize
    // round trip. Full functional verification (encrypt with deserialized pk,
    // decrypt with original sk -> round trip) lands once Ciphertext is in.

    SECTION("PublicKey serializes, deserializes, and re-serializes") {
        auto bytes1 = kp.public_key.serialize();
        REQUIRE_FALSE(bytes1.empty());

        auto pk2 = PublicKey::deserialize(ctx, bytes1);
        REQUIRE_FALSE(pk2.empty());

        auto bytes2 = pk2.serialize();
        REQUIRE_FALSE(bytes2.empty());
    }

    SECTION("SecretKey serializes, deserializes, and re-serializes") {
        auto bytes1 = kp.secret_key.serialize();
        REQUIRE_FALSE(bytes1.empty());

        auto sk2 = SecretKey::deserialize(ctx, bytes1);
        REQUIRE_FALSE(sk2.empty());

        auto bytes2 = sk2.serialize();
        REQUIRE_FALSE(bytes2.empty());
    }

    SECTION("Empty key serialize throws") {
        PublicKey empty_pk;
        SecretKey empty_sk;
        REQUIRE(empty_pk.empty());
        REQUIRE(empty_sk.empty());
        REQUIRE_THROWS_AS(empty_pk.serialize(), std::runtime_error);
        REQUIRE_THROWS_AS(empty_sk.serialize(), std::runtime_error);
    }
}
