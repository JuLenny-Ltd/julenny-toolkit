#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>

#include <nlohmann/json.hpp>

#include "registry/canonical_json.h"
#include "registry/hex.h"
#include "registry/signature.h"

using namespace fhe_toolkit::registry;
using nlohmann::json;

namespace {

std::string read_file(const std::filesystem::path& p) {
    std::ifstream in(p);
    if (!in) throw std::runtime_error("cannot open: " + p.string());
    std::stringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

}  // namespace

TEST_CASE("Ed25519 verifies the platform-signed function fixture",
          "[registry][signature]") {
    const auto path = std::filesystem::path(FHE_TOOLKIT_SCHEMAS_DIR)
                    / "signed-function-fixture.json";
    const auto fixture = json::parse(read_file(path));

    const auto pk_opt = hex_decode(fixture.at("publicKeyHex").get<std::string>());
    REQUIRE(pk_opt.has_value());
    REQUIRE(pk_opt->size() == 32);

    const auto canonical_opt = hex_decode(
        fixture.at("verification").at("canonicalBytesHex").get<std::string>());
    REQUIRE(canonical_opt.has_value());

    const auto sig_opt = hex_decode(
        fixture.at("verification").at("signatureHex").get<std::string>());
    REQUIRE(sig_opt.has_value());
    REQUIRE(sig_opt->size() == 64);

    SECTION("valid signature verifies against the recorded canonical bytes") {
        REQUIRE(verify_ed25519(*pk_opt, *canonical_opt, *sig_opt));
    }

    SECTION("our canonical JSON of the function-def matches the fixture's") {
        const auto& fn_def = fixture.at("signedFunctionDefinition");
        const auto our_canonical = function_definition_canonical_bytes(fn_def);
        REQUIRE(our_canonical == *canonical_opt);
    }

    SECTION("end-to-end verify_function_definition_signature on parsed JSON") {
        const auto& fn_def = fixture.at("signedFunctionDefinition");
        REQUIRE(verify_function_definition_signature(fn_def, *pk_opt));
    }

    SECTION("tampered signature fails") {
        auto bad_sig = *sig_opt;
        bad_sig[0] = static_cast<std::byte>(static_cast<unsigned char>(bad_sig[0]) ^ 0x01);
        REQUIRE_FALSE(verify_ed25519(*pk_opt, *canonical_opt, bad_sig));
    }

    SECTION("tampered message fails") {
        auto bad_msg = *canonical_opt;
        bad_msg.back() = static_cast<std::byte>(
            static_cast<unsigned char>(bad_msg.back()) ^ 0x01);
        REQUIRE_FALSE(verify_ed25519(*pk_opt, bad_msg, *sig_opt));
    }

    SECTION("wrong key size returns false instead of crashing") {
        std::vector<std::byte> short_pk(16);
        REQUIRE_FALSE(verify_ed25519(short_pk, *canonical_opt, *sig_opt));
    }

    SECTION("wrong sig size returns false instead of crashing") {
        std::vector<std::byte> short_sig(32);
        REQUIRE_FALSE(verify_ed25519(*pk_opt, *canonical_opt, short_sig));
    }
}

TEST_CASE("verify_function_definition_signature handles malformed inputs",
          "[registry][signature]") {
    const std::vector<std::byte> dummy_pk(32);

    SECTION("missing registry block") {
        json fn = { {"slug", "x"} };
        REQUIRE_FALSE(verify_function_definition_signature(fn, dummy_pk));
    }

    SECTION("registry not an object") {
        json fn = { {"slug", "x"}, {"registry", "not-an-object"} };
        REQUIRE_FALSE(verify_function_definition_signature(fn, dummy_pk));
    }

    SECTION("missing signature field") {
        json fn = { {"slug", "x"}, {"registry", {{"publishedBy", "x"}}} };
        REQUIRE_FALSE(verify_function_definition_signature(fn, dummy_pk));
    }

    SECTION("malformed base64 signature") {
        json fn = { {"slug", "x"}, {"registry", {{"signature", "not!base64@@"}}} };
        REQUIRE_FALSE(verify_function_definition_signature(fn, dummy_pk));
    }
}
