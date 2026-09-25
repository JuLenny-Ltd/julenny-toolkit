#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <fstream>
#include <set>
#include <string>

#include <nlohmann/json.hpp>

#include "crypto/context.h"

using namespace fhe_toolkit::crypto;

namespace {

// The platform's seed document, vendored from platform/backend/schemas/seed-data/.
// platform/scratch/psi-spike/d1/run.sh checks the copies are byte-identical.
nlohmann::json load_seed(const std::string& name) {
    std::ifstream in(std::string(FHE_TOOLKIT_SCHEMAS_DIR) + "/seed-data/" + name + ".json");
    REQUIRE(in.is_open());
    return nlohmann::json::parse(in);
}

}  // namespace

TEST_CASE("bfv-exact-psi-v1 matches the platform seed document field for field",
          "[crypto][context-spec]") {
    const auto seed = load_seed("bfv-exact-psi-v1");
    const auto spec = get_crypto_context_spec("bfv-exact-psi-v1");
    REQUIRE(spec.has_value());

    // A field the platform sets that this test does not compare is a field the
    // toolkit silently ignores: fail on it rather than pass.
    const std::set<std::string> compared = {
        "name", "scheme", "ringDimension", "securityLevel", "multiplicativeDepth",
        "plaintextModulus", "keySwitchTechnique", "multipartyMode", "notes"};
    for (const auto& item : seed.items()) {
        INFO("seed field: " << item.key());
        CHECK(compared.count(item.key()) == 1);
    }

    CHECK(spec->id == seed.at("name").get<std::string>());
    CHECK(spec->scheme == seed.at("scheme").get<std::string>());
    CHECK(spec->ring_dimension == seed.at("ringDimension").get<uint32_t>());
    CHECK(spec->security_level ==
          "HEStd_" + std::to_string(seed.at("securityLevel").get<int>()) + "_classic");
    CHECK(spec->multiplicative_depth == seed.at("multiplicativeDepth").get<uint32_t>());
    CHECK(spec->plaintext_modulus == seed.at("plaintextModulus").get<uint64_t>());
    CHECK(spec->key_switch_technique == seed.at("keySwitchTechnique").get<std::string>());
    CHECK(spec->multiparty_mode == seed.at("multipartyMode").get<std::string>());
    // The seed has no batchSize; the wrapper then leaves it to OpenFHE, and so must the toolkit.
    CHECK(spec->batch_size == 0);
}
