#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>

#include <nlohmann/json.hpp>

#include "registry/canonical_json.h"

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

std::string bytes_to_hex(const std::vector<std::byte>& bytes) {
    static const char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (auto b : bytes) {
        const auto v = static_cast<unsigned char>(b);
        out.push_back(hex[v >> 4]);
        out.push_back(hex[v & 0x0f]);
    }
    return out;
}

}  // namespace

TEST_CASE("Canonical JSON matches platform test vectors", "[registry][canonical_json]") {
    const auto path = std::filesystem::path(FHE_TOOLKIT_SCHEMAS_DIR)
                    / "canonical-json-test-vectors.json";
    const auto contents = read_file(path);
    const auto vectors = json::parse(contents);
    REQUIRE(vectors.is_array());
    REQUIRE(!vectors.empty());

    int passed = 0;
    int failed = 0;
    for (const auto& tc : vectors) {
        const std::string description = tc.at("description").get<std::string>();
        const std::string expected_canonical = tc.at("expectedCanonical").get<std::string>();
        const std::string expected_hex = tc.at("expectedBytesHex").get<std::string>();

        const auto bytes = canonical_json_bytes(tc.at("input"));
        const auto actual_canonical = canonical_json(tc.at("input"));
        const auto actual_hex = bytes_to_hex(bytes);

        INFO("Test case: " << description);
        INFO("Expected canonical: " << expected_canonical);
        INFO("Actual canonical:   " << actual_canonical);
        INFO("Expected hex:       " << expected_hex);
        INFO("Actual hex:         " << actual_hex);

        if (actual_canonical == expected_canonical && actual_hex == expected_hex) {
            ++passed;
        } else {
            ++failed;
            FAIL_CHECK("vector parity failed: " << description);
        }
    }

    REQUIRE(failed == 0);
    REQUIRE(passed == static_cast<int>(vectors.size()));
}

TEST_CASE("function_definition_canonical_bytes strips registry block",
          "[registry][canonical_json]") {
    json fn = {
        {"slug", "test"},
        {"name", "T"},
        {"registry", {{"signature", "ignored"}}},
    };

    const auto with_reg    = canonical_json(fn);
    const auto bytes       = function_definition_canonical_bytes(fn);
    const std::string fn_canon(reinterpret_cast<const char*>(bytes.data()), bytes.size());

    REQUIRE(with_reg.find("\"registry\"") != std::string::npos);
    REQUIRE(fn_canon.find("\"registry\"") == std::string::npos);
    REQUIRE(fn_canon.find("\"slug\":\"test\"") != std::string::npos);
}
