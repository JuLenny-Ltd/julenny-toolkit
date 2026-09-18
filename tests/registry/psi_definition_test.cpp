#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>

#include <nlohmann/json.hpp>

#include "registry/canonical_json.h"
#include "registry/hex.h"
#include "registry/signature.h"

// The exact-PSI function definitions (platform step E1), against this toolkit's fail-closed check.
//
// The platform signs them with its registry key; the fixture here is signed with a deterministic
// TEST key instead, so the cross-language property can be checked without the production secret:
// the same definition, canonicalized in TypeScript and in C++, must produce the same bytes, or a
// definition the platform signs is one this toolkit refuses to encrypt against.
//
// It also pins what `crypto encrypt --function-def` needs these definitions to say, since the
// encoder reads the role from input ORDER and the domain separator from schemaParams, and routes
// on `layout` before it ever looks at `schema`.

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

json load_fixture() {
    const auto path = std::filesystem::path(FHE_TOOLKIT_SCHEMAS_DIR) / "signed-psi-function-fixtures.json";
    return json::parse(read_file(path));
}

}  // namespace

TEST_CASE("the exact-PSI definitions verify across languages", "[registry][signature][psi]") {
    const auto fixture = load_fixture();
    const auto pk_opt = hex_decode(fixture.at("publicKeyHex").get<std::string>());
    REQUIRE(pk_opt.has_value());
    REQUIRE(pk_opt->size() == 32);
    REQUIRE(fixture.at("definitions").size() == 2);

    for (const auto& entry : fixture.at("definitions")) {
        const std::string slug = entry.at("slug").get<std::string>();
        CAPTURE(slug);
        const json& def = entry.at("signedFunctionDefinition");

        const auto expected = hex_decode(entry.at("verification").at("canonicalBytesHex").get<std::string>());
        REQUIRE(expected.has_value());

        SECTION(slug + ": our canonical JSON matches the platform's") {
            REQUIRE(function_definition_canonical_bytes(def) == *expected);
        }
        SECTION(slug + ": the signature verifies") {
            REQUIRE(verify_function_definition_signature(def, *pk_opt));
        }
        SECTION(slug + ": the circuit arrives as a commitment, not as ops") {
            REQUIRE(def.contains("opsHash"));
            REQUIRE_FALSE(def.contains("ops"));
        }

        // Catalog metadata is outside the fingerprint by design: the platform edits copy without
        // invalidating live grants. `variant` is new in E1 and must behave the same way.
        SECTION(slug + ": editing catalog metadata does not break the signature") {
            for (const char* field : { "variant", "family", "description", "name", "status", "richDescription" }) {
                json edited = def;
                edited[field] = "edited";
                CAPTURE(field);
                REQUIRE(verify_function_definition_signature(edited, *pk_opt));
            }
        }
        // ... but everything that decides what is actually computed is bound.
        SECTION(slug + ": the crypto identity and the encoding contract are bound") {
            json other_spec = def;
            other_spec["cryptoContextSpec"] = "bfv-default-v1";
            REQUIRE_FALSE(verify_function_definition_signature(other_spec, *pk_opt));

            json other_domain = def;
            other_domain["inputs"][0]["schemaParams"]["domainSeparator"] = "other-domain";
            REQUIRE_FALSE(verify_function_definition_signature(other_domain, *pk_opt));

            json other_schema = def;
            other_schema["inputs"][1]["schema"] = "indicator-hash";
            REQUIRE_FALSE(verify_function_definition_signature(other_schema, *pk_opt));

            json other_circuit = def;
            other_circuit["opsHash"] = std::string(64, '0');
            REQUIRE_FALSE(verify_function_definition_signature(other_circuit, *pk_opt));

            json swapped_roles = def;
            std::swap(swapped_roles["inputs"][0], swapped_roles["inputs"][1]);
            REQUIRE_FALSE(verify_function_definition_signature(swapped_roles, *pk_opt));
        }
        SECTION(slug + ": an unsigned definition is refused") {
            json unsigned_def = def;
            unsigned_def.erase("registry");
            REQUIRE_FALSE(verify_function_definition_signature(unsigned_def, *pk_opt));
        }
    }
}

TEST_CASE("the exact-PSI definitions say what the encoder needs them to say", "[registry][psi]") {
    const auto fixture = load_fixture();
    for (const auto& entry : fixture.at("definitions")) {
        const std::string slug = entry.at("slug").get<std::string>();
        CAPTURE(slug);
        const json& def = entry.at("signedFunctionDefinition");

        REQUIRE(def.at("cryptoContextSpec") == "bfv-exact-psi-v1");
        REQUIRE(def.at("scheme") == "BFV");
        REQUIRE(def.at("variant") == "exact");
        REQUIRE(def.at("family") == "Joint Record Overlap");

        const json& inputs = def.at("inputs");
        REQUIRE(inputs.size() >= 2);
        for (std::size_t i = 0; i < 2; ++i) {
            CAPTURE(i);
            REQUIRE(inputs[i].at("schema") == "signature-table");
            // crypto encrypt dispatches on layout BEFORE schema: "encrypted-bundle" would send
            // these inputs to the generic bundle encoder and never reach the PSI encoder.
            REQUIRE(inputs[i].at("layout") == "signature-table-bundle");
            REQUIRE(inputs[i].at("layout") != "encrypted-bundle");
            // The encoder takes the domain separator from here, and both parties must match.
            REQUIRE(inputs[i].at("schemaParams").at("domainSeparator").get<std::string>() == "julenny-psi-v1");
            REQUIRE(inputs[i].at("schemaParams").at("hash") == "sha256");
            // Sizing is pinned per grant (step E2), never in the definition: the encoder does not
            // read it from here, so a value here would be a second, silent source of truth.
            for (const char* sizing : { "cells", "tables", "limbs", "countGroups", "signatureBits" }) {
                CAPTURE(sizing);
                REQUIRE_FALSE(inputs[i].at("schemaParams").contains(sizing));
            }
        }
        // Input ORDER decides the sentinel role: first input encodes as A, second as B.
        REQUIRE(inputs[0].at("role") == "dataOwner");
        REQUIRE(inputs[1].at("role") == "queryAnalyst");

        const json& keys = def.at("requiredEvalKeys");
        REQUIRE(keys == json::array({ "relinearization", "sum" }));
    }
}
