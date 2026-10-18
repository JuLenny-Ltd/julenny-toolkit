#include "registry/canonical_json.h"

#include <algorithm>
#include <cstring>
#include <utility>
#include <vector>

namespace fhe_toolkit::registry {

using nlohmann::json;

std::string canonical_json(const json& value) {
    if (value.is_object()) {
        // Collect entries; sort keys lexicographically by UTF-8 byte order.
        std::vector<std::pair<std::string, const json*>> entries;
        entries.reserve(value.size());
        for (auto it = value.cbegin(); it != value.cend(); ++it) {
            entries.emplace_back(it.key(), &it.value());
        }
        std::sort(entries.begin(), entries.end(),
                  [](const auto& a, const auto& b) { return a.first < b.first; });

        std::string out = "{";
        bool first = true;
        for (const auto& [k, vptr] : entries) {
            if (!first) out += ",";
            first = false;
            // json(k).dump() produces the properly escaped quoted string for the key.
            out += json(k).dump();
            out += ":";
            out += canonical_json(*vptr);
        }
        out += "}";
        return out;
    }

    if (value.is_array()) {
        std::string out = "[";
        bool first = true;
        for (const auto& v : value) {
            if (!first) out += ",";
            first = false;
            out += canonical_json(v);
        }
        out += "]";
        return out;
    }

    // Scalars: strings, numbers, booleans, null.
    // nlohmann::json::dump() produces JSON-correct output for all of these.
    return value.dump();
}

std::vector<std::byte> canonical_json_bytes(const json& value) {
    const std::string s = canonical_json(value);
    std::vector<std::byte> bytes(s.size());
    if (!s.empty()) std::memcpy(bytes.data(), s.data(), s.size());
    return bytes;
}

namespace {

// pick(): copy only the named keys that are present, mirroring the platform's
// TS pick() which keeps a key iff its value !== undefined. In nlohmann a key is
// "present" iff it exists in the object; an explicit JSON null is kept.
json pick(const json& obj, const std::vector<const char*>& keys) {
    json out = json::object();
    for (const char* k : keys) {
        auto it = obj.find(k);
        if (it != obj.end()) out[k] = *it;
    }
    return out;
}

}  // namespace

std::vector<std::byte> function_definition_canonical_bytes(const json& fn_def) {
    if (!fn_def.is_object()) {
        return canonical_json_bytes(fn_def);
    }

    // ALLOWLIST fingerprint (matches platform functionDefinitionCanonicalBytes).
    // Only these top-level fields are hashed; everything else (name, description,
    // category, status, registry, supportedEngines, ...) is excluded, and each
    // input keeps only the fingerprint keys (encodingRecipe is dropped).
    // Key order below is irrelevant: canonical_json() re-sorts keys.
    static const std::vector<const char*> kInputKeys =
        {"name", "role", "encoding", "layout", "schema", "schemaParams"};
    static const std::vector<const char*> kOutputKeys = {"name", "layout"};

    json fp = json::object();

    // Scalars / pass-through fields: present (incl. null) -> keep; absent -> omit
    // (mirrors a TS undefined being dropped by the canonicalizer).
    auto keep_if_present = [&](const char* key) {
        auto it = fn_def.find(key);
        if (it != fn_def.end()) fp[key] = *it;
    };
    keep_if_present("slug");
    keep_if_present("version");
    keep_if_present("scheme");
    keep_if_present("cryptoContextSpec");

    // requiredEvalKeys: `def.requiredEvalKeys ?? null` -> present-non-null keeps
    // the value; absent OR explicit null coerces to null and is ALWAYS emitted.
    {
        auto it = fn_def.find("requiredEvalKeys");
        if (it != fn_def.end() && !it->is_null()) fp["requiredEvalKeys"] = *it;
        else fp["requiredEvalKeys"] = json(nullptr);
    }

    // inputs: array -> map each object through pick(); a present non-array value
    // is kept as-is; absent -> omit.
    {
        auto it = fn_def.find("inputs");
        if (it != fn_def.end()) {
            if (it->is_array()) {
                json arr = json::array();
                for (const auto& inp : *it) {
                    arr.push_back(inp.is_object() ? pick(inp, kInputKeys) : inp);
                }
                fp["inputs"] = std::move(arr);
            } else {
                fp["inputs"] = *it;
            }
        }
    }

    // opsHash: commitment to the circuit, sha256(canonicalJson(ops)) lowercase hex.
    // The toolkit never receives `ops` (JuLenny IP); it takes opsHash verbatim from
    // /definition. Platform derives it from ops; both sides hash to identical bytes.
    keep_if_present("opsHash");

    // output: object -> pick {name, layout}; present non-object kept; absent -> omit.
    {
        auto it = fn_def.find("output");
        if (it != fn_def.end()) {
            if (it->is_object()) fp["output"] = pick(*it, kOutputKeys);
            else fp["output"] = *it;
        }
    }

    return canonical_json_bytes(fp);
}

}  // namespace fhe_toolkit::registry
