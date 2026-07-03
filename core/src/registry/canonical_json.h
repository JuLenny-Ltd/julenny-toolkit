#ifndef FHE_TOOLKIT_REGISTRY_CANONICAL_JSON_H
#define FHE_TOOLKIT_REGISTRY_CANONICAL_JSON_H

// Canonical JSON serialization for cross-language signature verification.
//
// Produces byte-identical output to the platform-side TypeScript
// implementation at @fhe-platform/schemas/src/canonical-json.ts. The
// canonical form has:
//   - Object keys sorted lexicographically (UTF-8 byte order)
//   - No whitespace anywhere
//   - JSON-standard string escapes per RFC 8259 §7
//   - Numbers serialized as JavaScript JSON.stringify would
//   - Arrays preserve order; objects sort keys recursively
//
// Parity is verified by tests/registry/canonical_json_test.cpp running
// the third_party/schemas/canonical-json-test-vectors.json shipped from
// the platform repo. Any divergence is a signature-verification bug.

#include <cstddef>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace fhe_toolkit::registry {

// Returns the canonical JSON string for the given JSON value.
std::string canonical_json(const nlohmann::json& value);

// Returns the canonical bytes (UTF-8) for the given JSON value.
std::vector<std::byte> canonical_json_bytes(const nlohmann::json& value);

// Returns the canonical bytes of a function definition over the ALLOWLIST of
// fingerprint fields, matching the platform's functionDefinitionCanonicalBytes:
//   slug, version, scheme, cryptoContextSpec, requiredEvalKeys (null if absent),
//   inputs[name, role, encoding, layout, schema, schemaParams], opsHash,
//   output[name, layout].
// Every other field is excluded (name, description, category, status, registry,
// supportedEngines, per-input encodingRecipe, ...). This is the byte sequence
// the platform registry signs (and that we verify against).
std::vector<std::byte> function_definition_canonical_bytes(const nlohmann::json& fn_def);

}  // namespace fhe_toolkit::registry

#endif
