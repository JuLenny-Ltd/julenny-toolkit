#include "registry/envelope.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <cstdio>
#include <ctime>
#include <stdexcept>
#include <unordered_set>

#include "registry/canonical_json.h"
#include "registry/hex.h"

namespace fhe_toolkit::registry {

using nlohmann::json;

namespace {

constexpr std::string_view kStdAlphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void require(bool cond, const char* msg) {
    if (!cond) throw std::invalid_argument(msg);
}

}  // namespace

std::string base64_std_encode(std::span<const std::byte> bytes) {
    std::string out;
    // Each 3-byte block becomes 4 chars; round up.
    out.reserve(((bytes.size() + 2) / 3) * 4);

    std::size_t i = 0;
    while (i + 3 <= bytes.size()) {
        std::uint32_t v = (static_cast<std::uint32_t>(std::to_integer<unsigned char>(bytes[i]))     << 16) |
                          (static_cast<std::uint32_t>(std::to_integer<unsigned char>(bytes[i + 1])) << 8)  |
                           static_cast<std::uint32_t>(std::to_integer<unsigned char>(bytes[i + 2]));
        out.push_back(kStdAlphabet[(v >> 18) & 0x3f]);
        out.push_back(kStdAlphabet[(v >> 12) & 0x3f]);
        out.push_back(kStdAlphabet[(v >> 6)  & 0x3f]);
        out.push_back(kStdAlphabet[ v        & 0x3f]);
        i += 3;
    }
    if (i < bytes.size()) {
        std::uint32_t v = static_cast<std::uint32_t>(std::to_integer<unsigned char>(bytes[i])) << 16;
        if (i + 1 < bytes.size()) {
            v |= static_cast<std::uint32_t>(std::to_integer<unsigned char>(bytes[i + 1])) << 8;
        }
        out.push_back(kStdAlphabet[(v >> 18) & 0x3f]);
        out.push_back(kStdAlphabet[(v >> 12) & 0x3f]);
        if (i + 1 < bytes.size()) {
            out.push_back(kStdAlphabet[(v >> 6) & 0x3f]);
        } else {
            out.push_back('=');
        }
        out.push_back('=');
    }
    return out;
}

std::string iso8601_now_utc() {
    using namespace std::chrono;
    const auto now    = system_clock::now();
    const auto secs   = time_point_cast<seconds>(now);
    const auto millis = duration_cast<milliseconds>(now - secs).count();
    const auto t      = system_clock::to_time_t(secs);

    std::tm tm_utc{};
#if defined(_WIN32)
    gmtime_s(&tm_utc, &t);
#else
    gmtime_r(&t, &tm_utc);
#endif

    // 64 is comfortably more than the 24 chars a well-formed timestamp
    // produces. GCC's worst-case analysis on snprintf assumes pathological
    // int values (negative years, etc.) which never occur given how we
    // populate the struct tm; the bigger buffer silences the warning.
    char buf[64] = {};
    std::snprintf(buf, sizeof(buf),
                  "%04d-%02d-%02dT%02d:%02d:%02d.%03lldZ",
                  tm_utc.tm_year + 1900, tm_utc.tm_mon + 1, tm_utc.tm_mday,
                  tm_utc.tm_hour, tm_utc.tm_min, tm_utc.tm_sec,
                  static_cast<long long>(millis));
    return std::string{buf};
}

EnvelopeWithDetails make_signed_envelope_with_details(
    std::span<const std::byte> payload,
    const EnvelopeFields& fields,
    const fhe_toolkit::signing::SigningSecretKey& secret_key)
{
    require(!payload.empty(),                  "envelope payload is empty");
    require(!fields.permission_id.empty(),     "envelope permissionId is empty");
    require(fields.round >= 1,                 "envelope round must be >= 1");
    require(!fields.message_type.empty(),      "envelope messageType is empty");
    require(!fields.timestamp.empty(),         "envelope timestamp is empty");

    const std::string payload_b64 = base64_std_encode(payload);

    // The signed object includes the five signed envelope fields. canonical_json()
    // already sorts keys lexicographically; we just have to populate them.
    json signed_obj = {
        {"messageType",   fields.message_type},
        {"payloadB64",    payload_b64},
        {"permissionId",  fields.permission_id},
        {"round",         fields.round},
        {"timestamp",     fields.timestamp},
    };

    const std::string canonical = canonical_json(signed_obj);

    // Sign the canonical bytes.
    std::vector<std::byte> canon_bytes(canonical.size());
    if (!canonical.empty()) {
        std::memcpy(canon_bytes.data(), canonical.data(), canonical.size());
    }
    const auto sig = fhe_toolkit::signing::sign(
        secret_key,
        std::span<const std::byte>(canon_bytes.data(), canon_bytes.size()));

    const std::string signature_hex = hex_encode(
        std::span<const std::byte>(sig.bytes.data(), sig.bytes.size()));

    // The upload body has five fields - fromCompanyId and permissionId are
    // inferred by the backend from auth + URL respectively. Keys are written
    // in a stable order (alphabetical) but the platform does not require
    // canonicalization of the upload body (only of the signed payload).
    json upload_obj = {
        {"messageType",  fields.message_type},
        {"payloadB64",   payload_b64},
        {"round",        fields.round},
        {"signatureHex", signature_hex},
        {"timestamp",    fields.timestamp},
    };

    EnvelopeWithDetails out;
    out.upload_json              = upload_obj.dump(2);
    out.canonical_signed_payload = canonical;
    out.signature                = sig;
    return out;
}

std::string make_signed_envelope(
    std::span<const std::byte> payload,
    const EnvelopeFields& fields,
    const fhe_toolkit::signing::SigningSecretKey& secret_key)
{
    return make_signed_envelope_with_details(payload, fields, secret_key).upload_json;
}

// -----------------------------------------------------------------------------
// Final-keys submission envelope (multi-party keysetup finalization).
//
// Canonical signed payload (alphabetical keys at every nesting level, no
// whitespace, signatureHex excluded):
//   {
//     "keys": [
//       {"keyType": "eval_sum_key",     "objectKey": "...", "sha256Hex": "..."},
//       {"keyType": "joint_public_key", "objectKey": "...", "sha256Hex": "..."},
//       {"keyType": "joint_relin_key",  "objectKey": "...", "sha256Hex": "..."}
//     ],
//     "permissionId": "...",
//     "timestamp": "..."
//   }
//
// canonical_json() sorts object keys recursively but PRESERVES array order, so
// we must pre-sort 'keys' by keyType alphabetically before serialization.
// Upload body is { keys, signatureHex, timestamp }; fromCompanyId is inferred
// server-side from auth, permissionId from URL.

namespace {

constexpr std::array<std::string_view, 3> kAllowedFinalKeyTypes = {
    "eval_sum_key",
    "joint_public_key",
    "joint_relin_key",
};

bool is_allowed_final_key_type(std::string_view t) {
    for (auto allowed : kAllowedFinalKeyTypes) {
        if (t == allowed) return true;
    }
    return false;
}

bool is_lower_hex_64(std::string_view s) {
    if (s.size() != 64) return false;
    for (char c : s) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return true;
}

}  // namespace

FinalKeysEnvelopeWithDetails make_signed_final_keys_envelope_with_details(
    const std::vector<FinalKeyRef>& refs,
    const FinalKeysEnvelopeFields& fields,
    const fhe_toolkit::signing::SigningSecretKey& secret_key)
{
    require(!refs.empty(),                     "final-keys refs is empty");
    require(!fields.permission_id.empty(),     "envelope permissionId is empty");
    require(!fields.timestamp.empty(),         "envelope timestamp is empty");

    // Validate each ref: known keyType, non-empty objectKey, well-formed sha256Hex.
    std::unordered_set<std::string> seen_types;
    for (const auto& r : refs) {
        require(!r.key_type.empty(),            "final-keys ref has empty keyType");
        require(is_allowed_final_key_type(r.key_type),
                "final-keys ref has unrecognized keyType (must be one of eval_sum_key, joint_public_key, joint_relin_key)");
        require(!r.object_key.empty(),          "final-keys ref has empty objectKey");
        require(is_lower_hex_64(r.sha256_hex),  "final-keys ref has malformed sha256Hex (must be 64 lowercase hex chars)");
        require(seen_types.insert(r.key_type).second,
                "final-keys refs contain a duplicate keyType");
    }

    // Pre-sort by keyType so canonical_json's preserved-array-order produces
    // byte-identical output across clients regardless of input ordering.
    std::vector<FinalKeyRef> sorted = refs;
    std::sort(sorted.begin(), sorted.end(),
              [](const FinalKeyRef& a, const FinalKeyRef& b) {
                  return a.key_type < b.key_type;
              });

    // Build the keys array. nlohmann::json preserves insertion order for arrays,
    // and canonical_json() sorts the inner-object keys recursively, so the
    // {keyType, objectKey, sha256Hex} subobjects will canonicalize alphabetically.
    json keys_arr = json::array();
    for (const auto& r : sorted) {
        keys_arr.push_back(json{
            {"keyType",   r.key_type},
            {"objectKey", r.object_key},
            {"sha256Hex", r.sha256_hex},
        });
    }

    json signed_obj = {
        {"keys",          keys_arr},
        {"permissionId",  fields.permission_id},
        {"timestamp",     fields.timestamp},
    };

    const std::string canonical = canonical_json(signed_obj);

    std::vector<std::byte> canon_bytes(canonical.size());
    if (!canonical.empty()) {
        std::memcpy(canon_bytes.data(), canonical.data(), canonical.size());
    }
    const auto sig = fhe_toolkit::signing::sign(
        secret_key,
        std::span<const std::byte>(canon_bytes.data(), canon_bytes.size()));

    const std::string signature_hex = hex_encode(
        std::span<const std::byte>(sig.bytes.data(), sig.bytes.size()));

    // Upload body: three fields. fromCompanyId is server-injected (from auth);
    // permissionId comes from the URL. Keys are emitted in the same sorted
    // order we signed over, so a naive consumer can pass keys through to
    // canonical_json without re-sorting and get the same bytes back.
    json upload_obj = {
        {"keys",         keys_arr},
        {"signatureHex", signature_hex},
        {"timestamp",    fields.timestamp},
    };

    FinalKeysEnvelopeWithDetails out;
    out.upload_json              = upload_obj.dump(2);
    out.canonical_signed_payload = canonical;
    out.signature                = sig;
    return out;
}

std::string make_signed_final_keys_envelope(
    const std::vector<FinalKeyRef>& refs,
    const FinalKeysEnvelopeFields& fields,
    const fhe_toolkit::signing::SigningSecretKey& secret_key)
{
    return make_signed_final_keys_envelope_with_details(refs, fields, secret_key).upload_json;
}

// -----------------------------------------------------------------------------

std::string make_signed_envelope_from_ref(
    const PayloadRef& payload_ref,
    const EnvelopeFields& fields,
    const fhe_toolkit::signing::SigningSecretKey& secret_key)
{
    require(!payload_ref.object_key.empty(),   "payloadRef objectKey is empty");
    require(payload_ref.size_bytes > 0,        "payloadRef sizeBytes must be > 0");
    require(!fields.permission_id.empty(),     "envelope permissionId is empty");
    require(fields.round >= 1,                 "envelope round must be >= 1");
    require(!fields.message_type.empty(),      "envelope messageType is empty");
    require(!fields.timestamp.empty(),         "envelope timestamp is empty");

    // Build the nested payloadRef object. Note: nlohmann::json preserves
    // insertion order, but our canonical_json() sorts keys lexicographically,
    // so this ordering is irrelevant for the signed bytes.
    json payload_ref_obj = {
        {"objectKey", payload_ref.object_key},
        {"sizeBytes", static_cast<std::uint64_t>(payload_ref.size_bytes)},
    };

    // Signed canonical JSON: the five signed envelope fields, but payloadRef replaces
    // payloadB64. The platform reconstructs this exact shape and verifies.
    json signed_obj = {
        {"messageType",   fields.message_type},
        {"payloadRef",    payload_ref_obj},
        {"permissionId",  fields.permission_id},
        {"round",         fields.round},
        {"timestamp",     fields.timestamp},
    };

    const std::string canonical = canonical_json(signed_obj);

    std::vector<std::byte> canon_bytes(canonical.size());
    if (!canonical.empty()) {
        std::memcpy(canon_bytes.data(), canonical.data(), canonical.size());
    }
    const auto sig = fhe_toolkit::signing::sign(
        secret_key,
        std::span<const std::byte>(canon_bytes.data(), canon_bytes.size()));

    const std::string signature_hex = hex_encode(
        std::span<const std::byte>(sig.bytes.data(), sig.bytes.size()));

    // Upload body: same five fields as the inline variant, but with
    // payloadRef in place of payloadB64. fromCompanyId and permissionId
    // are still inferred server-side.
    json upload_obj = {
        {"messageType",  fields.message_type},
        {"payloadRef",   payload_ref_obj},
        {"round",        fields.round},
        {"signatureHex", signature_hex},
        {"timestamp",    fields.timestamp},
    };

    return upload_obj.dump(2);
}

}  // namespace fhe_toolkit::registry
