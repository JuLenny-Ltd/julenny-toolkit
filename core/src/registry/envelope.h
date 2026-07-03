#ifndef FHE_TOOLKIT_REGISTRY_ENVELOPE_H
#define FHE_TOOLKIT_REGISTRY_ENVELOPE_H

// Signed keysetup-message envelope.
//
// The JuLenny FHE Platform accepts keysetup contributions (joint public key
// shares, relinearization key shares, sum key shares, etc.) as signed JSON
// envelopes via POST /api/fhe-permissions/{permissionId}/keysetup/messages.
//
// The platform verifies an Ed25519 signature over the canonical JSON of
// {messageType, payloadB64, permissionId, round, timestamp}
// (sorted keys, no whitespace, signatureHex excluded). On
// success the envelope is stored under the company's previously registered
// signing public key.
//
// The HTTP body the customer uploads contains only what the platform needs
// in addition to what it infers from auth + URL:
//   { round, messageType, payloadB64, signatureHex, timestamp }
// The sender is identified by the auth token; permissionId from the URL.
//
// This header exposes the wrap-and-sign step as a pure data transformation,
// independent of the FHE crypto pipeline. The CLI's `crypto wrap-envelope`
// subcommand is a thin wrapper around make_signed_envelope.

#include <cstddef>
#include <span>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "crypto/signing.h"

namespace fhe_toolkit::registry {

struct EnvelopeFields {
    std::string permission_id;     // permission ID this share is for
    int         round = 0;         // 1-based round number from the platform's manifest
    std::string message_type;      // e.g. "pk-share", "relin-round1", "sum-round1-continue"
    std::string timestamp;         // ISO 8601 UTC, e.g. "2026-05-18T12:34:56.789Z"
};

// Build the signed JSON upload body for a keysetup-message endpoint.
//
// Returns the JSON string the customer uploads. The string contains exactly
// these five fields: round, messageType, payloadB64, signatureHex, timestamp.
// Throws std::invalid_argument on missing fields or empty payload.
//
// The signed payload is the canonical JSON of the envelope fields
// (the upload body plus permissionId). The platform
// re-canonicalizes from those fields and verifies against the registered
// public key.
std::string make_signed_envelope(
    std::span<const std::byte> payload,
    const EnvelopeFields& fields,
    const fhe_toolkit::signing::SigningSecretKey& secret_key);

// Same, but also returns the canonical bytes that were signed and the raw
// 64-byte signature, for tests / debugging. The first element of the pair
// is the canonical JSON string (UTF-8 bytes), the second is the signature.
struct EnvelopeWithDetails {
    std::string                                      upload_json;
    std::string                                      canonical_signed_payload;
    fhe_toolkit::signing::Signature                  signature;
};

EnvelopeWithDetails make_signed_envelope_with_details(
    std::span<const std::byte> payload,
    const EnvelopeFields& fields,
    const fhe_toolkit::signing::SigningSecretKey& secret_key);

// Reference to a payload that was uploaded out-of-band (e.g. to GCS via a
// pre-signed PUT URL). Used for large payloads that exceed Cloud Run's
// 32 MB request-body limit.
struct PayloadRef {
    std::string object_key;     // server-derived path, e.g. keysetup-messages/{permissionId}/{round}_{companyId}/payload.bin
    std::size_t size_bytes = 0; // raw payload size; used for server-side sanity checks
};

// Variant of make_signed_envelope for the large-payload (GCS-mediated) flow.
//
// The signed canonical JSON includes "payloadRef":{"objectKey":..., "sizeBytes":...}
// in place of "payloadB64". The upload body shape mirrors the canonical
// shape (round, messageType, payloadRef, signatureHex, timestamp).
//
// permissionId is NOT in the upload body; the platform
// reconstructs them from auth + URL, just like the inline variant.
std::string make_signed_envelope_from_ref(
    const PayloadRef& payload_ref,
    const EnvelopeFields& fields,
    const fhe_toolkit::signing::SigningSecretKey& secret_key);

// ---------------------------------------------------------------------------
// Final-keys submission envelope (multi-party keysetup finalization).
//
// After all keysetup rounds complete, each party locally combines its share
// material into three final joint keys (the joint public key, the joint
// relinearization key, and the joint sum / eval-automorphism key map). Both
// parties upload all three blobs to GCS via signed PUT URLs, then submit a
// single signed envelope to
//   POST /api/fhe-permissions/{permissionId}/keysetup/final-keys
// listing each blob's keyType, objectKey, and sha256Hex. The platform
// compares both parties' submissions by sha256Hex; on match, the permission
// transitions to 'active'. The signed-over canonical JSON is
//   {keys, permissionId, timestamp}
// where 'keys' is an array of {keyType, objectKey, sha256Hex} objects sorted
// alphabetically by keyType (canonicalJson does NOT reorder arrays, so we
// must pre-sort). The HTTP upload body omits permissionId (URL parameter)
// and contains exactly
//   {keys, signatureHex, timestamp}.
// This header exposes the wrap-and-sign step as a pure data transformation
// over already-known objectKeys and sha256Hexes. Producing the blobs and
// PUTting them to GCS happens elsewhere (the offline app produces blobs;
// the web UI or customer scripts do the GCS upload and the envelope POST).

struct FinalKeyRef {
    std::string key_type;     // one of: "eval_sum_key", "joint_public_key", "joint_relin_key"
    std::string object_key;   // GCS object path, e.g. "final-keys/{permId}/{companyId}/joint_public_key.bin"
    std::string sha256_hex;   // 64-char lowercase hex of sha256(blob bytes)
};

struct FinalKeysEnvelopeFields {
    std::string permission_id;     // permission ID
    std::string timestamp;         // ISO 8601 UTC, ms precision, trailing 'Z'
};

// Build the signed JSON upload body for the final-keys finalization endpoint.
//
// 'refs' is the list of three FinalKeyRef entries (one per keyType). The
// implementation copies and sorts them by key_type alphabetically before
// canonicalization (defense in depth; callers should sort too, but this
// guarantees byte-correct signed bytes regardless).
//
// Returns the JSON string the caller uploads. The string contains exactly
// these three fields: keys, signatureHex, timestamp. Throws
// std::invalid_argument on missing fields, empty refs, duplicate key_types,
// or unrecognized key_types.
std::string make_signed_final_keys_envelope(
    const std::vector<FinalKeyRef>& refs,
    const FinalKeysEnvelopeFields& fields,
    const fhe_toolkit::signing::SigningSecretKey& secret_key);

// Same, but also returns the canonical bytes that were signed and the raw
// 64-byte signature, for tests / debugging.
struct FinalKeysEnvelopeWithDetails {
    std::string                                      upload_json;
    std::string                                      canonical_signed_payload;
    fhe_toolkit::signing::Signature                  signature;
};

FinalKeysEnvelopeWithDetails make_signed_final_keys_envelope_with_details(
    const std::vector<FinalKeyRef>& refs,
    const FinalKeysEnvelopeFields& fields,
    const fhe_toolkit::signing::SigningSecretKey& secret_key);

// ---------------------------------------------------------------------------

// Standard base64 encoder (RFC 4648 §4, with '+' '/' alphabet and '=' padding).
// Distinct from base64url; matches what Node's Buffer.from(s, 'base64') expects.
std::string base64_std_encode(std::span<const std::byte> bytes);

// ISO 8601 UTC timestamp for "right now", with millisecond precision and a
// trailing 'Z'. Matches what JavaScript's Date.toISOString() produces.
std::string iso8601_now_utc();

}  // namespace fhe_toolkit::registry

#endif
