#ifndef JULENNY_TOOLKIT_CLI_COMMANDS_H
#define JULENNY_TOOLKIT_CLI_COMMANDS_H

#include <string>
#include <vector>

#include <CLI/CLI.hpp>

namespace julenny_fhe::cli {

// Local secret-store inspection. No network. The store lives on disk
// under --secret-store-path (or a per-OS default if the flag is omitted).
struct KeysStatusArgs {
    std::string secret_store_path;
    std::string passphrase;
    bool emit_json = false;
};
struct KeysGenerateArgs {
    std::string secret_store_path;
    std::string context_spec;          // no default; callers must pass --context-spec (or --function-def for encrypt)
    std::string passphrase;
    bool force = false;
    bool emit_json = false;
};
void register_keys(CLI::App& app,
                   KeysStatusArgs& status_args,
                   KeysGenerateArgs& generate_args,
                   int* exit_code);

struct CryptoSelftestArgs   {
    // Defaulted, unlike the other arg structs. self-test is an INSTALLATION CHECK, so the whole
    // point is that `julenny-toolkit crypto self-test` works with no arguments at all. Its --help
    // has always advertised this default, but the member was left empty, so the bare command died
    // with "error: unknown context spec: " - on the one feature a trial account can run with no
    // account, no partner and no data of its own.
    std::string context_spec = "bfv-default-v1";
    bool multi_party = false;   // 2-party in-process: full keysetup + EvalMult + Rotate + threshold decrypt
    bool emit_json = false;
};

// Ed25519 signing keypair generation. Each company has one Ed25519 keypair
// (separate from any FHE keys) used to sign keysetup contributions and
// partial decryptions in the rev 5 trust model. Standard 32-byte seed +
// 32-byte public key format; interoperable with libsodium, Go's ed25519,
// Python cryptography, etc.
struct CryptoSigningKeygenArgs {
    std::string output_secret_path;
    std::string output_public_path;
    bool emit_json = false;
};

// Sign an arbitrary file with an Ed25519 secret key. Writes the 64-byte
// detached signature to a separate output file. Used both as a utility
// command and as the building block for auto-signing keysetup
// contributions and partial decryptions.
struct CryptoSignArgs {
    std::string input_path;          // file whose bytes are signed
    std::string secret_key_path;     // Ed25519 secret key (32-byte seed)
    std::string output_path;         // where to write the signature (64 bytes)
    bool emit_json = false;
};

// Verify a signature against an Ed25519 public key. Returns exit code 0
// on valid, 1 on invalid signature, 2 on argument or file-IO error.
struct CryptoVerifyArgs {
    std::string input_path;          // file that was signed
    std::string public_key_path;     // Ed25519 public key (32 bytes)
    std::string signature_path;      // 64-byte signature file
    bool emit_json = false;
};
// Encrypt a plaintext input file under a joint public key. The app is
// function-agnostic in code; it does not know about specific functions.
// It supports two modes for declaring the encoding rules to apply:
//
//   Mode A (recommended for production): --function-def <path> + --input-name <name>.
//     The signed function-definition JSON document carries the encoding
//     rules (schema + schemaParams). The app reads them. Customers
//     download the file from GET /api/functions/{slug}/{version}/definition.
//     Signature provides trust + audit + consistency between parties.
//
//   Mode B (power-user / ad-hoc): --schema + per-schema flags
//     (--separator, --skip-header, --columns for indicator-hash).
//     The customer specifies the encoding directly. No platform involvement.
//     Useful for scripting, testing, or one-off encryption against a
//     known schema. Both parties in a multi-party flow MUST pass exactly
//     the same flags or the math will be wrong.
//
// Exactly one of {--function-def, --schema} must be set.
struct CryptoEncryptArgs {
    std::string input_path;            // plaintext input file
    std::string joint_public_key_path; // joint public key (binary)
    std::string output_path;           // ciphertext output (binary)

    // Mode A: function-def-driven.
    std::string function_def_path;     // optional in mode B
    std::string input_name;            // required only with --function-def

    // Mode B: explicit-flag.
    std::string schema;                // e.g. "indicator-hash"; required if no --function-def
    std::string separator;             // e.g. ",", "\t", ";", "|", or empty for "none"
    std::string columns = "all";       // "all" or comma-separated 1-based indices like "1,2"
    bool skip_header = false;

    std::string context_spec;          // optional override; if empty, read from function-def or default
    bool emit_json = false;
};
struct CryptoDecryptArgs {
    std::string input_path;       // ciphertext file (binary)
    std::string secret_key_path;  // secret key file (binary, cereal-serialized)
    std::string context_spec;          // no default; callers must pass --context-spec (or --function-def for encrypt)
    int show_slots = 16;          // number of leading slots to print
    bool non_zero_only = false;   // print only non-zero slots
    bool emit_json = false;
};
// Per-rev-5 chained construction: one party at a time runs this command on
// their own machine. role=lead is party 1 (no peer input; calls
// MultipartyKeyGen()); role=main is party 2+ (takes the previous party's
// public-key contribution as input; calls MultipartyKeyGen(prev_pk); the
// resulting public output IS the joint public key).
struct CryptoKeysetupContributeArgs {
    std::string role;                  // "lead" or "main"
    std::string peer_share_path;       // required for role=main; ignored for role=lead
    std::string output_secret_path;    // this party's secret share (stays on this machine)
    std::string output_public_path;    // role=lead: this party's pk contribution to upload.
                                       // role=main: the joint public key.
    std::string context_spec;          // no default; callers must pass --context-spec (or --function-def for encrypt)
    bool emit_json = false;
};
// Joint relinearization key contribution. Per-party, per-round. The toolkit
// core implements the 3 sub-rounds via three primitives the customer's app
// runs locally on each round's inputs:
//   round 1, role=lead:  relin_round1_initial(sk)              -> EvalKey
//   round 1, role=main:  relin_round1_continue(sk, prev)       -> EvalKey
//   round 2 (both):      relin_round2(sk, combined_r1, jpk)    -> EvalKey
// The combine steps (between round 1 and round 2, and producing the final
// key from the round-2 shares) are deterministic and live in CryptoRelinCombineArgs.
struct CryptoRelinContributeArgs {
    int round = 0;                     // 1 or 2
    std::string role;                  // "lead" or "main" (required for round 1; ignored for round 2)
    std::string secret_key_path;       // this party's FHE secret share
    std::string peer_share_path;       // required for round=1 + role=main (lead's round-1 share)
    std::string combined_r1_path;      // required for round=2 (deterministic combine of round-1 shares)
    std::string joint_pk_path;         // required for round=2
    std::string output_path;           // where to write this party's contribution for this round
    std::string context_spec;          // no default; callers must pass --context-spec (or --function-def for encrypt)
    bool emit_json = false;
};

// Joint relinearization key combine. Deterministic - both parties run this
// independently on the same inputs and produce byte-identical output. The
// platform verifies byte-equality across the two parties' submissions.
//   round 1:  relin_combine_round1(a, b, joint_pk)        -> intermediate
//   round 2:  relin_combine_round2(a, b, combined_round1) -> final relin key
struct CryptoRelinCombineArgs {
    int round = 0;                     // 1 or 2
    std::string share_a_path;          // party A's contribution for this round
    std::string share_b_path;          // party B's contribution for this round
    std::string joint_pk_path;         // required for round=1
    std::string combined_r1_path;      // required for round=2 (from a previous --round 1 combine)
    std::string output_path;
    std::string context_spec;          // no default; callers must pass --context-spec (or --function-def for encrypt)
    bool emit_json = false;
};

// Joint sum key contribution. Per-party, single round (2 sub-rounds total
// when combined with sum-combine). Toolkit core primitives:
//   role=lead:  sum_round1_initial(sk)                          -> SumKeyMap
//   role=main:  sum_round1_continue(sk, prev, joint_pk)         -> SumKeyMap
struct CryptoSumContributeArgs {
    std::string role;                  // "lead" or "main"
    std::string secret_key_path;       // this party's FHE secret share
    std::string peer_share_path;       // required for role=main (lead's contribution)
    std::string joint_pk_path;         // required for role=main
    std::string output_path;
    std::string context_spec;          // no default; callers must pass --context-spec (or --function-def for encrypt)
    bool emit_json = false;
};

// Joint sum key combine. Deterministic - both parties run this on the same
// inputs and produce byte-identical final sum key.
//   sum_combine(a, b, joint_pk) -> final sum key
struct CryptoSumCombineArgs {
    std::string share_a_path;
    std::string share_b_path;
    std::string joint_pk_path;
    std::string output_path;
    std::string context_spec;          // no default; callers must pass --context-spec (or --function-def for encrypt)
    bool emit_json = false;
};

// Joint rotation key contribution. Per-party, single round (2 sub-rounds
// total when combined with rotation-combine). Mirrors the sum-key shape but
// requires a caller-supplied list of rotation indices.
//   role=lead:  rotation_round1_initial(sk, indices)                    -> RotationKeyMap
//   role=main:  rotation_round1_continue(sk, prev, indices, joint_pk)   -> RotationKeyMap
struct CryptoRotationContributeArgs {
    std::string role;                  // "lead" or "main"
    std::string secret_key_path;       // this party's FHE secret share
    std::string peer_share_path;       // required for role=main (lead's contribution)
    std::string joint_pk_path;         // required for role=main
    std::string indices_csv;           // e.g. "1,2,4,8,-1,-2"
    std::string output_path;
    std::string context_spec;          // no default; callers must pass --context-spec (or --function-def for encrypt)
    bool emit_json = false;
};

// Joint rotation key combine. Deterministic - both parties run this on the
// same inputs and produce byte-identical final rotation key.
//   rotation_combine(a, b, joint_pk) -> final rotation key
struct CryptoRotationCombineArgs {
    std::string share_a_path;
    std::string share_b_path;
    std::string joint_pk_path;
    std::string output_path;
    std::string context_spec;          // no default; callers must pass --context-spec (or --function-def for encrypt)
    bool emit_json = false;
};

// Resolve indicator-hash non-zero slot positions back to the original CSV
// records that produced them. Used by 06-decrypt for itemized-overlap-style
// functions: after threshold decrypt produces a sparse indicator vector,
// this maps the non-zero slots back to the customer names (or whatever
// records the CSV holds) by rehashing each line in the local CSV and
// checking membership in the non-zero slot set. The rehash logic must match
// crypto encrypt's logic exactly, so this command reuses the same
// fnv1a_64 / compose_record / parse_columns_spec helpers.
struct CryptoResolveIndicatorArgs {
    std::string slots_csv;          // comma-separated non-zero slot indices, e.g. "3215,7890"
    std::string input_csv_path;     // the local CSV to resolve against (Beta's customers)
    std::string function_def_path;  // function-def JSON for schema params
    std::string input_name;         // which input in the function-def is this dataset for
    std::string context_spec;          // no default; callers must pass --context-spec (or --function-def for encrypt)
    bool emit_json = false;
};

// Derive the rotation index set for the rule-based-cross-match function (or any
// function with the same pair-list shape). Implements the hash-based
// derivation rule: index = fnv1a_64(name) % slotCount over every name in
// rule_pairs (left + right halves), deduped. Toolkit-side mirror of the
// server's derivation; used by phase 4.5 as a defensive cross-check.
//
// Changed in 0.5.5 from the original dictionary-position derivation when
// rule-based-cross-match's encoding contract switched to fnv1a hashing (see
// plans/dual-compatibility-indicator-encoding-mismatch.md). Pure local;
// no network, no FHE crypto. Slot count is derived from --context-spec
// (ckks-default-v1 -> 8192).
struct CryptoDeriveRotationIndicesArgs {
    std::string rule_pairs_path;    // CSV, each row "left_name,right_name" (split on FIRST comma)
    std::string context_spec;       // required; used to look up slot count
    bool        emit_json = false;  // when set, output is JSON {indices: [...], indexCount: N}
};

// Sign the final-keys submission envelope for multi-party keysetup
// finalization. The input is a "to-sign" JSON file (produced either by the
// platform's web UI's finalization flow, or hand-built by a customer
// script) listing the three (keyType, objectKey, sha256Hex) tuples plus
// permissionId and timestamp. The output is the signed
// JSON body for POST /api/fhe-permissions/{id}/keysetup/final-keys.
//
// To-sign file schema (must match exactly what the web UI emits):
//   {
//     "keys": [
//       { "keyType": "eval_sum_key",     "objectKey": "...", "sha256Hex": "..." },
//       { "keyType": "joint_public_key", "objectKey": "...", "sha256Hex": "..." },
//       { "keyType": "joint_relin_key",  "objectKey": "...", "sha256Hex": "..." }
//     ],
//     "permissionId": "...",
//     "timestamp": "<ISO 8601 UTC, ms precision, trailing Z>"
//   }
//
// Output (upload body):
//   { "keys": [...], "signatureHex": "...", "timestamp": "..." }
//
// File-in, file-out; no FHE crypto, no network. This is the offline
// signing step in the round-trip-through-the-app finalization flow.
struct CryptoWrapFinalKeysEnvelopeArgs {
    std::string to_sign_path;        // input .json with keys[], permissionId, timestamp
    std::string secret_key_path;     // 32-byte Ed25519 signing secret seed
    std::string output_path;         // output .json (upload body for POST /keysetup/final-keys)
    bool        emit_json = false;
};

// Wrap an opaque binary share into the signed JSON envelope the JuLenny
// platform expects at POST /api/fhe-permissions/{id}/keysetup/messages.
// File-in, file-out; no FHE crypto, just sign-and-serialize. The signing
// key is the company's Ed25519 secret seed (32 bytes), the same one
// `crypto signing-keygen` produces. The output JSON file IS the HTTP
// body the customer uploads through the web UI (no further wrapping).
struct CryptoWrapEnvelopeArgs {
    // Required in BOTH modes:
    std::string secret_key_path;    // 32-byte Ed25519 secret seed
    std::string output_path;        // .json upload body
    std::string permission_id;      // permission ID
    int         round = 0;          // manifest round number (>= 1)
    std::string message_type;       // e.g. "pk-share", "relin-round1", "sum-round1-continue"
    std::string timestamp;          // optional ISO 8601 override; defaults to now-UTC
    bool        emit_json = false;

    // Mode A (inline payloadB64): required for small payloads.
    std::string payload_path;       // binary share file; bytes are base64'd into the envelope

    // Mode B (payloadRef): for large payloads uploaded out-of-band to GCS.
    // When --object-key is set, the envelope is signed with payloadRef in
    // place of payloadB64. --size-bytes is required; --payload is ignored.
    std::string object_key;         // GCS objectKey returned by the upload-url endpoint
    std::size_t size_bytes = 0;     // raw payload size (bytes); required in Mode B
};

struct CryptoPartialDecryptArgs {
    std::string input_path;       // ciphertext file (binary)
    std::string secret_key_path;  // this party's secret key share (binary)
    std::string output_path;      // partial-decryption output file (binary)
    std::string context_spec;          // no default; callers must pass --context-spec (or --function-def for encrypt)
    bool lead = false;            // true for the "lead" party in the threshold protocol
    bool emit_json = false;
};
struct CryptoCombineArgs {
    std::vector<std::string> partial_paths;  // partial-decryption files, one per party
    std::string context_spec;          // no default; callers must pass --context-spec (or --function-def for encrypt)
    int show_slots = 16;
    bool non_zero_only = false;
    bool real_output = false;          // CKKS only: emit raw real-valued slots (no int rounding)
    std::string out_file_path;         // blind: write plaintext result here; stdout returns references only
    bool emit_json = false;
};
// Diagnostic: dump a ciphertext file's metadata + EMBEDDED crypto context
// parameters without validating against any local context. Used to diff
// cross-component context mismatches ("ValidateCiphertext" failures).
struct CryptoInspectArgs {
    std::string input_path;       // ciphertext file (binary)
    std::string context_spec;     // only used to construct the deserialization shim; default ckks-default-v1
    bool emit_json = false;
};

void register_crypto(CLI::App& app,
                     CryptoSelftestArgs& selftest_args,
                     CryptoSigningKeygenArgs& signing_keygen_args,
                     CryptoSignArgs& sign_args,
                     CryptoVerifyArgs& verify_args,
                     CryptoEncryptArgs& encrypt_args,
                     CryptoDecryptArgs& decrypt_args,
                     CryptoKeysetupContributeArgs& keysetup_contribute_args,
                     CryptoRelinContributeArgs& relin_contribute_args,
                     CryptoRelinCombineArgs& relin_combine_args,
                     CryptoSumContributeArgs& sum_contribute_args,
                     CryptoSumCombineArgs& sum_combine_args,
                     CryptoRotationContributeArgs& rotation_contribute_args,
                     CryptoRotationCombineArgs& rotation_combine_args,
                     CryptoWrapEnvelopeArgs& wrap_envelope_args,
                     CryptoWrapFinalKeysEnvelopeArgs& wrap_final_keys_envelope_args,
                     CryptoPartialDecryptArgs& partial_args,
                     CryptoCombineArgs& combine_args,
                     CryptoResolveIndicatorArgs& resolve_indicator_args,
                     CryptoDeriveRotationIndicesArgs& derive_rotation_indices_args,
                     CryptoInspectArgs& inspect_args,
                     int* exit_code);

}  // namespace julenny_fhe::cli

#endif
