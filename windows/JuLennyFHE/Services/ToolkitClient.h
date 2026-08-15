#pragma once

#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace JuLennyFHE::Services
{
    // Result of a single crypto operation. Success flag plus a
    // human-readable summary suitable for displaying in the UI's
    // result card.
    struct OperationResult
    {
        bool success = false;
        std::wstring summary;       // shown on success
        std::wstring error;         // shown on failure
    };

    // Generate a fresh FHE keypair. Scenario-agnostic: the resulting
    // (sk, pk) pair can be used standalone for single-party encrypt /
    // decrypt, OR uploaded as the first party's contribution to start a
    // joint keysetup (in which case the second party will chain on the
    // public half via KeysetupChain below).
    struct GenerateKeypairOptions
    {
        std::filesystem::path output_secret_path;
        std::filesystem::path output_public_path;
        std::string context_spec = "bfv-default-v1";
    };

    // Chain on a peer's already-published public key to derive a joint
    // public key. Use this when joining an existing keysetup as the
    // second party.
    //   peer_share_path:   the first party's public key (downloaded
    //                      from the platform).
    //   output_secret_path: this party's secret share (stays here).
    //   output_public_path: the joint public key, suitable to upload
    //                      to the platform for both parties to use
    //                      when encrypting.
    struct KeysetupChainOptions
    {
        std::filesystem::path peer_share_path;
        std::filesystem::path output_secret_path;
        std::filesystem::path output_public_path;
        std::string context_spec = "bfv-default-v1";
    };

    // Options for the Encrypt operation. Two modes (matches the Linux CLI):
    //   Mode A: function_def_path + input_name. Encoding rules (schema,
    //           separator, columns, skip_header) are read from the signed
    //           function-definition JSON. Recommended for production.
    //   Mode B: schema + per-schema fields specified directly. Useful for
    //           ad-hoc / testing. Both parties must use identical params
    //           or the math breaks.
    // Exactly one of {function_def_path, schema} must be set.
    struct EncryptOptions
    {
        std::filesystem::path input_path;
        std::filesystem::path joint_public_key_path;
        std::filesystem::path output_path;

        // Mode A:
        std::filesystem::path function_def_path;         // signed JSON file
        std::string input_name;                          // e.g. "dataset_a"

        // Mode B:
        std::string schema;                              // e.g. "indicator-hash"
        std::string separator = "none";                  // "none" | "comma" | "tab" | "semicolon" | "pipe"
        bool skip_header = false;
        std::string columns = "all";                     // "all" or "1,2,..."

        std::string context_spec;                        // optional override
    };

    // Per-party partial decryption of a result ciphertext. The recipient
    // party (the analyst, who'll see the plaintext) sets is_lead = true;
    // other parties set it false.
    struct PartialDecryptOptions
    {
        std::filesystem::path ciphertext_path;
        std::filesystem::path secret_key_path;
        std::filesystem::path output_path;
        bool is_lead = false;
        std::string context_spec = "bfv-default-v1";
    };

    // Combine all parties' partial decryptions to recover the plaintext.
    // The resulting plaintext exists only on this machine; nothing is
    // uploaded.
    struct CombineOptions
    {
        std::vector<std::filesystem::path> partial_paths;  // at least 2
        std::string context_spec = "bfv-default-v1";
    };

    // Generate an Ed25519 signing keypair. One-time per company. The
    // public half is uploaded to the platform via the company-settings
    // signing-key registration page; the secret stays here.
    struct SigningKeygenOptions
    {
        std::filesystem::path output_secret_path;
        std::filesystem::path output_public_path;
    };

    // Sign an arbitrary file with the Ed25519 secret key. Used as a
    // utility (typical signing happens automatically inside other ops
    // once integrated, but the explicit utility is useful for debugging
    // and for one-off signing tasks).
    struct SignOptions
    {
        std::filesystem::path input_path;          // file whose bytes get signed
        std::filesystem::path secret_key_path;     // 32-byte Ed25519 secret
        std::filesystem::path output_path;         // 64-byte signature output
    };

    // Verify a detached Ed25519 signature.
    struct VerifyOptions
    {
        std::filesystem::path input_path;          // file that was signed
        std::filesystem::path public_key_path;     // 32-byte Ed25519 public key
        std::filesystem::path signature_path;      // 64-byte signature
    };

    // Per-party joint-relinearization-key contribution. Needed for
    // any function that does multiplications (like joint-record-overlap).
    //
    // round 1, role=lead:  initial contribution, no peer input
    // round 1, role=main:  chains on peer's round-1 share
    // round 2:             each party computes from the combined-round-1
    //                      using their own secret share; no role distinction
    struct RelinContributeOptions
    {
        int round = 0;                              // 1 or 2
        std::string role;                           // "lead" or "main" for round 1; ignored for round 2
        std::filesystem::path secret_key_path;      // this party's FHE secret share
        std::filesystem::path peer_share_path;      // required for round=1, role=main
        std::filesystem::path combined_r1_path;     // required for round=2
        std::filesystem::path joint_pk_path;        // required for round=2
        std::filesystem::path output_path;
        std::string context_spec = "bfv-default-v1";
    };

    // Deterministic combine for the joint relinearization key. Both
    // parties run this independently on the same inputs and produce
    // byte-identical output that the platform compares for verification.
    struct RelinCombineOptions
    {
        int round = 0;                              // 1 (intermediate) or 2 (final)
        std::filesystem::path share_a_path;
        std::filesystem::path share_b_path;
        std::filesystem::path joint_pk_path;        // required for round=1
        std::filesystem::path combined_r1_path;     // required for round=2
        std::filesystem::path output_path;
        std::string context_spec = "bfv-default-v1";
    };

    // Per-party joint sum-key contribution. Needed for any function
    // that does slot summation (like joint-record-overlap's final
    // sum-of-slots step).
    struct SumContributeOptions
    {
        std::string role;                           // "lead" or "main"
        std::filesystem::path secret_key_path;      // this party's FHE secret share
        std::filesystem::path peer_share_path;      // required for role=main
        std::filesystem::path joint_pk_path;        // required for role=main
        std::filesystem::path output_path;
        std::string context_spec = "bfv-default-v1";
    };

    // Deterministic combine for the joint sum key.
    struct SumCombineOptions
    {
        std::filesystem::path share_a_path;
        std::filesystem::path share_b_path;
        std::filesystem::path joint_pk_path;
        std::filesystem::path output_path;
        std::string context_spec = "bfv-default-v1";
    };

    // Per-party joint rotation-key contribution. Required by any function
    // whose function-def lists "rotation" in requiredEvalKeys (CKKS
    // pipelines, in particular). Mirrors SumContribute except that the
    // caller supplies a comma-separated list of rotation indices the
    // joint key must support (e.g. "1,2,4,-1,-2").
    struct RotationContributeOptions
    {
        std::string role;                           // "lead" or "main"
        std::filesystem::path secret_key_path;      // this party's FHE secret share
        std::filesystem::path peer_share_path;      // required for role=main
        std::filesystem::path joint_pk_path;        // required for role=main
        std::string indices_csv;                    // e.g. "1,2,4,-1,-2"
        std::filesystem::path output_path;
        std::string context_spec = "bfv-default-v1";
    };

    // Deterministic combine for the joint rotation key.
    struct RotationCombineOptions
    {
        std::filesystem::path share_a_path;
        std::filesystem::path share_b_path;
        std::filesystem::path joint_pk_path;
        std::filesystem::path output_path;
        std::string context_spec = "bfv-default-v1";
    };

    // Wrap a binary contribution share into the signed JSON envelope the
    // platform's keysetup endpoint expects. File-in, file-out; no FHE
    // crypto. The output .json IS the HTTP request body the user uploads
    // (no further wrapping needed). The binary stays on disk for any
    // local chaining into subsequent rounds.
    struct WrapEnvelopeOptions
    {
        std::filesystem::path payload_path;     // any .bin produced by a contribute step
        std::filesystem::path secret_key_path;  // 32-byte Ed25519 secret (from signing-keygen)
        std::filesystem::path output_path;      // where to write the .json upload body
        std::string permission_id;              // permission ID
        int round = 0;                          // manifest round number (>= 1)
        std::string message_type;               // "pk-share", "relin-round1", "sum-round1-continue", etc.
        // NOTE (2026-06): the signed envelope no longer carries fromCompanyId.
        // The platform derives the signer from authentication; company IDs are
        // not known to (or stored by) the toolkit anywhere.
    };

    // Sign the multi-party keysetup finalization envelope. The three final
    // joint keys have already been uploaded to GCS by the web UI (or by a
    // customer script using the platform's REST API). The app's only job
    // here is to sign the canonical envelope listing each blob's keyType,
    // objectKey, and sha256Hex. File-in, file-out; no FHE crypto, no
    // network. Output is the HTTP body for POST /keysetup/final-keys.
    //
    // The to-sign file schema (must match the web UI's emitted file exactly):
    //   { keys: [{keyType, objectKey, sha256Hex}, ...],
    //     permissionId, timestamp }
    // (2026-06: fromCompanyId was removed from the canonical signed payload;
    // if an older to-sign file still contains it, it is ignored.)
    struct WrapFinalKeysEnvelopeOptions
    {
        std::filesystem::path to_sign_path;     // .json from the web UI (or hand-built script)
        std::filesystem::path secret_key_path;  // 32-byte Ed25519 secret (from signing-keygen)
        std::filesystem::path output_path;      // where to write the signed envelope .json
    };

    // Result of a successful Combine: the plaintext slot values plus
    // summary stats. Only the recipient party ever sees this.
    struct CombineResult
    {
        bool success = false;
        std::wstring error;

        std::vector<long long> slots;       // full plaintext, all 16384 slots
        std::size_t non_zero_slots = 0;
        long long sum_of_slots = 0;
        long long max_slot_value = 0;
        std::wstring summary;
    };

    // Façade over the fhe_toolkit_core library for the WinUI 3 app. The app is
    // strictly offline - operations read and write local files; the
    // platform's web UI or REST API moves the files between parties.
    // No HTTP code lives here.
    class ToolkitClient
    {
    public:
        ToolkitClient();
        ~ToolkitClient();

        // Human-readable local-state summary for Home / Settings. Shows
        // only local toolkit build info; nothing about the platform,
        // because this app does not talk to one.
        std::wstring GetLocalStatus();

        // Generate a fresh FHE keypair. Use the result for single-party
        // encrypt/decrypt OR as a starting contribution to a joint
        // keysetup that a peer will chain on later.
        OperationResult GenerateKeypair(const GenerateKeypairOptions& options);

        // Chain on a peer's already-published public key to derive a
        // joint public key (second-party role in a joint keysetup).
        OperationResult KeysetupChain(const KeysetupChainOptions& options);

        // Encrypt an input file under a joint public key. Two modes
        // (see EncryptOptions). Writes ciphertext suitable for uploading
        // to the platform as a dataset.
        OperationResult Encrypt(const EncryptOptions& options);

        // Compute this party's partial decryption of a result ciphertext.
        // Writes the partial to disk; the customer uploads it via the
        // platform's release endpoint (data owner) or downloads peer
        // partials before combining (recipient).
        OperationResult PartialDecrypt(const PartialDecryptOptions& options);

        // Combine all parties' partial decryptions and recover the
        // plaintext. Returns the slot values for display; the caller
        // is responsible for displaying them or saving to a file.
        CombineResult CombinePartials(const CombineOptions& options);

        // Ed25519 signing primitives.
        OperationResult SigningKeygen(const SigningKeygenOptions& options);
        OperationResult Sign(const SignOptions& options);
        OperationResult Verify(const VerifyOptions& options);

        // Joint relinearization key (multiplication enablement). Per-party,
        // 3 sub-rounds (round 1 contribute + combine, round 2 contribute + combine).
        OperationResult RelinContribute(const RelinContributeOptions& options);
        OperationResult RelinCombine(const RelinCombineOptions& options);

        // Joint sum key (slot summation enablement). Per-party, 2 sub-rounds
        // (round 1 contribute + combine).
        OperationResult SumContribute(const SumContributeOptions& options);
        OperationResult SumCombine(const SumCombineOptions& options);

        // Joint rotation key (CKKS pipelines and any function whose
        // function-def requiredEvalKeys includes "rotation"). Per-party,
        // 2 sub-rounds (round 1 contribute + combine), mirroring the sum
        // protocol; the only extra input is the rotation indices.
        OperationResult RotationContribute(const RotationContributeOptions& options);
        OperationResult RotationCombine(const RotationCombineOptions& options);

        // Wrap any binary contribution share into the signed JSON envelope
        // the platform's keysetup endpoint expects. Use after producing a
        // share via the relevant contribute screen.
        OperationResult WrapEnvelope(const WrapEnvelopeOptions& options);

        // Sign the multi-party keysetup finalization envelope. Takes the
        // to-sign file produced by the platform's web UI (or by a customer
        // script) and emits the signed POST body for /keysetup/final-keys.
        OperationResult WrapFinalKeysEnvelope(const WrapFinalKeysEnvelopeOptions& options);

    private:
        struct Impl;
        std::unique_ptr<Impl> m_impl;
    };
}
