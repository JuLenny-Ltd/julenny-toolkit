#include "commands.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <set>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <nlohmann/json.hpp>

#include "crypto/context.h"
#include "crypto/keys.h"
#include "crypto/ciphertext.h"
#include "crypto/eval_keys.h"
#include "crypto/signing.h"
#include "registry/envelope.h"
#include "registry/signature.h"
#include "registry/trust_root.h"
#include "fhe_toolkit/fhe_toolkit.h"

namespace julenny_fhe::cli {

using nlohmann::json;
using fhe_toolkit::crypto::Context;
using fhe_toolkit::crypto::get_crypto_context_spec;

namespace {

// Read decoded plaintext slots as int64 regardless of scheme. For CKKS, the
// underlying double values are rounded to the nearest integer. Adequate for
// indicator-style schemas (values are 0.0 or 1.0) and count-aggregation
// outputs (the only shapes the customer-overlap-family functions produce
// today). General CKKS workloads with arbitrary real-valued outputs will
// want a dedicated real-valued display path; not implemented yet.
std::vector<std::int64_t>
values_as_int64(const fhe_toolkit::crypto::PlaintextPacked& pt,
                const fhe_toolkit::crypto::CryptoContextSpec& spec) {
    if (spec.scheme == "CKKS") {
        auto reals = pt.real_values();
        std::vector<std::int64_t> out;
        out.reserve(reals.size());
        for (auto v : reals) {
            out.push_back(static_cast<std::int64_t>(std::llround(v)));
        }
        return out;
    }
    return pt.values();
}

void write_bytes(const std::filesystem::path& path,
                 std::span<const std::byte> bytes) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) throw std::runtime_error("cannot open for writing: " + path.string());
    out.write(reinterpret_cast<const char*>(bytes.data()),
              static_cast<std::streamsize>(bytes.size()));
    if (!out) throw std::runtime_error("write failed: " + path.string());
}

void write_text(const std::filesystem::path& path, const std::string& s) {
    std::ofstream out(path, std::ios::trunc);
    if (!out) throw std::runtime_error("cannot open for writing: " + path.string());
    out << s;
    if (!out) throw std::runtime_error("write failed: " + path.string());
}

std::vector<std::byte> read_bytes(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary | std::ios::ate);
    if (!in) throw std::runtime_error("cannot open for reading: " + path.string());
    auto size = static_cast<std::size_t>(in.tellg());
    in.seekg(0, std::ios::beg);
    std::vector<std::byte> bytes(size);
    if (size > 0) {
        in.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(size));
        if (!in) throw std::runtime_error("read failed: " + path.string());
    }
    return bytes;
}

// FNV-1a 64-bit hash. Deterministic, fast, no external deps. Not
// cryptographic; for v0 hash-based name matching only. Replace with
// SHA-256 later when we add OpenSSL to the CLI's direct link inputs.
std::uint64_t fnv1a_64(std::string_view s) noexcept {
    constexpr std::uint64_t offset = 14695981039346656037ULL;
    constexpr std::uint64_t prime  = 1099511628211ULL;
    std::uint64_t h = offset;
    for (unsigned char c : s) {
        h ^= c;
        h *= prime;
    }
    return h;
}

std::string trim_inplace(std::string s) {
    auto not_space = [](unsigned char c) { return !std::isspace(c); };
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), not_space));
    s.erase(std::find_if(s.rbegin(), s.rend(), not_space).base(), s.end());
    return s;
}

// Split a string by a single-character delimiter. Whitespace is not trimmed
// from fields; the caller does that if needed. Empty trailing field (line
// ending with the delim) is preserved.
std::vector<std::string> split_string(const std::string& s, char delim) {
    std::vector<std::string> out;
    std::string field;
    std::stringstream ss(s);
    while (std::getline(ss, field, delim)) out.push_back(field);
    return out;
}

// Parse a column-spec string from a function-def's schemaParams. "all" or
// empty means use every column. Otherwise it's a comma-separated list of
// 1-based column indices like "1,3,5". Returns the parsed indices in
// 1-based form, or an empty vector for "all".
std::vector<int> parse_columns_spec(const std::string& spec) {
    std::vector<int> out;
    if (spec.empty() || spec == "all") return out;
    for (auto& part : split_string(spec, ',')) {
        auto t = trim_inplace(part);
        if (!t.empty()) {
            try { out.push_back(std::stoi(t)); }
            catch (...) { /* skip non-numeric */ }
        }
    }
    return out;
}

// Compose a string suitable for hashing from one input line, given the
// schema's separator and column-selection rules. Uses ASCII Unit Separator
// (\x1F) to join selected columns so the joined string is unambiguous and
// matches the Windows app's encoding for cross-platform reproducibility.
std::string compose_record(const std::string& line,
                            char sep_char,
                            const std::vector<int>& cols) {
    if (sep_char == '\0') {
        // No separator declared: hash the whole trimmed line.
        return trim_inplace(line);
    }
    auto fields = split_string(line, sep_char);
    std::string composed;
    if (cols.empty()) {
        // "all" columns.
        for (std::size_t i = 0; i < fields.size(); ++i) {
            if (i > 0) composed.push_back('\x1F');
            composed.append(trim_inplace(fields[i]));
        }
    } else {
        // Selected 1-based column indices.
        for (std::size_t i = 0; i < cols.size(); ++i) {
            int col = cols[i] - 1;
            if (col >= 0 && col < static_cast<int>(fields.size())) {
                if (i > 0) composed.push_back('\x1F');
                composed.append(trim_inplace(fields[col]));
            }
        }
    }
    return composed;
}

// Slot count for our default BFV context (ringDimension = 16384 per
// schemas/seed-data/bfv-default-v1.json on the platform). Since p=65537
// is prime and 65537 = 1 mod 2*ringDimension, the cyclotomic polynomial
// splits completely and batchSize = ringDimension.
//
// TODO: replace with Context::slot_count() once the core wrapper exposes
// it (OpenFHE reports it via cc->GetEncodingParams()->GetBatchSize()).
constexpr std::int64_t BFV_DEFAULT_V1_SLOTS  = 16384;
constexpr std::int64_t CKKS_DEFAULT_V1_SLOTS = 8192;   // ringDim/2 for CKKS
constexpr std::int64_t CKKS_TREE_V1_SLOTS    = 32768;  // ringDim/2 for ckks-tree-v1 (ring 65536)

std::int64_t resolve_slot_count(std::string_view context_spec_id) {
    if (context_spec_id == "bfv-default-v1")  return BFV_DEFAULT_V1_SLOTS;
    if (context_spec_id == "ckks-default-v1") return CKKS_DEFAULT_V1_SLOTS;
    if (context_spec_id == "ckks-tree-v1")    return CKKS_TREE_V1_SLOTS;
    throw std::runtime_error("unknown context spec: " + std::string(context_spec_id));
}

// Generate an Ed25519 signing keypair. Standard 32-byte seed (secret) +
// 32-byte public key. The secret stays on this machine; the public key is
// registered with the platform via POST /api/companies/{id}/signing-public-key.
int run_crypto_signing_keygen(const CryptoSigningKeygenArgs& args) {
    namespace fs = std::filesystem;

    if (args.output_secret_path.empty() || args.output_public_path.empty()) {
        std::cerr << "error: --output-secret and --output-public are required\n";
        return 2;
    }

    auto kp = fhe_toolkit::signing::generate_keypair();

    const fs::path sk_path(args.output_secret_path);
    const fs::path pk_path(args.output_public_path);
    if (sk_path.has_parent_path()) fs::create_directories(sk_path.parent_path());
    if (pk_path.has_parent_path()) fs::create_directories(pk_path.parent_path());

    write_bytes(sk_path, std::span<const std::byte>(kp.secret_key.bytes.data(), kp.secret_key.bytes.size()));
    write_bytes(pk_path, std::span<const std::byte>(kp.public_key.bytes.data(), kp.public_key.bytes.size()));

    // Owner-only on the secret file.
    try {
        fs::permissions(sk_path,
                        fs::perms::owner_read | fs::perms::owner_write,
                        fs::perm_options::replace);
    } catch (...) { /* best-effort */ }

    if (args.emit_json) {
        json j;
        j["status"]            = "ok";
        j["algorithm"]         = "Ed25519";
        j["outputSecretPath"]  = sk_path.string();
        j["outputPublicPath"]  = pk_path.string();
        j["outputSecretBytes"] = fhe_toolkit::signing::secret_key_bytes;
        j["outputPublicBytes"] = fhe_toolkit::signing::public_key_bytes;
        std::cout << j.dump(2) << "\n";
    } else {
        std::cout << "Ed25519 signing keypair generated.\n";
        std::cout << "  Secret key:  " << sk_path.string()
                  << " (" << fhe_toolkit::signing::secret_key_bytes << " bytes, owner-only)\n";
        std::cout << "  Public key:  " << pk_path.string()
                  << " (" << fhe_toolkit::signing::public_key_bytes << " bytes)\n\n";
        std::cout << "Register the public key with the platform via the web UI\n";
        std::cout << "(company settings > signing key) or POST /api/companies/{id}/signing-public-key.\n";
        std::cout << "The secret key stays on this machine. It must NEVER be uploaded.\n";
    }
    return 0;
}

// Sign a file's bytes with an Ed25519 secret key. Output is the raw 64-byte
// detached signature.
int run_crypto_sign(const CryptoSignArgs& args) {
    namespace fs = std::filesystem;

    if (args.input_path.empty() || args.secret_key_path.empty() || args.output_path.empty()) {
        std::cerr << "error: --input, --secret-key, and --output are required\n";
        return 2;
    }

    auto sk_bytes = read_bytes(args.secret_key_path);
    auto sk = fhe_toolkit::signing::load_secret_key(sk_bytes);
    auto message = read_bytes(args.input_path);
    auto sig = fhe_toolkit::signing::sign(sk, message);

    const fs::path out_path(args.output_path);
    if (out_path.has_parent_path()) fs::create_directories(out_path.parent_path());
    write_bytes(out_path, std::span<const std::byte>(sig.bytes.data(), sig.bytes.size()));

    if (args.emit_json) {
        json j;
        j["status"]          = "ok";
        j["algorithm"]       = "Ed25519";
        j["inputPath"]       = args.input_path;
        j["inputBytes"]      = message.size();
        j["outputPath"]      = out_path.string();
        j["outputBytes"]     = fhe_toolkit::signing::signature_bytes;
        std::cout << j.dump(2) << "\n";
    } else {
        std::cout << "Signed " << message.size() << " bytes of " << args.input_path << ".\n";
        std::cout << "  Signature: " << out_path.string()
                  << " (" << fhe_toolkit::signing::signature_bytes << " bytes)\n";
    }
    return 0;
}

// Verify a detached signature against an Ed25519 public key. Exit code:
// 0 = signature valid, 1 = signature invalid, 2 = argument or file error.
int run_crypto_verify(const CryptoVerifyArgs& args) {
    if (args.input_path.empty() || args.public_key_path.empty() ||
        args.signature_path.empty()) {
        std::cerr << "error: --input, --public-key, and --signature are required\n";
        return 2;
    }

    auto pk_bytes  = read_bytes(args.public_key_path);
    auto sig_bytes = read_bytes(args.signature_path);
    auto message   = read_bytes(args.input_path);

    auto pk  = fhe_toolkit::signing::load_public_key(pk_bytes);
    auto sig = fhe_toolkit::signing::load_signature(sig_bytes);
    bool ok  = fhe_toolkit::signing::verify(pk, message, sig);

    if (args.emit_json) {
        json j;
        j["status"]     = ok ? "valid" : "invalid";
        j["algorithm"]  = "Ed25519";
        j["inputPath"]  = args.input_path;
        j["inputBytes"] = message.size();
        std::cout << j.dump(2) << "\n";
    } else {
        std::cout << (ok ? "VALID" : "INVALID")
                  << ": Ed25519 signature on " << args.input_path << "\n";
    }
    return ok ? 0 : 1;
}

// Wrap a binary share (the .bin produced by a contribution command) into
// the signed JSON envelope the platform expects at POST keysetup/messages.
// All metadata fields are required: the toolkit cannot infer round number
// or messageType because those depend on the project's manifest, which
// lives platform-side. The Windows / web UI passes them through.
int run_crypto_wrap_envelope(const CryptoWrapEnvelopeArgs& args) {
    namespace fs = std::filesystem;

    if (args.secret_key_path.empty() || args.output_path.empty()) {
        std::cerr << "error: --secret-key and --output are required\n";
        return 2;
    }
    if (args.permission_id.empty()) {
        std::cerr << "error: --permission-id is required\n";
        return 2;
    }
    if (args.round < 1) {
        std::cerr << "error: --round must be >= 1 (manifest round number)\n";
        return 2;
    }
    if (args.message_type.empty()) {
        std::cerr << "error: --message-type is required "
                     "(e.g. pk-share, relin-round1, sum-round1-continue)\n";
        return 2;
    }

    // Mode selection: --object-key triggers payloadRef mode; otherwise we
    // need --payload for inline base64 mode.
    const bool ref_mode = !args.object_key.empty();
    if (ref_mode) {
        if (args.size_bytes == 0) {
            std::cerr << "error: --size-bytes is required when --object-key is set\n";
            return 2;
        }
    } else {
        if (args.payload_path.empty()) {
            std::cerr << "error: --payload is required (or use --object-key + --size-bytes for the GCS-mediated path)\n";
            return 2;
        }
    }

    const auto sk_bytes = read_bytes(args.secret_key_path);
    auto sk = fhe_toolkit::signing::load_secret_key(sk_bytes);

    fhe_toolkit::registry::EnvelopeFields fields;
    fields.permission_id   = args.permission_id;
    fields.round           = args.round;
    fields.message_type    = args.message_type;
    fields.timestamp       = args.timestamp.empty()
                                ? fhe_toolkit::registry::iso8601_now_utc()
                                : args.timestamp;

    std::string body;
    std::size_t payload_size = 0;
    try {
        if (ref_mode) {
            fhe_toolkit::registry::PayloadRef ref;
            ref.object_key = args.object_key;
            ref.size_bytes = args.size_bytes;
            payload_size = args.size_bytes;
            body = fhe_toolkit::registry::make_signed_envelope_from_ref(
                ref, fields, sk);
        } else {
            const auto payload = read_bytes(args.payload_path);
            payload_size = payload.size();
            body = fhe_toolkit::registry::make_signed_envelope(
                std::span<const std::byte>(payload.data(), payload.size()),
                fields, sk);
        }
    } catch (const std::exception& e) {
        std::cerr << "error: failed to build envelope: " << e.what() << "\n";
        return 1;
    }

    const fs::path out_path(args.output_path);
    if (out_path.has_parent_path()) fs::create_directories(out_path.parent_path());
    write_text(out_path, body);

    if (args.emit_json) {
        json j;
        j["status"]         = "ok";
        j["mode"]           = ref_mode ? "payloadRef" : "payloadB64";
        j["outputPath"]     = out_path.string();
        j["outputBytes"]    = body.size();
        j["payloadBytes"]   = payload_size;
        j["round"]          = fields.round;
        j["messageType"]    = fields.message_type;
        j["permissionId"]   = fields.permission_id;
        j["timestamp"]      = fields.timestamp;
        if (ref_mode) j["objectKey"] = args.object_key;
        std::cout << j.dump(2) << "\n";
    } else {
        std::cout << "Signed envelope written (" << (ref_mode ? "payloadRef" : "payloadB64") << " mode).\n";
        std::cout << "  Output:        " << out_path.string()
                  << " (" << body.size() << " bytes)\n";
        std::cout << "  Round:         " << fields.round << "\n";
        std::cout << "  Message type:  " << fields.message_type << "\n";
        std::cout << "  Payload bytes: " << payload_size << "\n";
        if (ref_mode) std::cout << "  Object key:    " << args.object_key << "\n";
        std::cout << "  Timestamp:     " << fields.timestamp << "\n";
    }
    return 0;
}

// Sign the final-keys submission envelope. Reads the to-sign file emitted
// by the platform's web UI (or assembled by a customer script) and writes
// the signed JSON upload body. Strictly offline: no network calls, no GCS
// access, no platform interaction. The caller is responsible for having
// already uploaded the three blob files to GCS and assembled the to-sign
// file with the resulting objectKeys + sha256 hashes.
int run_crypto_wrap_final_keys_envelope(const CryptoWrapFinalKeysEnvelopeArgs& args) {
    namespace fs = std::filesystem;

    if (args.to_sign_path.empty() || args.secret_key_path.empty() || args.output_path.empty()) {
        std::cerr << "error: --to-sign, --secret-key, and --output are required\n";
        return 2;
    }

    // Read the to-sign file.
    json to_sign;
    try {
        std::ifstream in(args.to_sign_path);
        if (!in) {
            std::cerr << "error: cannot open --to-sign file: " << args.to_sign_path << "\n";
            return 1;
        }
        in >> to_sign;
    } catch (const std::exception& e) {
        std::cerr << "error: --to-sign file is not valid JSON: " << e.what() << "\n";
        return 1;
    }

    if (!to_sign.is_object()) {
        std::cerr << "error: --to-sign file must be a JSON object\n";
        return 1;
    }

    // Required top-level fields.
    auto require_str = [&](const char* name) -> std::string {
        if (!to_sign.contains(name) || !to_sign.at(name).is_string()) {
            throw std::runtime_error(std::string("--to-sign file missing required string field: ") + name);
        }
        return to_sign.at(name).get<std::string>();
    };

    fhe_toolkit::registry::FinalKeysEnvelopeFields fields;
    std::vector<fhe_toolkit::registry::FinalKeyRef> refs;
    try {
        fields.permission_id   = require_str("permissionId");
        fields.timestamp       = require_str("timestamp");

        if (!to_sign.contains("keys") || !to_sign.at("keys").is_array()) {
            throw std::runtime_error("--to-sign file missing required array field: keys");
        }
        for (const auto& k : to_sign.at("keys")) {
            if (!k.is_object()) throw std::runtime_error("keys[] entry is not an object");
            fhe_toolkit::registry::FinalKeyRef r;
            r.key_type   = k.at("keyType").get<std::string>();
            r.object_key = k.at("objectKey").get<std::string>();
            r.sha256_hex = k.at("sha256Hex").get<std::string>();
            refs.push_back(std::move(r));
        }
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }

    // Load the signing key.
    std::vector<std::byte> sk_bytes;
    fhe_toolkit::signing::SigningSecretKey sk;
    try {
        sk_bytes = read_bytes(args.secret_key_path);
        sk = fhe_toolkit::signing::load_secret_key(sk_bytes);
    } catch (const std::exception& e) {
        std::cerr << "error: cannot load signing secret key: " << e.what() << "\n";
        return 1;
    }

    // Build the signed envelope.
    std::string body;
    try {
        body = fhe_toolkit::registry::make_signed_final_keys_envelope(refs, fields, sk);
    } catch (const std::exception& e) {
        std::cerr << "error: failed to build envelope: " << e.what() << "\n";
        return 1;
    }

    const fs::path out_path(args.output_path);
    if (out_path.has_parent_path()) fs::create_directories(out_path.parent_path());
    write_text(out_path, body);

    if (args.emit_json) {
        json j;
        j["status"]         = "ok";
        j["outputPath"]     = out_path.string();
        j["outputBytes"]    = body.size();
        j["permissionId"]   = fields.permission_id;
        j["timestamp"]      = fields.timestamp;
        j["keyCount"]       = refs.size();
        std::cout << j.dump(2) << "\n";
    } else {
        std::cout << "Signed final-keys envelope written.\n";
        std::cout << "  Output:           " << out_path.string()
                  << " (" << body.size() << " bytes)\n";
        std::cout << "  Permission ID:    " << fields.permission_id << "\n";
        std::cout << "  Timestamp:        " << fields.timestamp << "\n";
        std::cout << "  Key count:        " << refs.size() << "\n";
        std::cout << "\nUpload this file to POST /api/fhe-permissions/"
                  << fields.permission_id << "/keysetup/final-keys\n";
    }
    return 0;
}

// 2-party in-process self-test: simulates a full collaboration without
// touching the platform. Exercises joint keysetup (relin + rotation),
// EvalMult + EvalAtIndex, and threshold decryption. The protocol calls go
// through the same Context::*_round1_initial/_continue/_combine methods
// that the demo scripts drive, so a pass here means the multi-party crypto
// code is consistent with itself.
int run_crypto_selftest_multiparty(const CryptoSelftestArgs& args) {
    auto spec = get_crypto_context_spec(args.context_spec);
    if (!spec) {
        std::cerr << "error: unknown context spec: " << args.context_spec << "\n";
        return 2;
    }

    using clock = std::chrono::steady_clock;
    auto ms = [](clock::time_point a, clock::time_point b) {
        return std::chrono::duration_cast<std::chrono::milliseconds>(b - a).count();
    };

    const auto t0 = clock::now();
    Context ctx(*spec);
    const auto t1 = clock::now();

    // -------- 2-party keygen --------
    auto kpA = ctx.multiparty_keygen();                       // Party A (data owner / lead)
    auto kpB = ctx.multiparty_keygen(kpA.public_key);         // Party B (data consumer / main)
    // kpB.public_key is the JOINT public key.
    const auto t2 = clock::now();

    // -------- Multi-party relin keysetup (4-step) --------
    {
        auto relinA1   = ctx.relin_round1_initial(kpA.secret_key);
        auto relinB1   = ctx.relin_round1_continue(kpB.secret_key, relinA1);
        auto combinedR1 = ctx.relin_combine_round1(relinA1, relinB1, kpB.public_key);
        auto relinA2   = ctx.relin_round2(kpA.secret_key, combinedR1, kpB.public_key);
        auto relinB2   = ctx.relin_round2(kpB.secret_key, combinedR1, kpB.public_key);
        auto finalRelin = ctx.relin_combine_round2(relinA2, relinB2, combinedR1);
        ctx.install_relin_key(finalRelin);
    }
    const auto t3 = clock::now();

    // -------- Multi-party rotation keysetup --------
    const std::vector<int32_t> indices = {1};   // single-slot right rotation
    {
        auto rotA = ctx.rotation_round1_initial(kpA.secret_key, indices);
        auto rotB = ctx.rotation_round1_continue(kpB.secret_key, rotA, indices, kpB.public_key);
        auto finalRot = ctx.rotation_combine(rotA, rotB, kpB.public_key);
        ctx.install_rotation_keys(finalRot);
    }
    const auto t4 = clock::now();

    // -------- Encrypt two known vectors with the joint PK --------
    // For BFV: integers. For CKKS: doubles (cast from same values).
    const std::vector<int64_t> input_a_i = {1, 2, 3, 4, 5, 6, 7, 8};
    const std::vector<int64_t> input_b_i = {2, 2, 2, 2, 2, 2, 2, 2};
    fhe_toolkit::crypto::PlaintextPacked ptA, ptB;
    if (spec->scheme == "CKKS") {
        std::vector<double> a_d(input_a_i.begin(), input_a_i.end());
        std::vector<double> b_d(input_b_i.begin(), input_b_i.end());
        ptA = ctx.encode_ckks_packed(a_d);
        ptB = ctx.encode_ckks_packed(b_d);
    } else {
        ptA = ctx.encode_packed(input_a_i);
        ptB = ctx.encode_packed(input_b_i);
    }
    auto ctA = ctx.encrypt(kpB.public_key, ptA);   // encrypt with joint PK
    auto ctB = ctx.encrypt(kpB.public_key, ptB);
    const auto t5 = clock::now();

    // -------- EvalMult + EvalAtIndex (rotation by 1) --------
    // EvalMult: expected slot-wise product = {2, 4, 6, 8, 10, 12, 14, 16}.
    // Then rotate left by 1: expected = {4, 6, 8, 10, 12, 14, 16, 2}.
    // (We don't directly call EvalAtIndex through Context yet - the rotation
    // keys are installed in the underlying CC, and EvalMult is exposed via
    // Context::eval_mult. For now, the rotation key install IS the test;
    // a full rotate-and-verify happens once we expose EvalAtIndex on Context.)
    auto ctMul = ctx.eval_mult(ctA, ctB);
    const auto t6 = clock::now();

    // -------- Threshold decrypt (lead + main + combine) --------
    auto partialA = ctx.partial_decrypt_lead(kpA.secret_key, ctMul);
    auto partialB = ctx.partial_decrypt_main(kpB.secret_key, ctMul);
    std::vector<const fhe_toolkit::crypto::Ciphertext*> ptrs = {&partialA, &partialB};
    auto decoded = ctx.combine_partials(ptrs);
    const auto t7 = clock::now();

    // -------- Verify --------
    // Expected: {2, 4, 6, 8, 10, 12, 14, 16}.
    const std::vector<int64_t> expected = {2, 4, 6, 8, 10, 12, 14, 16};
    bool ok;
    if (spec->scheme == "CKKS") {
        constexpr double TOL = 1.0;  // looser tolerance after one mul + threshold
        auto values = decoded.real_values();
        ok = values.size() >= expected.size();
        for (size_t i = 0; ok && i < expected.size(); ++i) {
            if (std::abs(values[i] - static_cast<double>(expected[i])) > TOL) ok = false;
        }
    } else {
        auto values = decoded.values();
        ok = values.size() >= expected.size();
        for (size_t i = 0; ok && i < expected.size(); ++i) {
            if (values[i] != expected[i]) ok = false;
        }
    }

    if (args.emit_json) {
        json out;
        out["status"]                  = ok ? "ok" : "fail";
        out["contextSpec"]             = args.context_spec;
        out["mode"]                    = "multi-party-2";
        out["timings"]["contextMs"]    = ms(t0, t1);
        out["timings"]["mpKeyGenMs"]   = ms(t1, t2);
        out["timings"]["relinSetupMs"] = ms(t2, t3);
        out["timings"]["rotSetupMs"]   = ms(t3, t4);
        out["timings"]["encryptMs"]    = ms(t4, t5);
        out["timings"]["evalMultMs"]   = ms(t5, t6);
        out["timings"]["thresholdDecryptMs"] = ms(t6, t7);
        out["timings"]["totalMs"]      = ms(t0, t7);
        std::cout << out.dump(2) << "\n";
    } else {
        std::cout << (ok ? "OK" : "FAIL") << ": multi-party crypto self-test on context "
                  << args.context_spec << "\n";
        std::cout << "  Expected slots:   " << expected.size() << " ({2,4,6,...,16})\n";
        std::cout << "  Timings:\n";
        std::cout << "    Build context:        " << ms(t0, t1) << " ms\n";
        std::cout << "    2-party joint KeyGen: " << ms(t1, t2) << " ms\n";
        std::cout << "    Relin keysetup (mp):  " << ms(t2, t3) << " ms\n";
        std::cout << "    Rotation keysetup:    " << ms(t3, t4) << " ms\n";
        std::cout << "    Encrypt (2 vectors):  " << ms(t4, t5) << " ms\n";
        std::cout << "    EvalMult:             " << ms(t5, t6) << " ms\n";
        std::cout << "    Threshold decrypt:    " << ms(t6, t7) << " ms\n";
        std::cout << "    Total:                " << ms(t0, t7) << " ms\n";
    }
    return ok ? 0 : 1;
}

int run_crypto_selftest(const CryptoSelftestArgs& args) {
    if (args.multi_party) {
        return run_crypto_selftest_multiparty(args);
    }

    auto spec = get_crypto_context_spec(args.context_spec);
    if (!spec) {
        std::cerr << "error: unknown context spec: " << args.context_spec << "\n";
        return 2;
    }

    using clock = std::chrono::steady_clock;
    auto ms = [](clock::time_point a, clock::time_point b) {
        return std::chrono::duration_cast<std::chrono::milliseconds>(b - a).count();
    };

    const auto t0 = clock::now();
    Context ctx(*spec);
    const auto t1 = clock::now();
    auto kp = ctx.generate_keypair();
    const auto t2 = clock::now();

    // BFV: exact integers. CKKS: approximate doubles; check within tolerance.
    const std::vector<int64_t> input_i = {1, 2, 3, 42, -7, 100, 1000, -1000};
    fhe_toolkit::crypto::PlaintextPacked pt;
    if (spec->scheme == "CKKS") {
        std::vector<double> input_d(input_i.begin(), input_i.end());
        pt = ctx.encode_ckks_packed(input_d);
    } else {
        pt = ctx.encode_packed(input_i);
    }
    const auto t3 = clock::now();
    auto ct = ctx.encrypt(kp.public_key, pt);
    const auto t4 = clock::now();
    auto decoded = ctx.decrypt(kp.secret_key, ct);
    const auto t5 = clock::now();

    bool ok;
    if (spec->scheme == "CKKS") {
        constexpr double TOL = 1e-3;  // post-encode/decrypt CKKS tolerance
        auto values = decoded.real_values();
        ok = values.size() >= input_i.size();
        if (ok) {
            for (size_t i = 0; i < input_i.size(); ++i) {
                if (std::abs(values[i] - static_cast<double>(input_i[i])) > TOL) {
                    ok = false;
                    break;
                }
            }
        }
    } else {
        auto values = decoded.values();
        ok = values.size() >= input_i.size();
        if (ok) {
            for (size_t i = 0; i < input_i.size(); ++i) {
                if (values[i] != input_i[i]) { ok = false; break; }
            }
        }
    }
    auto ct_bytes = ct.serialize();

    if (args.emit_json) {
        json out;
        out["status"]              = ok ? "ok" : "fail";
        out["contextSpec"]         = args.context_spec;
        out["inputValues"]         = input_i.size();
        out["ciphertextBytes"]     = ct_bytes.size();
        out["timings"]["contextMs"]  = ms(t0, t1);
        out["timings"]["keygenMs"]   = ms(t1, t2);
        out["timings"]["encodeMs"]   = ms(t2, t3);
        out["timings"]["encryptMs"]  = ms(t3, t4);
        out["timings"]["decryptMs"]  = ms(t4, t5);
        out["timings"]["totalMs"]    = ms(t0, t5);
        std::cout << out.dump(2) << "\n";
    } else {
        std::cout << (ok ? "OK" : "FAIL") << ": crypto self-test on context "
                  << args.context_spec << "\n";
        std::cout << "  Input slots tested: " << input_i.size() << "\n";
        std::cout << "  Ciphertext size:    " << ct_bytes.size() << " bytes\n";
        std::cout << "  Timings:\n";
        std::cout << "    Build context:    " << ms(t0, t1) << " ms\n";
        std::cout << "    Generate keypair: " << ms(t1, t2) << " ms\n";
        std::cout << "    Encode plaintext: " << ms(t2, t3) << " ms\n";
        std::cout << "    Encrypt:          " << ms(t3, t4) << " ms\n";
        std::cout << "    Decrypt:          " << ms(t4, t5) << " ms\n";
        std::cout << "    Total:            " << ms(t0, t5) << " ms\n";
    }
    return ok ? 0 : 1;
}

// Encrypt a plaintext input file under a joint public key. Two modes:
//
//   Mode A: --function-def <path> + --input-name <name>
//     Read schema + schemaParams from the signed function-definition file.
//     Trust + audit + consistency story; recommended for production.
//
//   Mode B: --schema <name> + per-schema flags
//     Specify encoding directly via CLI flags. Useful for scripting and
//     ad-hoc work. Both parties in a multi-party flow MUST agree on
//     identical flags for the math to work.
//
// Mode A verifies the function-def's pinned registry signature before use
// (see the fail-closed check in run_crypto_encrypt). Unsigned/altered defs are
// refused; the registry public key is pinned in registry/trust_root.cpp.
// Generic bundle encoder (defined below, near the old tree path). Encrypts a
// structured list of real vectors described by an upstream cleartext prep step
// into one archive. crypto encrypt dispatches here on layout=="encrypted-bundle"
// so the toolkit stays function-agnostic (no per-function verbs).
int encrypt_bundle(const std::string& input_path,
                   const std::string& joint_public_key_path,
                   const std::string& output_path,
                   const std::string& context_spec_id,
                   bool emit_json);

int run_crypto_encrypt(const CryptoEncryptArgs& args) {
    namespace fs = std::filesystem;

    if (args.input_path.empty() || args.joint_public_key_path.empty() ||
        args.output_path.empty()) {
        std::cerr << "error: --input, --joint-public-key, and --output are required\n";
        return 2;
    }

    const bool has_fn_def = !args.function_def_path.empty();
    const bool has_schema = !args.schema.empty();
    if (has_fn_def == has_schema) {
        std::cerr << "error: exactly one of --function-def or --schema must be set\n";
        std::cerr << "       --function-def reads encoding rules from a signed JSON file (mode A)\n";
        std::cerr << "       --schema specifies the encoding directly via CLI flags (mode B)\n";
        return 2;
    }

    // Resolved per-input encoding parameters.
    std::string context_spec_id;
    std::string schema_name;
    std::string layout;  // mode A 'layout'; "encrypted-bundle" -> generic bundle encoder
    std::string sep_str;
    bool skip_header = false;
    std::string cols_spec = "all";
    // Provenance fields, populated only in mode A for the result summary.
    std::string fn_slug, fn_version, fn_role;

    if (has_fn_def) {
        // Mode A: function-def-driven.
        if (args.input_name.empty()) {
            std::cerr << "error: --input-name is required when --function-def is set\n";
            return 2;
        }

        json fn_def;
        try {
            std::ifstream fn_in(args.function_def_path);
            if (!fn_in) {
                std::cerr << "error: cannot open function-def file: "
                          << args.function_def_path << "\n";
                return 1;
            }
            fn_in >> fn_def;
        } catch (const std::exception& e) {
            std::cerr << "error: failed to parse function-def JSON: " << e.what() << "\n";
            return 1;
        }

        // Fail-closed signature verification (the function id is a security
        // property: both parties must compute the SAME signed definition).
        // Refuse to encrypt against any def that is unsigned or altered. The
        // registry public key is pinned in the binary (registry_public_key()),
        // never fetched from the server we are verifying. Platform AND custom
        // functions are signed by the registry at registration, so a missing or
        // bad signature here means tampering or a non-registry def -> we stop.
        if (!fhe_toolkit::registry::verify_function_definition_signature(
                fn_def, fhe_toolkit::registry::registry_public_key())) {
            std::cerr << "error: function-definition signature verification FAILED\n"
                      << "       file: " << args.function_def_path << "\n"
                      << "       refusing to encrypt: the definition is unsigned or has "
                         "been altered.\n"
                      << "       the function id must carry a valid JuLenny registry "
                         "signature.\n";
            return 1;
        }

        json input_def;
        if (fn_def.contains("inputs") && fn_def["inputs"].is_array()) {
            for (const auto& in : fn_def["inputs"]) {
                if (in.value("name", "") == args.input_name) {
                    input_def = in;
                    break;
                }
            }
        }
        if (input_def.is_null()) {
            std::cerr << "error: function-def has no input named '"
                      << args.input_name << "'\n       available inputs: ";
            if (fn_def.contains("inputs") && fn_def["inputs"].is_array()) {
                bool first = true;
                for (const auto& in : fn_def["inputs"]) {
                    if (!first) std::cerr << ", ";
                    std::cerr << in.value("name", "?");
                    first = false;
                }
            }
            std::cerr << "\n";
            return 1;
        }

        fn_slug    = fn_def.value("slug", std::string{});
        fn_version = fn_def.value("version", std::string{});
        fn_role    = input_def.value("role", std::string{});
        context_spec_id = args.context_spec.empty()
            ? fn_def.value("cryptoContextSpec", std::string{"bfv-default-v1"})
            : args.context_spec;
        schema_name = input_def.value("schema", std::string{});
        layout      = input_def.value("layout", std::string{});

        json params = input_def.value("schemaParams", json::object());
        sep_str     = params.value("separator", std::string{});
        skip_header = params.value("skipHeader", false);
        cols_spec   = params.value("columns", std::string{"all"});
    } else {
        // Mode B: explicit-flag.
        schema_name = args.schema;
        sep_str     = args.separator;
        skip_header = args.skip_header;
        cols_spec   = args.columns;
        context_spec_id = args.context_spec.empty()
            ? std::string{"bfv-default-v1"}
            : args.context_spec;
    }

    // Bundle-layout inputs (e.g. an encrypted-model bundle) are not flat
    // value-per-line data. Their structuring happens upstream (cleartext prep
    // driven by the function-def's encodingRecipe); the file we receive here is
    // already a generic header + real-vector-list description. Dispatch to the
    // generic bundle encoder so crypto encrypt stays function-agnostic.
    if (layout == "encrypted-bundle") {
        return encrypt_bundle(args.input_path, args.joint_public_key_path,
                              args.output_path, context_spec_id, args.emit_json);
    }

    auto spec = get_crypto_context_spec(context_spec_id);
    if (!spec) {
        std::cerr << "error: unknown context spec: " << context_spec_id << "\n";
        return 2;
    }
    const std::int64_t slot_count = resolve_slot_count(spec->id);

    // Dispatch on schema.
    // 'packed-real' is the function-def schema name for plain real-vector
    // inputs (e.g. decision-tree 'features': feature j in slot j). It encodes
    // identically to 'weight-vector' (one real per line -> CKKS slots in file
    // order), so it folds into the same path.
    const bool is_weight_vector    = (schema_name == "weight-vector" || schema_name == "packed-real");
    const bool is_binary_indicator = (schema_name == "binary-indicator");
    if (schema_name != "indicator-hash" && !is_weight_vector && !is_binary_indicator) {
        std::cerr << "error: unsupported schema '" << schema_name
                  << "' (this version supports 'indicator-hash', 'weight-vector',"
                  << " 'packed-real', and 'binary-indicator')\n";
        return 2;
    }
    if (is_weight_vector && spec->scheme != "CKKS") {
        std::cerr << "error: schema '" << schema_name << "' requires a CKKS context spec; got '"
                  << spec->id << "' (" << spec->scheme << ")\n";
        return 2;
    }

    // Read the input file and apply the schema's encoding.
    std::ifstream in_file(args.input_path);
    if (!in_file) {
        std::cerr << "error: cannot open input file: " << args.input_path << "\n";
        return 1;
    }

    std::vector<std::int64_t> indicator;  // indicator-hash
    std::vector<double> weights;          // weight-vector
    std::size_t records_read = 0;
    std::size_t lines_seen = 0;
    std::size_t lines_skipped = 0;
    std::size_t collisions = 0;
    std::size_t duplicate_rows = 0;      // same record listed more than once
    std::size_t colliding_records = 0;   // genuinely different records sharing a slot
    std::unordered_map<std::size_t, std::set<std::uint64_t>> slot_full_hashes;
    std::string line;

    if (is_weight_vector) {
        // weight-vector: one finite real value per line, encoded into CKKS
        // slots in file order. Blank lines and '#' comments are skipped.
        while (std::getline(in_file, line)) {
            ++lines_seen;
            auto trimmed = trim_inplace(line);
            if (trimmed.empty() || trimmed[0] == '#') { ++lines_skipped; continue; }
            double v = 0.0;
            std::size_t pos = 0;
            try {
                v = std::stod(trimmed, &pos);
            } catch (const std::exception&) {
                pos = std::string::npos;
            }
            if (pos != trimmed.size() || !std::isfinite(v)) {
                std::cerr << "error: line " << lines_seen << " is not a number: '"
                          << trimmed << "'\n"
                          << "       weight-vector inputs are one real value per line\n";
                return 1;
            }
            weights.push_back(v);
            ++records_read;
        }
        if (static_cast<std::int64_t>(weights.size()) > slot_count) {
            std::cerr << "error: input has " << weights.size()
                      << " weights but the context has only " << slot_count
                      << " slots\n";
            return 1;
        }
    } else if (is_binary_indicator) {
        // binary-indicator: one 0/1 per line; the slot index is the line's
        // POSITION in the agreed grid enumeration (no hashing). Blank lines
        // and '#' comments are skipped and do not advance the position, so
        // the grid file can be annotated.
        indicator.assign(static_cast<std::size_t>(slot_count), 0);
        std::size_t grid_pos = 0;
        while (std::getline(in_file, line)) {
            ++lines_seen;
            auto trimmed = trim_inplace(line);
            if (trimmed.empty() || trimmed[0] == '#') { ++lines_skipped; continue; }
            if (trimmed != "0" && trimmed != "1") {
                std::cerr << "error: line " << lines_seen << " must be 0 or 1, got '"
                          << trimmed << "'\n"
                          << "       binary-indicator inputs are one 0/1 per grid position\n";
                return 1;
            }
            if (static_cast<std::int64_t>(grid_pos) >= slot_count) {
                std::cerr << "error: input has more than " << slot_count
                          << " grid positions (context slot limit)\n";
                return 1;
            }
            if (trimmed == "1") indicator[grid_pos] = 1;
            ++grid_pos;
            ++records_read;
        }
    } else {

    const char sep_char = sep_str.empty() ? '\0' : sep_str[0];
    auto cols = parse_columns_spec(cols_spec);
    indicator.assign(static_cast<std::size_t>(slot_count), 0);
    bool header_consumed = false;
    while (std::getline(in_file, line)) {
        ++lines_seen;
        auto trimmed = trim_inplace(line);
        if (trimmed.empty() || trimmed[0] == '#') { ++lines_skipped; continue; }
        if (skip_header && !header_consumed) {
            header_consumed = true;
            ++lines_skipped;
            continue;
        }
        auto composed = compose_record(trimmed, sep_char, cols);
        if (composed.empty()) { ++lines_skipped; continue; }
        const auto full_hash = fnv1a_64(composed);
        auto slot = static_cast<std::size_t>(
            full_hash % static_cast<std::uint64_t>(slot_count));
        if (indicator[slot] != 0) ++collisions;
        // Separate the two reasons a slot fills twice. Storing the FULL 64-bit hash
        // (not the slot) identifies the record: same hash = same composed record, so
        // a repeat is a duplicate ROW in the input, while a different hash in the same
        // slot is a genuine collision. Eight bytes per distinct record keeps this cheap
        // on large inputs. Reporting a single blended "collisions" number, as this used
        // to, leaves the user unable to tell a harmless duplicate from a false positive.
        auto& seen_here = slot_full_hashes[slot];
        if (!seen_here.insert(full_hash).second) {
            ++duplicate_rows;
        } else if (seen_here.size() > 1) {
            ++colliding_records;
        }
        // SET semantics, deliberately not += 1. Record overlap asks "is this record
        // present", not "how many rows mention it", so a slot is a membership flag.
        // Accumulating instead made a person listed twice count twice, which inflated
        // the overlap total (5 shared people reported as 6) - a wrong answer, not just
        // a cosmetic one, and duplicates are routine in real customer lists.
        indicator[slot] = 1;
        ++records_read;
    }

    }  // end indicator-hash branch

    if (records_read == 0) {
        std::cerr << "error: no records found in input (read " << lines_seen
                  << " lines, " << lines_skipped << " skipped as blank/comment/header)\n";
        return 1;
    }

    std::size_t unique_slots = 0;
    for (auto v : indicator) if (v != 0) ++unique_slots;

    // Load the joint public key and encrypt the indicator vector. CKKS
    // encoding takes doubles, BFV takes int64; otherwise the path is the same.
    auto pk_bytes = read_bytes(args.joint_public_key_path);

    Context ctx(*spec);
    auto pk = fhe_toolkit::crypto::PublicKey::deserialize(ctx, pk_bytes);
    // Encode + encrypt under the freshly built context (from the spec), NOT the
    // pk's deserialized keygen context. With MATHBACKEND=4 + noiseEstimate aligned
    // across toolkit and wrapper, this context matches the wrapper's byte for byte,
    // and because it has never been (de)serialized in this process OpenFHE embeds
    // the FULL context into the ciphertext. Adopting the pk's context instead made
    // OpenFHE emit a process-global back-reference (to the context id from the pk
    // deserialize) that the wrapper cannot resolve from a standalone ciphertext
    // file ("Could not find id ..."). The joint pk is still passed to encrypt(),
    // so the ciphertext stays bound to the joint secret shares.
    fhe_toolkit::crypto::PlaintextPacked pt;
    if (is_weight_vector) {
        pt = ctx.encode_ckks_packed(weights);
    } else if (spec->scheme == "CKKS") {
        std::vector<double> real_vals(indicator.begin(), indicator.end());
        pt = ctx.encode_ckks_packed(real_vals);
    } else {
        pt = ctx.encode_packed(indicator);
    }
    auto ct = ctx.encrypt(pk, pt);
    auto ct_bytes = ct.serialize();

    const fs::path out_path(args.output_path);
    if (out_path.has_parent_path()) fs::create_directories(out_path.parent_path());
    write_bytes(out_path, ct_bytes);

    if (args.emit_json) {
        json out;
        out["status"]            = "ok";
        out["mode"]              = has_fn_def ? "function-def" : "explicit-flag";
        if (has_fn_def) {
            out["functionSlug"]    = fn_slug;
            out["functionVersion"] = fn_version;
            out["inputName"]       = args.input_name;
            out["role"]            = fn_role;
        }
        out["schema"]            = schema_name;
        out["recordsRead"]       = records_read;
        if (!is_weight_vector) {
            out["uniqueSlotsSet"] = unique_slots;
            out["hashCollisions"]   = collisions;
            out["duplicateRows"]    = duplicate_rows;
            out["collidingRecords"] = colliding_records;
        }
        out["linesSkipped"]      = lines_skipped;
        out["slotCount"]         = slot_count;
        out["outputPath"]        = out_path.string();
        out["ciphertextBytes"]   = ct_bytes.size();
        out["contextSpec"]       = spec->id;
        std::cout << out.dump(2) << "\n";
    } else {
        std::cout << "Encrypted " << records_read << " records.\n";
        if (has_fn_def) {
            std::cout << "  Function:        " << (fn_slug.empty() ? "?" : fn_slug)
                      << " v" << (fn_version.empty() ? "?" : fn_version) << "\n";
            std::cout << "  Input role:      " << args.input_name
                      << " (" << (fn_role.empty() ? "?" : fn_role) << ")\n";
        } else {
            std::cout << "  Mode:            explicit-flag (no function-def)\n";
        }
        std::cout << "  Schema:          " << schema_name << "\n";
        std::cout << "  Input file:      " << args.input_path << "\n";
        std::cout << "  Joint pub key:   " << args.joint_public_key_path << "\n";
        std::cout << "  Output:          " << out_path.string()
                  << " (" << ct_bytes.size() << " bytes)\n";
        std::cout << "  Context:         " << spec->id
                  << " (" << spec->scheme << ", slots=" << slot_count;
        if (spec->scheme == "BFV") std::cout << ", p=" << spec->plaintext_modulus;
        std::cout << ")\n";
        if (!is_weight_vector) {
            std::cout << "  Unique slots:    " << unique_slots << "\n";
            std::cout << "  Duplicate rows:  " << duplicate_rows
                      << " (the same record listed more than once)\n";
            std::cout << "  Collisions:      " << colliding_records
                      << " (genuinely different records sharing a slot)\n";
            if (duplicate_rows > 0) {
                std::cout << "    (duplicates are encoded once, so they do not inflate the\n";
                std::cout << "     result; no need to de-duplicate the file.)\n";
            }
        }
        std::cout << "  Skipped lines:   " << lines_skipped
                  << " (blank, comment, or header)\n";
    }
    return 0;
}

int run_crypto_decrypt(const CryptoDecryptArgs& args) {
    if (args.input_path.empty() || args.secret_key_path.empty()) {
        std::cerr << "error: --input and --secret-key are required\n";
        return 2;
    }

    auto spec = get_crypto_context_spec(args.context_spec);
    if (!spec) {
        std::cerr << "error: unknown context spec: " << args.context_spec << "\n";
        return 2;
    }

    auto ct_bytes = read_bytes(args.input_path);
    auto sk_bytes = read_bytes(args.secret_key_path);

    Context ctx(*spec);
    auto sk = fhe_toolkit::crypto::SecretKey::deserialize(ctx, sk_bytes);
    auto ct = fhe_toolkit::crypto::Ciphertext::deserialize(ctx, ct_bytes);
    auto pt = ctx.decrypt(sk, ct);
    auto values = values_as_int64(pt, *spec);

    // Aggregates for the display.
    std::size_t non_zero = 0;
    std::int64_t total_sum = 0;
    std::int64_t max_value = 0;
    for (auto v : values) {
        if (v != 0) ++non_zero;
        total_sum += v;
        if (v > max_value) max_value = v;
    }

    if (args.emit_json) {
        json out;
        out["status"]        = "ok";
        out["totalSlots"]    = values.size();
        out["nonZeroSlots"]  = non_zero;
        out["sumOfSlots"]    = total_sum;
        out["maxSlotValue"]  = max_value;
        out["contextSpec"]   = spec->id;
        if (args.non_zero_only) {
            json sample = json::object();
            for (std::size_t i = 0; i < values.size(); ++i) {
                if (values[i] != 0) sample[std::to_string(i)] = values[i];
            }
            out["nonZeroValues"] = sample;
        } else {
            const auto n = std::min<std::size_t>(values.size(),
                                                  static_cast<std::size_t>(args.show_slots));
            out["firstSlots"] = std::vector<std::int64_t>(values.begin(), values.begin() + n);
        }
        std::cout << out.dump(2) << "\n";
    } else {
        std::cout << "Decrypted ciphertext.\n";
        std::cout << "  Context:        " << spec->id << "\n";
        std::cout << "  Total slots:    " << values.size() << "\n";
        std::cout << "  Non-zero slots: " << non_zero << "\n";
        std::cout << "  Sum of slots:   " << total_sum << "\n";
        std::cout << "  Max slot value: " << max_value << "\n";
        if (args.non_zero_only) {
            std::cout << "  Non-zero slot positions and values:\n";
            for (std::size_t i = 0; i < values.size(); ++i) {
                if (values[i] != 0) {
                    std::cout << "    [" << i << "] = " << values[i] << "\n";
                }
            }
        } else {
            const auto n = std::min<std::size_t>(values.size(),
                                                  static_cast<std::size_t>(args.show_slots));
            std::cout << "  First " << n << " slots:\n    [";
            for (std::size_t i = 0; i < n; ++i) {
                if (i > 0) std::cout << ", ";
                std::cout << values[i];
            }
            std::cout << "]\n";
        }
    }
    return 0;
}

// Per-party keysetup contribution. Each party runs this on their own machine, with
// only the previous party's public-key contribution (if any) as input. The
// secret share never leaves this machine; the public output is uploaded to
// the platform for the next party (or, for role=main, becomes the joint pk).
int run_crypto_keysetup_contribute(const CryptoKeysetupContributeArgs& args) {
    namespace fs = std::filesystem;

    if (args.role != "lead" && args.role != "main") {
        std::cerr << "error: --role must be 'lead' (party 1) or 'main' (party 2+)\n";
        return 2;
    }
    if (args.output_secret_path.empty() || args.output_public_path.empty()) {
        std::cerr << "error: --output-secret and --output-public are required\n";
        return 2;
    }
    if (args.role == "main" && args.peer_share_path.empty()) {
        std::cerr << "error: --peer-share is required when --role main "
                     "(the previous party's public-key contribution)\n";
        return 2;
    }
    if (args.role == "lead" && !args.peer_share_path.empty()) {
        std::cerr << "error: --peer-share must NOT be set when --role lead "
                     "(lead has no peer input; it starts the chain)\n";
        return 2;
    }

    auto spec = get_crypto_context_spec(args.context_spec);
    if (!spec) {
        std::cerr << "error: unknown context spec: " << args.context_spec << "\n";
        return 2;
    }

    Context ctx(*spec);

    fhe_toolkit::crypto::KeyPair kp;
    if (args.role == "lead") {
        // Party 1: standalone keygen. The output public key IS this party's
        // contribution to the chain. OpenFHE's MultipartyKeyGen() with no
        // prev_pk is equivalent to KeyGen().
        kp = ctx.multiparty_keygen();
    } else {
        // Party 2+: chain on the previous party's public key. The output
        // public key IS the joint public key (it transitively incorporates
        // every prior party's contribution).
        auto peer_bytes = read_bytes(args.peer_share_path);
        auto peer_pk = fhe_toolkit::crypto::PublicKey::deserialize(ctx, peer_bytes);
        kp = ctx.multiparty_keygen(peer_pk);
    }

    auto sk_bytes = kp.secret_key.serialize();
    auto pk_bytes = kp.public_key.serialize();

    const fs::path sk_path(args.output_secret_path);
    const fs::path pk_path(args.output_public_path);
    if (sk_path.has_parent_path()) fs::create_directories(sk_path.parent_path());
    if (pk_path.has_parent_path()) fs::create_directories(pk_path.parent_path());

    write_bytes(sk_path, sk_bytes);
    write_bytes(pk_path, pk_bytes);

    // Tighten permissions on the secret file (owner-only). No-op on most
    // Windows configurations; sets explicit 0600 on POSIX.
    try {
        fs::permissions(sk_path,
                        fs::perms::owner_read | fs::perms::owner_write,
                        fs::perm_options::replace);
    } catch (...) { /* best-effort */ }

    if (args.emit_json) {
        json out;
        out["status"]                = "ok";
        out["role"]                  = args.role;
        out["contextSpec"]           = args.context_spec;
        out["outputSecretPath"]      = sk_path.string();
        out["outputPublicPath"]      = pk_path.string();
        out["outputSecretBytes"]     = sk_bytes.size();
        out["outputPublicBytes"]     = pk_bytes.size();
        out["outputPublicIsJointPk"] = (args.role == "main");
        std::cout << out.dump(2) << "\n";
    } else {
        std::cout << "Keysetup contribution generated (role: " << args.role << ").\n";
        std::cout << "  Secret share: " << sk_path.string()
                  << " (" << sk_bytes.size() << " bytes, owner-only)\n";
        std::cout << "  Public " << (args.role == "main" ? "joint key" : "contribution")
                  << ": " << pk_path.string()
                  << " (" << pk_bytes.size() << " bytes)\n";
        if (args.role == "lead") {
            std::cout << "\nUpload the public contribution to the platform. The peer\n";
            std::cout << "party will download it and produce the joint public key.\n";
        } else {
            std::cout << "\nUpload the joint public key to the platform. Both parties\n";
            std::cout << "will use it to encrypt data for this project.\n";
        }
        std::cout << "The secret share stays on this machine. It must NEVER be uploaded.\n";
    }

    return 0;
}

// Per-party joint relinearization key contribution. Customer runs this on
// their own machine; secret never leaves. Round 1 has two roles (lead has
// no peer input; main chains on lead's contribution). Round 2 is symmetric:
// both parties run the same operation with their own secret and the round-1
// combined output as inputs.
int run_crypto_relin_contribute(const CryptoRelinContributeArgs& args) {
    namespace fs = std::filesystem;

    if (args.round != 1 && args.round != 2) {
        std::cerr << "error: --round must be 1 or 2\n";
        return 2;
    }
    if (args.secret_key_path.empty() || args.output_path.empty()) {
        std::cerr << "error: --secret-key and --output are required\n";
        return 2;
    }
    if (args.round == 1) {
        if (args.role != "lead" && args.role != "main") {
            std::cerr << "error: --role must be 'lead' or 'main' for round 1\n";
            return 2;
        }
        if (args.role == "main" && args.peer_share_path.empty()) {
            std::cerr << "error: --peer-share is required for round 1 role=main "
                         "(lead's round-1 contribution)\n";
            return 2;
        }
        if (args.role == "lead" && !args.peer_share_path.empty()) {
            std::cerr << "error: --peer-share must NOT be set for round 1 role=lead\n";
            return 2;
        }
    } else {  // round 2
        if (args.combined_r1_path.empty() || args.joint_pk_path.empty()) {
            std::cerr << "error: --combined-r1 and --joint-pk are required for round 2\n";
            return 2;
        }
    }

    auto spec = get_crypto_context_spec(args.context_spec);
    if (!spec) {
        std::cerr << "error: unknown context spec: " << args.context_spec << "\n";
        return 2;
    }

    Context ctx(*spec);
    auto sk_bytes = read_bytes(args.secret_key_path);
    auto sk = fhe_toolkit::crypto::SecretKey::deserialize(ctx, sk_bytes);

    fhe_toolkit::crypto::EvalKey out;
    if (args.round == 1 && args.role == "lead") {
        out = ctx.relin_round1_initial(sk);
    } else if (args.round == 1 && args.role == "main") {
        auto prev_bytes = read_bytes(args.peer_share_path);
        auto prev = fhe_toolkit::crypto::EvalKey::deserialize(ctx, prev_bytes);
        out = ctx.relin_round1_continue(sk, prev);
    } else {  // round 2
        auto c1_bytes = read_bytes(args.combined_r1_path);
        auto c1 = fhe_toolkit::crypto::EvalKey::deserialize(ctx, c1_bytes);
        auto jpk_bytes = read_bytes(args.joint_pk_path);
        auto jpk = fhe_toolkit::crypto::PublicKey::deserialize(ctx, jpk_bytes);
        out = ctx.relin_round2(sk, c1, jpk);
    }

    auto out_bytes = out.serialize();
    const fs::path out_path(args.output_path);
    if (out_path.has_parent_path()) fs::create_directories(out_path.parent_path());
    write_bytes(out_path, out_bytes);

    if (args.emit_json) {
        json j;
        j["status"]       = "ok";
        j["keyType"]      = "relinearization";
        j["round"]        = args.round;
        if (args.round == 1) j["role"] = args.role;
        j["outputPath"]   = out_path.string();
        j["outputBytes"]  = out_bytes.size();
        std::cout << j.dump(2) << "\n";
    } else {
        std::cout << "Relinearization key contribution (round " << args.round;
        if (args.round == 1) std::cout << ", role " << args.role;
        std::cout << ").\n";
        std::cout << "  Output: " << out_path.string()
                  << " (" << out_bytes.size() << " bytes)\n";
        std::cout << "\nUpload this file to the platform's keysetup endpoint for the\n";
        std::cout << "current sub-round, then wait for the peer's contribution and\n";
        std::cout << "the combined output before advancing to the next sub-round.\n";
    }
    return 0;
}

// Deterministic combine for joint relinearization key. Both parties run
// this independently on the same inputs and produce byte-identical output.
// Platform verifies byte-equality across submissions.
int run_crypto_relin_combine(const CryptoRelinCombineArgs& args) {
    namespace fs = std::filesystem;

    if (args.round != 1 && args.round != 2) {
        std::cerr << "error: --round must be 1 or 2\n";
        return 2;
    }
    if (args.share_a_path.empty() || args.share_b_path.empty() || args.output_path.empty()) {
        std::cerr << "error: --share-a, --share-b, and --output are required\n";
        return 2;
    }
    if (args.round == 1 && args.joint_pk_path.empty()) {
        std::cerr << "error: --joint-pk is required for round 1 combine\n";
        return 2;
    }
    if (args.round == 2 && args.combined_r1_path.empty()) {
        std::cerr << "error: --combined-r1 is required for round 2 combine\n";
        return 2;
    }

    auto spec = get_crypto_context_spec(args.context_spec);
    if (!spec) {
        std::cerr << "error: unknown context spec: " << args.context_spec << "\n";
        return 2;
    }

    Context ctx(*spec);
    auto a = fhe_toolkit::crypto::EvalKey::deserialize(ctx, read_bytes(args.share_a_path));
    auto b = fhe_toolkit::crypto::EvalKey::deserialize(ctx, read_bytes(args.share_b_path));

    fhe_toolkit::crypto::EvalKey out;
    if (args.round == 1) {
        auto jpk = fhe_toolkit::crypto::PublicKey::deserialize(ctx, read_bytes(args.joint_pk_path));
        out = ctx.relin_combine_round1(a, b, jpk);
    } else {
        auto c1 = fhe_toolkit::crypto::EvalKey::deserialize(ctx, read_bytes(args.combined_r1_path));
        out = ctx.relin_combine_round2(a, b, c1);
    }

    auto out_bytes = out.serialize();
    const fs::path out_path(args.output_path);
    if (out_path.has_parent_path()) fs::create_directories(out_path.parent_path());
    write_bytes(out_path, out_bytes);

    if (args.emit_json) {
        json j;
        j["status"]      = "ok";
        j["keyType"]     = "relinearization";
        j["round"]       = args.round;
        j["combineKind"] = (args.round == 1) ? "intermediate" : "final";
        j["outputPath"]  = out_path.string();
        j["outputBytes"] = out_bytes.size();
        std::cout << j.dump(2) << "\n";
    } else {
        std::cout << "Relinearization key " << (args.round == 1 ? "round-1 intermediate" : "final")
                  << " combine.\n";
        std::cout << "  Output: " << out_path.string()
                  << " (" << out_bytes.size() << " bytes)\n";
        std::cout << "\nUpload this (or its hash) to the platform for byte-equality\n";
        std::cout << "verification against the peer's independently-computed combine.\n";
    }
    return 0;
}

// Per-party joint sum key contribution. Lead and main run different toolkit
// primitives; the resulting share files have the same format.
int run_crypto_sum_contribute(const CryptoSumContributeArgs& args) {
    namespace fs = std::filesystem;

    if (args.role != "lead" && args.role != "main") {
        std::cerr << "error: --role must be 'lead' or 'main'\n";
        return 2;
    }
    if (args.secret_key_path.empty() || args.output_path.empty()) {
        std::cerr << "error: --secret-key and --output are required\n";
        return 2;
    }
    if (args.role == "main" && (args.peer_share_path.empty() || args.joint_pk_path.empty())) {
        std::cerr << "error: --peer-share and --joint-pk are required for role=main\n";
        return 2;
    }
    if (args.role == "lead" && (!args.peer_share_path.empty() || !args.joint_pk_path.empty())) {
        std::cerr << "error: --peer-share and --joint-pk must NOT be set for role=lead\n";
        return 2;
    }

    auto spec = get_crypto_context_spec(args.context_spec);
    if (!spec) {
        std::cerr << "error: unknown context spec: " << args.context_spec << "\n";
        return 2;
    }

    Context ctx(*spec);
    auto sk = fhe_toolkit::crypto::SecretKey::deserialize(ctx, read_bytes(args.secret_key_path));

    fhe_toolkit::crypto::SumKeyMap out;
    if (args.role == "lead") {
        out = ctx.sum_round1_initial(sk);
    } else {
        auto prev = fhe_toolkit::crypto::SumKeyMap::deserialize(ctx, read_bytes(args.peer_share_path));
        auto jpk = fhe_toolkit::crypto::PublicKey::deserialize(ctx, read_bytes(args.joint_pk_path));
        out = ctx.sum_round1_continue(sk, prev, jpk);
    }

    auto out_bytes = out.serialize();
    const fs::path out_path(args.output_path);
    if (out_path.has_parent_path()) fs::create_directories(out_path.parent_path());
    write_bytes(out_path, out_bytes);

    if (args.emit_json) {
        json j;
        j["status"]      = "ok";
        j["keyType"]     = "sum";
        j["role"]        = args.role;
        j["outputPath"]  = out_path.string();
        j["outputBytes"] = out_bytes.size();
        std::cout << j.dump(2) << "\n";
    } else {
        std::cout << "Sum key contribution (role " << args.role << ").\n";
        std::cout << "  Output: " << out_path.string()
                  << " (" << out_bytes.size() << " bytes)\n";
        std::cout << "\nUpload this to the platform for the peer to download.\n";
    }
    return 0;
}

// Deterministic combine for joint sum key. Both parties run this on the same
// inputs and produce byte-identical output; platform verifies byte-equality.
int run_crypto_sum_combine(const CryptoSumCombineArgs& args) {
    namespace fs = std::filesystem;

    if (args.share_a_path.empty() || args.share_b_path.empty() ||
        args.joint_pk_path.empty() || args.output_path.empty()) {
        std::cerr << "error: --share-a, --share-b, --joint-pk, and --output are required\n";
        return 2;
    }

    auto spec = get_crypto_context_spec(args.context_spec);
    if (!spec) {
        std::cerr << "error: unknown context spec: " << args.context_spec << "\n";
        return 2;
    }

    Context ctx(*spec);
    auto a = fhe_toolkit::crypto::SumKeyMap::deserialize(ctx, read_bytes(args.share_a_path));
    auto b = fhe_toolkit::crypto::SumKeyMap::deserialize(ctx, read_bytes(args.share_b_path));
    auto jpk = fhe_toolkit::crypto::PublicKey::deserialize(ctx, read_bytes(args.joint_pk_path));

    auto out = ctx.sum_combine(a, b, jpk);
    auto out_bytes = out.serialize();
    const fs::path out_path(args.output_path);
    if (out_path.has_parent_path()) fs::create_directories(out_path.parent_path());
    write_bytes(out_path, out_bytes);

    if (args.emit_json) {
        json j;
        j["status"]      = "ok";
        j["keyType"]     = "sum";
        j["combineKind"] = "final";
        j["outputPath"]  = out_path.string();
        j["outputBytes"] = out_bytes.size();
        std::cout << j.dump(2) << "\n";
    } else {
        std::cout << "Sum key final combine.\n";
        std::cout << "  Output: " << out_path.string()
                  << " (" << out_bytes.size() << " bytes)\n";
        std::cout << "\nUpload this (or its hash) to the platform for byte-equality\n";
        std::cout << "verification against the peer's independently-computed combine.\n";
    }
    return 0;
}

// Parse a "1,2,4,-1,-2" comma-separated integer list into a vector<int32_t>.
// Whitespace around commas is tolerated. Empty entries are skipped. Throws on
// any token that doesn't fully parse as an integer.
std::vector<int32_t> parse_indices_csv(std::string_view csv) {
    std::vector<int32_t> out;
    std::string buf;
    auto flush = [&]() {
        if (buf.empty()) return;
        std::size_t pos = 0;
        int v = std::stoi(buf, &pos);
        if (pos != buf.size()) throw std::runtime_error("bad index token: '" + buf + "'");
        out.push_back(static_cast<int32_t>(v));
        buf.clear();
    };
    for (char c : csv) {
        if (c == ' ' || c == '\t') continue;
        if (c == ',') flush();
        else buf.push_back(c);
    }
    flush();
    return out;
}

// Per-party joint rotation key contribution. Mirrors sum-contribute but
// requires --indices specifying which rotation indices to generate keys for.
int run_crypto_rotation_contribute(const CryptoRotationContributeArgs& args) {
    namespace fs = std::filesystem;

    if (args.role != "lead" && args.role != "main") {
        std::cerr << "error: --role must be 'lead' or 'main'\n";
        return 2;
    }
    if (args.secret_key_path.empty() || args.output_path.empty()) {
        std::cerr << "error: --secret-key and --output are required\n";
        return 2;
    }
    if (args.indices_csv.empty()) {
        std::cerr << "error: --indices is required (e.g. --indices '1,2,4,-1,-2')\n";
        return 2;
    }
    if (args.role == "main" && (args.peer_share_path.empty() || args.joint_pk_path.empty())) {
        std::cerr << "error: --peer-share and --joint-pk are required for role=main\n";
        return 2;
    }
    if (args.role == "lead" && (!args.peer_share_path.empty() || !args.joint_pk_path.empty())) {
        std::cerr << "error: --peer-share and --joint-pk must NOT be set for role=lead\n";
        return 2;
    }

    auto spec = get_crypto_context_spec(args.context_spec);
    if (!spec) {
        std::cerr << "error: unknown context spec: " << args.context_spec << "\n";
        return 2;
    }

    std::vector<int32_t> indices;
    try {
        indices = parse_indices_csv(args.indices_csv);
    } catch (const std::exception& e) {
        std::cerr << "error: --indices parse error: " << e.what() << "\n";
        return 2;
    }
    if (indices.empty()) {
        std::cerr << "error: --indices parsed to empty list\n";
        return 2;
    }

    Context ctx(*spec);
    auto sk = fhe_toolkit::crypto::SecretKey::deserialize(ctx, read_bytes(args.secret_key_path));

    fhe_toolkit::crypto::RotationKeyMap out;
    if (args.role == "lead") {
        out = ctx.rotation_round1_initial(sk, indices);
    } else {
        auto prev = fhe_toolkit::crypto::RotationKeyMap::deserialize(ctx, read_bytes(args.peer_share_path));
        auto jpk = fhe_toolkit::crypto::PublicKey::deserialize(ctx, read_bytes(args.joint_pk_path));
        out = ctx.rotation_round1_continue(sk, prev, indices, jpk);
    }

    auto out_bytes = out.serialize();
    const fs::path out_path(args.output_path);
    if (out_path.has_parent_path()) fs::create_directories(out_path.parent_path());
    write_bytes(out_path, out_bytes);

    if (args.emit_json) {
        json j;
        j["status"]      = "ok";
        j["keyType"]     = "rotation";
        j["role"]        = args.role;
        j["indexCount"]  = indices.size();
        j["outputPath"]  = out_path.string();
        j["outputBytes"] = out_bytes.size();
        std::cout << j.dump(2) << "\n";
    } else {
        std::cout << "Rotation key contribution (role " << args.role << ", "
                  << indices.size() << " indices).\n";
        std::cout << "  Output: " << out_path.string()
                  << " (" << out_bytes.size() << " bytes)\n";
        std::cout << "\nUpload this to the platform for the peer to download.\n";
    }
    return 0;
}

// Deterministic combine for joint rotation key. Both parties run this on the
// same inputs and produce byte-identical output.
int run_crypto_rotation_combine(const CryptoRotationCombineArgs& args) {
    namespace fs = std::filesystem;

    if (args.share_a_path.empty() || args.share_b_path.empty() ||
        args.joint_pk_path.empty() || args.output_path.empty()) {
        std::cerr << "error: --share-a, --share-b, --joint-pk, and --output are required\n";
        return 2;
    }

    auto spec = get_crypto_context_spec(args.context_spec);
    if (!spec) {
        std::cerr << "error: unknown context spec: " << args.context_spec << "\n";
        return 2;
    }

    Context ctx(*spec);
    auto a = fhe_toolkit::crypto::RotationKeyMap::deserialize(ctx, read_bytes(args.share_a_path));
    auto b = fhe_toolkit::crypto::RotationKeyMap::deserialize(ctx, read_bytes(args.share_b_path));
    auto jpk = fhe_toolkit::crypto::PublicKey::deserialize(ctx, read_bytes(args.joint_pk_path));

    auto out = ctx.rotation_combine(a, b, jpk);
    auto out_bytes = out.serialize();
    const fs::path out_path(args.output_path);
    if (out_path.has_parent_path()) fs::create_directories(out_path.parent_path());
    write_bytes(out_path, out_bytes);

    if (args.emit_json) {
        json j;
        j["status"]      = "ok";
        j["keyType"]     = "rotation";
        j["combineKind"] = "final";
        j["outputPath"]  = out_path.string();
        j["outputBytes"] = out_bytes.size();
        std::cout << j.dump(2) << "\n";
    } else {
        std::cout << "Rotation key final combine.\n";
        std::cout << "  Output: " << out_path.string()
                  << " (" << out_bytes.size() << " bytes)\n";
        std::cout << "\nUpload this (or its hash) to the platform for byte-equality\n";
        std::cout << "verification against the peer's independently-computed combine.\n";
    }
    return 0;
}

int run_crypto_partial_decrypt(const CryptoPartialDecryptArgs& args) {
    if (args.input_path.empty() || args.secret_key_path.empty() || args.output_path.empty()) {
        std::cerr << "error: --input, --secret-key, and --output are all required\n";
        return 2;
    }

    auto spec = get_crypto_context_spec(args.context_spec);
    if (!spec) {
        std::cerr << "error: unknown context spec: " << args.context_spec << "\n";
        return 2;
    }

    auto ct_bytes = read_bytes(args.input_path);
    auto sk_bytes = read_bytes(args.secret_key_path);

    Context ctx(*spec);
    auto sk = fhe_toolkit::crypto::SecretKey::deserialize(ctx, sk_bytes);
    auto ct = fhe_toolkit::crypto::Ciphertext::deserialize(ctx, ct_bytes);

    auto partial = args.lead
        ? ctx.partial_decrypt_lead(sk, ct)
        : ctx.partial_decrypt_main(sk, ct);
    auto partial_bytes = partial.serialize();

    // Guard has_parent_path() as every other output path in this file does. A bare
    // filename (--output partial.bin) has an EMPTY parent, and create_directories("")
    // throws; nothing here catches it, so the process died via abort() with exit code
    // 0xC0000409 and not one byte on stdout or stderr. The crypto had already succeeded -
    // only the directory bookkeeping failed - but from outside it looked like threshold
    // decryption was broken. The MCP always passes absolute paths, so this only ever hit
    // people driving the CLI directly, which is exactly what the docs tell them to do.
    const std::filesystem::path out_path(args.output_path);
    if (out_path.has_parent_path()) std::filesystem::create_directories(out_path.parent_path());
    write_bytes(args.output_path, partial_bytes);

    if (args.emit_json) {
        json out;
        out["status"]           = "ok";
        out["role"]             = args.lead ? "lead" : "main";
        out["outputPath"]       = args.output_path;
        out["partialBytes"]     = partial_bytes.size();
        out["contextSpec"]      = spec->id;
        std::cout << out.dump(2) << "\n";
    } else {
        std::cout << "Produced partial decryption.\n";
        std::cout << "  Role:           " << (args.lead ? "lead" : "main") << "\n";
        std::cout << "  Input ct:       " << args.input_path << "\n";
        std::cout << "  Secret key:     " << args.secret_key_path << "\n";
        std::cout << "  Output:         " << args.output_path
                  << " (" << partial_bytes.size() << " bytes)\n";
        std::cout << "  Context:        " << spec->id << "\n";
        std::cout << "\nThe output is a partial-decryption blob; on its own it reveals\n";
        std::cout << "nothing about the plaintext. Combine it with every other party's\n";
        std::cout << "partial to recover the plaintext.\n";
    }
    return 0;
}

int run_crypto_combine(const CryptoCombineArgs& args) {
    if (args.partial_paths.size() < 2) {
        std::cerr << "error: at least 2 partial files required (got " << args.partial_paths.size() << ")\n";
        return 2;
    }

    auto spec = get_crypto_context_spec(args.context_spec);
    if (!spec) {
        std::cerr << "error: unknown context spec: " << args.context_spec << "\n";
        return 2;
    }

    Context ctx(*spec);

    // Read every partial as a Ciphertext (partial decryptions are
    // Ciphertext-shaped blobs in the underlying scheme). We keep the
    // deserialised objects alive for the entire combine call and pass
    // raw pointers to combine_partials.
    std::vector<fhe_toolkit::crypto::Ciphertext> partials;
    partials.reserve(args.partial_paths.size());
    for (const auto& path : args.partial_paths) {
        auto bytes = read_bytes(path);
        partials.push_back(fhe_toolkit::crypto::Ciphertext::deserialize(ctx, bytes));
    }
    std::vector<const fhe_toolkit::crypto::Ciphertext*> ptrs;
    ptrs.reserve(partials.size());
    for (const auto& p : partials) ptrs.push_back(&p);

    auto pt = ctx.combine_partials(ptrs);

    // Real-valued output (weight-vector style results, e.g. federated-average
    // global weights). Slot values are fractional by design; integer rounding
    // would destroy them, so emit raw doubles and skip the indicator-style
    // uniform/non-zero analysis entirely.
    if (args.real_output) {
        if (spec->scheme != "CKKS") {
            std::cerr << "error: --real requires a CKKS context spec; got '"
                      << spec->id << "' (" << spec->scheme << ")\n";
            return 2;
        }
        auto reals = pt.real_values();
        const auto n = std::min<std::size_t>(reals.size(),
                                              static_cast<std::size_t>(args.show_slots));
        if (!args.out_file_path.empty()) {
            // Blind-by-design: write the plaintext result to a local file; stdout
            // returns references only (no values), so an agent never sees the
            // decrypted result. Viewing the file is the user's local choice.
            // Separate signal from CKKS noise. Noise sits ~1e-14 while any real value is
            // O(1), so a threshold relative to the largest magnitude splits them with an
            // enormous margin. Without this a one-value result arrived as 8,192 raw
            // doubles and was unreadable.
            double max_abs = 0.0;
            for (double v : reals) max_abs = std::max(max_abs, std::abs(v));
            const double threshold = std::max(1e-9, max_abs * 1e-6);

            json significant = json::object();
            std::size_t significant_count = 0;
            double sum_significant = 0.0;
            for (std::size_t i = 0; i < reals.size(); ++i) {
                if (std::abs(reals[i]) > threshold) {
                    if (significant_count < 4096) {
                        significant[std::to_string(i)] = reals[i];
                    }
                    ++significant_count;
                    sum_significant += reals[i];
                }
            }

            json result;
            result["valueType"]         = "real";
            result["totalSlots"]        = reals.size();
            result["contextSpec"]       = spec->id;
            result["significantSlots"]  = significant_count;
            result["significantValues"] = significant;
            result["sumOfSignificant"]  = sum_significant;
            result["maxAbsValue"]       = max_abs;
            result["noiseThreshold"]    = threshold;
            // CKKS is approximate, so a count of three arrives as 2.999999999999586.
            // Round when every meaningful value sits within a whisker of a whole
            // number, which is the case for counts and match vectors and is not the
            // case for real results like averaged model weights. Never round those.
            bool all_whole = significant_count > 0;
            json rounded = json::object();
            for (auto& [slot, val] : significant.items()) {
                const double v = val.get<double>();
                const double nearest = std::round(v);
                if (std::abs(v - nearest) > std::max(1e-6, std::abs(v) * 1e-9)) {
                    all_whole = false;
                    break;
                }
                rounded[slot] = static_cast<std::int64_t>(nearest);
            }
            if (all_whole) {
                result["significantValuesRounded"] = rounded;
                // The common case is a single answer. Put it where a person will
                // find it instead of making them read a map with one entry.
                if (significant_count == 1) {
                    result["result"] = rounded.begin().value();
                }
            }

            result["note"] = std::string(
                "significantValues holds the slots above the noise threshold, keyed by "
                "slot index. CKKS leaves every other slot at a tiny non-zero value "
                "(~1e-14) which carries no meaning.")
                + (all_whole ? " significantValuesRounded gives the same values as whole numbers."
                             : "")
                + (args.full_vector ? " allValues has every slot."
                                    : " Pass --full-vector to also write every slot.");
            if (args.full_vector) {
                result["allValues"] = std::vector<double>(reals.begin(), reals.end());
            }
            std::filesystem::path op(args.out_file_path);
            if (op.has_parent_path()) std::filesystem::create_directories(op.parent_path());
            std::ofstream of(op, std::ios::trunc);
            if (!of) { std::cerr << "error: cannot open --out-file: " << args.out_file_path << "\n"; return 1; }
            of << result.dump(2) << "\n";
            if (!of) { std::cerr << "error: write failed: " << args.out_file_path << "\n"; return 1; }
            if (args.emit_json) {
                json ref;
                ref["status"]           = "ok";
                ref["partialsCombined"] = args.partial_paths.size();
                ref["totalSlots"]       = reals.size();
                ref["significantSlots"] = significant_count;
                ref["valueType"]        = "real";
                ref["contextSpec"]      = spec->id;
                ref["outputPath"]       = op.string();
                std::cout << ref.dump(2) << "\n";
            } else {
                std::cout << "ok: wrote real-valued plaintext result ("
                          << significant_count << " meaningful of " << reals.size()
                          << " slots) to " << op.string() << "\n";
            }
            return 0;
        }
        if (args.emit_json) {
            json out;
            out["status"]           = "ok";
            out["partialsCombined"] = args.partial_paths.size();
            out["totalSlots"]       = reals.size();
            out["valueType"]        = "real";
            out["contextSpec"]      = spec->id;
            out["firstSlots"]       = std::vector<double>(reals.begin(), reals.begin() + n);
            std::cout << out.dump(2) << "\n";
        } else {
            std::cout << "Combined " << args.partial_paths.size()
                      << " partial decryptions into a real-valued plaintext.\n";
            std::cout << "  Context:        " << spec->id << "\n";
            std::cout << "  Total slots:    " << reals.size() << "\n";
            std::cout << "  First " << n << " slots:\n";
            for (std::size_t i = 0; i < n; ++i) {
                char buf[32];
                std::snprintf(buf, sizeof(buf), "%.6f", reals[i]);
                std::cout << "    [" << i << "] = " << buf << "\n";
            }
        }
        return 0;
    }

    auto values = values_as_int64(pt, *spec);

    std::size_t non_zero = 0;
    std::int64_t total_sum = 0;
    std::int64_t max_value = 0;
    for (auto v : values) {
        if (v != 0) ++non_zero;
        total_sum += v;
        if (v > max_value) max_value = v;
    }

    // Uniform detection: every non-zero slot holds the same value (count-
    // aggregation, replicated by EvalSum; or itemized indicator with all
    // matches as 1). Collapse the per-slot dump into a single "Answer"
    // line so we don't print 16384 identical entries.
    //
    // All-zeros is trivially uniform with value 0. This is the count-style
    // result for "no overlap", and we still want to report it as
    // Answer: 0 rather than silently dropping the answer field.
    bool uniform = true;
    std::int64_t uniform_value = 0;
    bool seeded = false;
    for (auto v : values) {
        if (v == 0) continue;
        if (!seeded) { uniform_value = v; seeded = true; }
        else if (v != uniform_value) { uniform = false; break; }
    }
    // If !seeded, every slot was 0; uniform stays true, uniform_value stays 0.

    if (!args.out_file_path.empty()) {
        // Blind-by-design: write the plaintext result to a local file; stdout
        // returns references only (no values, not even non-zero counts), so an
        // agent never sees the decrypted answer. Viewing the file is the user's
        // local choice.
        json result;
        result["valueType"]    = "int";
        result["totalSlots"]   = values.size();
        result["nonZeroSlots"] = non_zero;
        result["sumOfSlots"]   = total_sum;
        result["maxSlotValue"] = max_value;
        result["contextSpec"]  = spec->id;
        if (uniform) result["answer"] = uniform_value;
        {
            json nz = json::object();
            for (std::size_t i = 0; i < values.size(); ++i)
                if (values[i] != 0) nz[std::to_string(i)] = values[i];
            result["nonZeroValues"] = nz;
        }
        std::filesystem::path op(args.out_file_path);
        if (op.has_parent_path()) std::filesystem::create_directories(op.parent_path());
        std::ofstream of(op, std::ios::trunc);
        if (!of) { std::cerr << "error: cannot open --out-file: " << args.out_file_path << "\n"; return 1; }
        of << result.dump(2) << "\n";
        if (!of) { std::cerr << "error: write failed: " << args.out_file_path << "\n"; return 1; }
        if (args.emit_json) {
            json ref;
            ref["status"]           = "ok";
            ref["partialsCombined"] = args.partial_paths.size();
            ref["totalSlots"]       = values.size();
            ref["contextSpec"]      = spec->id;
            ref["outputPath"]       = op.string();
            std::cout << ref.dump(2) << "\n";
        } else {
            std::cout << "ok: wrote plaintext result (" << values.size() << " slots) to "
                      << op.string() << "\n";
        }
        return 0;
    }

    if (args.emit_json) {
        json out;
        out["status"]           = "ok";
        out["partialsCombined"] = args.partial_paths.size();
        out["totalSlots"]       = values.size();
        out["nonZeroSlots"]     = non_zero;
        out["sumOfSlots"]       = total_sum;
        out["maxSlotValue"]     = max_value;
        out["contextSpec"]      = spec->id;

        // .answer is set whenever the non-zero slots all hold the same
        // value (count-style functions, or itemized indicator vectors
        // where every match is 1). Independent of --non-zero.
        if (uniform) {
            out["answer"] = uniform_value;
        }

        // --non-zero ALWAYS populates .nonZeroValues when set, even if
        // .answer is also set. Itemized functions need the slot
        // positions for post-decrypt resolve-indicator; emitting both
        // .answer and .nonZeroValues for uniform outputs costs nothing
        // and lets callers branch on the function-def output shape
        // rather than on which fields happen to be present.
        if (args.non_zero_only) {
            json sample = json::object();
            for (std::size_t i = 0; i < values.size(); ++i) {
                if (values[i] != 0) sample[std::to_string(i)] = values[i];
            }
            out["nonZeroValues"] = sample;
        } else {
            const auto n = std::min<std::size_t>(values.size(),
                                                  static_cast<std::size_t>(args.show_slots));
            out["firstSlots"] = std::vector<std::int64_t>(values.begin(), values.begin() + n);
        }
        std::cout << out.dump(2) << "\n";
    } else {
        std::cout << "Combined " << args.partial_paths.size() << " partial decryptions into plaintext.\n";
        std::cout << "  Context:        " << spec->id << "\n";
        std::cout << "  Total slots:    " << values.size() << "\n";
        std::cout << "  Non-zero slots: " << non_zero << "\n";
        std::cout << "  Sum of slots:   " << total_sum << "\n";
        std::cout << "  Max slot value: " << max_value << "\n";
        if (uniform) {
            std::cout << "\nAnswer: " << uniform_value
                      << "  (uniform across " << non_zero << " non-zero slot"
                      << (non_zero == 1 ? "" : "s") << ")\n";
        } else if (args.non_zero_only) {
            std::cout << "  Non-zero slot positions and values:\n";
            for (std::size_t i = 0; i < values.size(); ++i) {
                if (values[i] != 0) {
                    std::cout << "    [" << i << "] = " << values[i] << "\n";
                }
            }
        } else {
            const auto n = std::min<std::size_t>(values.size(),
                                                  static_cast<std::size_t>(args.show_slots));
            std::cout << "  First " << n << " slots:\n    [";
            for (std::size_t i = 0; i < n; ++i) {
                if (i > 0) std::cout << ", ";
                std::cout << values[i];
            }
            std::cout << "]\n";
        }
    }
    return 0;
}

// Diagnostic: dump a ciphertext file's metadata + embedded context params.
int run_crypto_inspect(const CryptoInspectArgs& args) {
    const std::string spec_id =
        args.context_spec.empty() ? std::string{"ckks-default-v1"} : args.context_spec;
    auto spec = get_crypto_context_spec(spec_id);
    if (!spec) {
        std::cerr << "error: unknown context spec: " << spec_id << "\n";
        return 2;
    }

    auto ct_bytes = read_bytes(args.input_path);
    Context ctx(*spec);
    auto ct = fhe_toolkit::crypto::Ciphertext::deserialize(ctx, ct_bytes);

    if (args.emit_json) {
        json out;
        out["status"]      = "ok";
        out["file"]        = args.input_path;
        out["fileBytes"]   = ct_bytes.size();
        out["contextSpec"] = spec->id;
        out["describe"]    = ct.describe();  // non-secret ciphertext/context metadata
        std::cout << out.dump(2) << "\n";
    } else {
        std::cout << "file:           " << args.input_path << "\n";
        std::cout << "fileBytes:      " << ct_bytes.size() << "\n";
        std::cout << ct.describe();
    }
    return 0;
}

// Map indicator-hash non-zero slot positions back to the records that
// produced them. After a threshold-decrypt of an indicator-hash result, the
// non-zero slots tell us "these hash buckets matched" but not "which records
// landed in those buckets". This command re-hashes each line of the local
// CSV the same way crypto encrypt did, and emits the lines whose hash falls
// into the non-zero slot set.
int run_crypto_resolve_indicator(const CryptoResolveIndicatorArgs& args) {
    if (args.slots_csv.empty() || args.input_csv_path.empty() ||
        args.function_def_path.empty() || args.input_name.empty()) {
        std::cerr << "error: --slots, --input, --function-def, and --input-name are all required\n";
        return 2;
    }

    auto spec = get_crypto_context_spec(args.context_spec);
    if (!spec) {
        std::cerr << "error: unknown context spec: " << args.context_spec << "\n";
        return 2;
    }
    const auto slot_count = resolve_slot_count(args.context_spec);

    // Parse --slots into a set for O(1) membership tests.
    std::unordered_set<std::uint64_t> non_zero_set;
    {
        std::string buf;
        bool parse_error = false;
        auto flush = [&]() {
            if (buf.empty()) return;
            try {
                std::size_t pos = 0;
                unsigned long long v = std::stoull(buf, &pos);
                if (pos != buf.size()) throw std::runtime_error("trailing chars");
                non_zero_set.insert(v);
            } catch (const std::exception&) {
                std::cerr << "error: bad slot token: '" << buf << "'\n";
                parse_error = true;
            }
            buf.clear();
        };
        for (char c : args.slots_csv) {
            if (c == ' ' || c == '\t') continue;
            if (c == ',') flush();
            else buf.push_back(c);
        }
        flush();
        if (parse_error) return 2;
    }
    if (non_zero_set.empty()) {
        std::cerr << "error: --slots parsed to empty set\n";
        return 2;
    }

    // Read function-def to get schema + schemaParams for the named input.
    json fn_def;
    try {
        std::ifstream fn_in(args.function_def_path);
        if (!fn_in) {
            std::cerr << "error: cannot open function-def: " << args.function_def_path << "\n";
            return 1;
        }
        fn_in >> fn_def;
    } catch (const std::exception& e) {
        std::cerr << "error: failed to parse function-def JSON: " << e.what() << "\n";
        return 1;
    }

    json input_def;
    if (fn_def.contains("inputs") && fn_def["inputs"].is_array()) {
        for (const auto& in : fn_def["inputs"]) {
            if (in.value("name", "") == args.input_name) { input_def = in; break; }
        }
    }
    if (input_def.is_null()) {
        std::cerr << "error: function-def has no input named '" << args.input_name << "'\n";
        return 1;
    }

    const std::string schema_name = input_def.value("schema", std::string{});
    if (schema_name != "indicator-hash") {
        std::cerr << "error: resolve-indicator only supports indicator-hash schema; got '"
                  << schema_name << "'\n";
        return 2;
    }
    const json params = input_def.value("schemaParams", json::object());
    const std::string sep_str = params.value("separator", std::string{});
    const bool skip_header    = params.value("skipHeader", false);
    const std::string cols_spec = params.value("columns", std::string{"all"});

    const char sep_char = sep_str.empty() ? '\0' : sep_str[0];
    auto cols = parse_columns_spec(cols_spec);

    // Walk the CSV, rehashing each line the same way crypto encrypt did,
    // and collect the lines whose hash falls in non_zero_set.
    std::ifstream in_file(args.input_csv_path);
    if (!in_file) {
        std::cerr << "error: cannot open input file: " << args.input_csv_path << "\n";
        return 1;
    }

    std::vector<std::string> matches;
    // Two DIFFERENT things make a slot hold more than one of your rows, and users
    // cannot be expected to tell them apart from a count alone:
    //
    //   1. The same record listed twice in your file. compose_record trims every
    //      field, so "Susan Mitchell ,2002-12-13" and "Susan Mitchell,2002-12-13"
    //      compose identically. Both rows are the same person, both genuinely match,
    //      and nothing is wrong. This is by far the common case.
    //   2. A real hash collision: two GENUINELY DIFFERENT records landing in one slot.
    //      Here one of them really is a false positive.
    //
    // We hold the composed value - the exact bytes that were hashed - so we can tell
    // these apart exactly rather than leaving a caller to guess. Reporting only the
    // raw count invites a wrong and alarming explanation.
    std::unordered_map<std::uint64_t, std::vector<std::string>> matched_by_slot;
    std::size_t lines_seen = 0, lines_skipped = 0;
    bool header_consumed = false;
    std::string line;
    while (std::getline(in_file, line)) {
        ++lines_seen;
        auto trimmed = trim_inplace(line);
        if (trimmed.empty() || trimmed[0] == '#') { ++lines_skipped; continue; }
        if (skip_header && !header_consumed) { header_consumed = true; ++lines_skipped; continue; }
        auto composed = compose_record(trimmed, sep_char, cols);
        if (composed.empty()) { ++lines_skipped; continue; }
        auto slot = fnv1a_64(composed) % static_cast<std::uint64_t>(slot_count);
        if (non_zero_set.contains(slot)) {
            matches.push_back(std::string(trimmed));
            matched_by_slot[slot].push_back(composed);
        }
    }

    // Classify every slot that matched more than one of our rows.
    std::size_t duplicate_rows = 0;    // extra rows that are the SAME record
    std::size_t colliding_slots = 0;   // slots holding genuinely different records
    for (const auto& [slot, composed_list] : matched_by_slot) {
        std::set<std::string> distinct(composed_list.begin(), composed_list.end());
        duplicate_rows += composed_list.size() - distinct.size();
        if (distinct.size() > 1) ++colliding_slots;
    }
    const std::size_t distinct_matches = matches.size() - duplicate_rows;

    if (args.emit_json) {
        json out;
        out["status"]            = "ok";
        out["matchCount"]          = matches.size();
        out["distinctMatchCount"]  = distinct_matches;
        out["duplicateRowCount"]   = duplicate_rows;
        out["collidingSlotCount"]  = colliding_slots;
        out["nonZeroSlotCount"]  = non_zero_set.size();
        out["linesRead"]         = lines_seen;
        out["linesSkipped"]      = lines_skipped;
        out["matches"]           = matches;
        std::cout << out.dump(2) << "\n";
    } else {
        std::cout << "Resolved indicator-hash slots against " << args.input_csv_path << ".\n";
        std::cout << "  Non-zero slots:   " << non_zero_set.size() << "\n";
        std::cout << "  Lines read:       " << lines_seen << "\n";
        std::cout << "  Lines matched:    " << matches.size() << "\n";
        if (duplicate_rows > 0) {
            std::cout << "  Distinct records: " << distinct_matches << "\n";
            std::cout << "    (" << duplicate_rows << " matched row(s) are the same record listed more\n";
            std::cout << "     than once in your file - e.g. rows differing only by spacing. They\n";
            std::cout << "     are genuine matches, not false positives.)\n";
        }
        if (colliding_slots > 0) {
            std::cout << "  Hash collisions:  " << colliding_slots << " slot(s) hold genuinely different\n";
            std::cout << "     records of yours; one record per affected slot is a false positive.\n";
        }
        std::cout << "  Matched records:\n";
        for (const auto& m : matches) std::cout << "    " << m << "\n";
        if (matches.empty()) {
            std::cout << "    (none - the non-zero slots correspond to records not in this CSV,\n";
            std::cout << "     which is expected for indicator-hash overlap: only the matching\n";
            std::cout << "     party's records that ALSO appear in the other party's set will\n";
            std::cout << "     surface here.)\n";
        }
    }
    return 0;
}

// Map itemized cross-match slots back to rule rows.
//
// The itemized circuit puts rule row i in slot i, so this is a positional lookup,
// not a hash resolve. resolve-indicator cannot answer it: that command re-hashes
// local records to find which slot they landed in, which is correct for overlap
// and the wrong question here.
//
// The parse mirrors the platform's parseCsvPairs exactly: strip trailing CR/LF,
// skip empty lines, skip lines with no comma, trim spaces around each half. Row
// numbering is defined by which lines survive that filter, so any divergence
// makes the output name the wrong rules while looking perfectly plausible.
int run_crypto_resolve_rules(const CryptoResolveRulesArgs& args) {
    if (args.slots_csv.empty() || args.rule_pairs_path.empty() || args.output_path.empty()) {
        std::cerr << "error: --slots, --rule-pairs and --output are all required\n";
        return 2;
    }

    std::vector<std::size_t> slots;
    {
        std::string buf;
        auto flush = [&]() {
            if (buf.empty()) return true;
            try {
                std::size_t pos = 0;
                long long v = std::stoll(buf, &pos);
                if (pos != buf.size()) throw std::runtime_error("trailing chars");
                if (v < 0) throw std::runtime_error("negative");
                slots.push_back(static_cast<std::size_t>(v));
            } catch (const std::exception&) {
                std::cerr << "error: bad slot token: '" << buf << "'\n";
                return false;
            }
            buf.clear();
            return true;
        };
        for (char c : args.slots_csv) {
            if (c == ' ' || c == '\t') continue;
            if (c == ',') { if (!flush()) return 2; }
            else buf.push_back(c);
        }
        if (!flush()) return 2;
    }
    if (slots.empty()) {
        std::cerr << "error: --slots parsed to an empty set\n";
        return 2;
    }

    std::ifstream rf(args.rule_pairs_path);
    if (!rf) {
        std::cerr << "error: cannot open --rule-pairs: " << args.rule_pairs_path << "\n";
        return 2;
    }
    std::vector<std::string> rows;
    std::string line;
    while (std::getline(rf, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
        if (line.empty()) continue;
        auto comma = line.find(',');
        if (comma == std::string::npos) continue;
        std::string left  = line.substr(0, comma);
        std::string right = line.substr(comma + 1);
        auto trim_spaces = [](std::string& v) {
            while (!v.empty() && v.front() == ' ') v.erase(v.begin());
            while (!v.empty() && v.back()  == ' ') v.pop_back();
        };
        trim_spaces(left);
        trim_spaces(right);
        rows.push_back(left + "," + right);
    }

    std::vector<std::string> matched;
    std::vector<std::size_t> out_of_range;
    for (auto slot : slots) {
        if (slot < rows.size()) matched.push_back(rows[slot]);
        else out_of_range.push_back(slot);
    }

    std::filesystem::path op(args.output_path);
    if (op.has_parent_path()) std::filesystem::create_directories(op.parent_path());
    std::ofstream of(op, std::ios::trunc);
    if (!of) {
        std::cerr << "error: cannot open --output: " << args.output_path << "\n";
        return 1;
    }
    for (const auto& m : matched) of << m << "\n";
    if (!of) {
        std::cerr << "error: write failed: " << args.output_path << "\n";
        return 1;
    }
    of.close();

    if (args.emit_json) {
        json out;
        out["status"]     = "ok";
        out["outputPath"] = args.output_path;
        // A slot past the end of the rule list means the two sides are not using the
        // same file. Flag that it happened; the answer itself stays in the file.
        out["outOfRange"] = !out_of_range.empty();
        std::cout << out.dump(2) << "\n";
    } else {
        std::cout << "Wrote " << matched.size() << " matched rule(s) to " << args.output_path << "\n";
        for (const auto& m : matched) std::cout << "    " << m << "\n";
        if (!out_of_range.empty()) {
            std::cout << "  WARNING: " << out_of_range.size() << " slot(s) fall past the end of this\n";
            std::cout << "  rule list (" << rows.size() << " rows). The two sides are not using the\n";
            std::cout << "  same rule file, so this answer cannot be trusted.\n";
        }
    }
    return 0;
}

// Derive the rotation index set from rule_pairs alone, using FNV1a-64 mod
// slotCount on every name. Toolkit-side mirror of the platform's
// derivation (changed in 0.5.5 alongside rule-based-cross-match's encoding
// switch to hash-based slot assignment). Used by phase 4.5 as a defensive
// cross-check vs pendingRotationKeySetup.indices.
//
// Normalization (must match the platform exactly; see contract):
//   - strip leading/trailing ASCII whitespace from each row and each field
//   - skip blank rows (after whitespace strip)
//   - rule_pairs is bare CSV: split on the FIRST comma only
//   - case-sensitive
//   - trailing \r tolerated for \r\n line endings
//   - empty left or right name after normalization: that half is skipped
//     (the OTHER half of the row still contributes its hash)
int run_crypto_derive_rotation_indices(const CryptoDeriveRotationIndicesArgs& args) {
    if (args.rule_pairs_path.empty()) {
        std::cerr << "error: --rule-pairs is required\n";
        return 2;
    }
    if (args.context_spec.empty()) {
        std::cerr << "error: --context-spec is required (used to look up slot count)\n";
        return 2;
    }
    auto spec = get_crypto_context_spec(args.context_spec);
    if (!spec) {
        std::cerr << "error: unknown context spec: " << args.context_spec << "\n";
        return 2;
    }
    const std::int64_t slot_count = resolve_slot_count(spec->id);

    auto normalize = [](std::string s) -> std::string {
        auto not_space = [](unsigned char c) { return !std::isspace(c); };
        s.erase(s.begin(), std::find_if(s.begin(), s.end(), not_space));
        s.erase(std::find_if(s.rbegin(), s.rend(), not_space).base(), s.end());
        return s;
    };

    std::set<std::int32_t> indices;
    std::size_t rows_seen = 0, rows_skipped_blank = 0, rows_no_comma = 0;
    std::size_t names_hashed = 0, halves_skipped_blank = 0;

    std::ifstream in(args.rule_pairs_path);
    if (!in) {
        std::cerr << "error: cannot open rule-pairs: " << args.rule_pairs_path << "\n";
        return 1;
    }
    std::string line;
    while (std::getline(in, line)) {
        ++rows_seen;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        auto row = normalize(line);
        if (row.empty()) { ++rows_skipped_blank; continue; }
        auto comma = row.find(',');
        if (comma == std::string::npos) { ++rows_no_comma; continue; }
        auto left  = normalize(row.substr(0, comma));
        auto right = normalize(row.substr(comma + 1));
        for (const auto& name : { left, right }) {
            if (name.empty()) { ++halves_skipped_blank; continue; }
            auto slot = static_cast<std::int32_t>(
                fnv1a_64(name) % static_cast<std::uint64_t>(slot_count));
            indices.insert(slot);
            ++names_hashed;
        }
    }

    // -1 shifts the accumulator one slot right, which is how the itemized variant
    // gives each rule row its own slot. MUST match the platform's derivation in
    // backend/lib/rotation-index-derivation.ts: if the two sets differ by even one
    // index the keys are built for a circuit the platform is not running.
    if (!indices.empty()) indices.insert(-1);

    std::vector<std::int32_t> sorted_indices(indices.begin(), indices.end());

    if (args.emit_json) {
        json out;
        out["status"]               = "ok";
        out["indices"]              = sorted_indices;
        out["indexCount"]           = sorted_indices.size();
        out["slotCount"]            = slot_count;
        out["contextSpec"]          = spec->id;
        out["rulePairsRowsSeen"]    = rows_seen;
        out["rulePairsRowsBlank"]   = rows_skipped_blank;
        out["rulePairsRowsNoComma"] = rows_no_comma;
        out["namesHashed"]          = names_hashed;
        out["halvesSkippedBlank"]   = halves_skipped_blank;
        std::cout << out.dump(2) << "\n";
    } else {
        std::cout << "Derived rotation index set: " << sorted_indices.size() << " unique indices.\n";
        std::cout << "  Context spec:        " << spec->id << " (slotCount = " << slot_count << ")\n";
        std::cout << "  Rule pairs rows:     " << rows_seen << " seen, "
                  << rows_skipped_blank << " blank, " << rows_no_comma << " missing comma\n";
        std::cout << "  Names hashed:        " << names_hashed
                  << " (" << halves_skipped_blank << " row-halves were blank, skipped)\n";
        std::cout << "  Hash collisions:     " << (names_hashed - sorted_indices.size())
                  << " (names that hashed to a slot already in the set)\n";
        std::cout << "  Indices:             ";
        for (std::size_t i = 0; i < sorted_indices.size(); ++i) {
            if (i > 0) std::cout << ",";
            std::cout << sorted_indices[i];
        }
        std::cout << "\n";
    }
    return 0;
}

int encrypt_bundle(const std::string& input_path,
                   const std::string& joint_public_key_path,
                   const std::string& output_path,
                   const std::string& context_spec_id,
                   bool emit_json) {
    namespace fs = std::filesystem;

    // The input is a generic, cleartext bundle description produced upstream
    // (e.g. by the MCP/scripts executing the function-def's encodingRecipe).
    // The toolkit stays function-agnostic: it knows nothing about trees or any
    // other business shape, only "encode these real vectors, write this header".
    //   { "header": ["LINE", ...],
    //     "vectors": [ [v0, v1, ...]  |  {"fill": x}, ... ] }
    json desc;
    {
        std::ifstream in(input_path);
        if (!in) { std::cerr << "error: cannot open bundle-input file: " << input_path << "\n"; return 1; }
        try { in >> desc; }
        catch (const std::exception& e) {
            std::cerr << "error: invalid bundle-input JSON: " << e.what() << "\n"; return 1;
        }
    }
    if (!desc.contains("vectors") || !desc["vectors"].is_array() || desc["vectors"].empty()) {
        std::cerr << "error: bundle-input must contain a non-empty 'vectors' array\n"; return 2;
    }

    std::vector<std::string> header_lines;
    if (desc.contains("header")) {
        if (!desc["header"].is_array()) {
            std::cerr << "error: bundle-input 'header' must be an array of strings\n"; return 2;
        }
        for (const auto& h : desc["header"]) {
            if (!h.is_string()) { std::cerr << "error: bundle-input 'header' entries must be strings\n"; return 2; }
            header_lines.push_back(h.get<std::string>());
        }
    }

    const std::string ctx_id =
        context_spec_id.empty() ? std::string{"ckks-tree-v1"} : context_spec_id;
    auto spec = get_crypto_context_spec(ctx_id);
    if (!spec) { std::cerr << "error: unknown context spec: " << ctx_id << "\n"; return 2; }
    if (spec->scheme != "CKKS") {
        std::cerr << "error: encrypted-bundle encoding requires a CKKS context; got '"
                  << spec->id << "' (" << spec->scheme << ")\n"; return 2;
    }
    const std::int64_t slot_count = resolve_slot_count(spec->id);

    auto pk_bytes = read_bytes(joint_public_key_path);
    Context ctx(*spec);
    auto pk = fhe_toolkit::crypto::PublicKey::deserialize(ctx, pk_bytes);

    // Build each plaintext vector from its generic description and encrypt it.
    //   [a, b, ...]   explicit values in the low slots (CKKS zero-pads the rest)
    //   {"fill": x}   scalar x replicated across all slots
    // Both are plain real-vector forms; no domain semantics here.
    std::vector<fhe_toolkit::crypto::Ciphertext> cts;
    cts.reserve(desc["vectors"].size());
    std::size_t vi = 0;
    for (const auto& v : desc["vectors"]) {
        std::vector<double> vals;
        if (v.is_array()) {
            vals.reserve(v.size());
            for (const auto& x : v) {
                if (!x.is_number()) { std::cerr << "error: vectors[" << vi << "] has a non-numeric value\n"; return 2; }
                vals.push_back(x.get<double>());
            }
        } else if (v.is_object() && v.contains("fill")) {
            if (!v.at("fill").is_number()) { std::cerr << "error: vectors[" << vi << "].fill must be a number\n"; return 2; }
            vals.assign(static_cast<std::size_t>(slot_count), v.at("fill").get<double>());
        } else {
            std::cerr << "error: vectors[" << vi << "] must be an array or {\"fill\": <number>}\n"; return 2;
        }
        if (vals.size() > static_cast<std::size_t>(slot_count)) {
            std::cerr << "error: vectors[" << vi << "] has " << vals.size()
                      << " values, exceeds slot count " << slot_count << "\n"; return 2;
        }
        cts.push_back(ctx.encrypt(pk, ctx.encode_ckks_packed(vals)));
        ++vi;
    }

    // Serialize ALL vectors in ONE cereal archive (the bundle payload).
    auto payload = ctx.serialize_ciphertext_vector(cts);

    const fs::path out_path(output_path);
    if (out_path.has_parent_path()) std::filesystem::create_directories(out_path.parent_path());
    {
        std::ofstream out(out_path, std::ios::binary | std::ios::trunc);
        if (!out) { std::cerr << "error: cannot open output: " << output_path << "\n"; return 1; }
        for (const auto& line : header_lines) { out << line << "\n"; }
        out << "PAYLOAD\n";
        out.write(reinterpret_cast<const char*>(payload.data()),
                  static_cast<std::streamsize>(payload.size()));
        if (!out) { std::cerr << "error: write failed: " << output_path << "\n"; return 1; }
    }

    if (emit_json) {
        json o;
        o["status"]          = "ok";
        o["ciphertextCount"] = cts.size();
        o["contextSpec"]     = spec->id;
        o["outputPath"]      = out_path.string();
        if (!header_lines.empty()) o["bundleFormat"] = header_lines.front();
        std::cout << o.dump(2) << "\n";
    } else {
        std::cout << "ok: wrote encrypted bundle (" << cts.size() << " ciphertexts; context "
                  << spec->id << ") to " << out_path.string() << "\n";
    }
    return 0;
}

}  // namespace

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
                     CryptoResolveRulesArgs& resolve_rules_args,
                     CryptoDeriveRotationIndicesArgs& derive_rotation_indices_args,
                     CryptoInspectArgs& inspect_args,
                     int* exit_code) {
    auto* crypto = app.add_subcommand("crypto",
        "Cryptographic operations and diagnostics");

    auto* selftest = crypto->add_subcommand("self-test",
        "Verify the OpenFHE install with an encrypt-decrypt round-trip");
    selftest->add_option("--context-spec", selftest_args.context_spec,
                         "Crypto context spec (default: bfv-default-v1)");
    selftest->add_flag  ("--multi-party", selftest_args.multi_party,
                         "Run a 2-party in-process scenario: joint keysetup (relin + rotation) + EvalMult + EvalAtIndex + threshold decrypt");
    selftest->add_flag  ("--json", selftest_args.emit_json, "Emit JSON output");
    selftest->callback([&selftest_args, exit_code]() {
        *exit_code = run_crypto_selftest(selftest_args);
    });

    // Ed25519 signing keypair. One per company; secret stays local, public
    // is registered with the platform via POST /api/companies/{id}/signing-public-key.
    auto* signing_keygen = crypto->add_subcommand("signing-keygen",
        "Generate an Ed25519 signing keypair (one-time per company; secret stays local)");
    signing_keygen->add_option("--output-secret", signing_keygen_args.output_secret_path,
                               "Where to write the 32-byte secret key (owner-only)")->required();
    signing_keygen->add_option("--output-public", signing_keygen_args.output_public_path,
                               "Where to write the 32-byte public key (to upload to the platform)")->required();
    signing_keygen->add_flag  ("--json", signing_keygen_args.emit_json, "Emit JSON output");
    signing_keygen->callback([&signing_keygen_args, exit_code]() {
        *exit_code = run_crypto_signing_keygen(signing_keygen_args);
    });

    // Sign an arbitrary file with an Ed25519 secret key.
    auto* sign = crypto->add_subcommand("sign",
        "Sign a file's bytes with an Ed25519 secret key (produces a 64-byte detached signature)");
    sign->add_option("--input", sign_args.input_path,
                     "File whose bytes are signed")->required();
    sign->add_option("--secret-key", sign_args.secret_key_path,
                     "Ed25519 secret key file (32-byte seed)")->required();
    sign->add_option("--output", sign_args.output_path,
                     "Where to write the 64-byte signature")->required();
    sign->add_flag  ("--json", sign_args.emit_json, "Emit JSON output");
    sign->callback([&sign_args, exit_code]() {
        *exit_code = run_crypto_sign(sign_args);
    });

    // Verify a detached signature.
    auto* verify = crypto->add_subcommand("verify",
        "Verify an Ed25519 signature against a public key (exit 0 = valid, 1 = invalid)");
    verify->add_option("--input", verify_args.input_path,
                       "File that was signed")->required();
    verify->add_option("--public-key", verify_args.public_key_path,
                       "Ed25519 public key file (32 bytes)")->required();
    verify->add_option("--signature", verify_args.signature_path,
                       "Signature file (64 bytes)")->required();
    verify->add_flag  ("--json", verify_args.emit_json, "Emit JSON output");
    verify->callback([&verify_args, exit_code]() {
        *exit_code = run_crypto_verify(verify_args);
    });

    auto* encrypt = crypto->add_subcommand("encrypt",
        "Encrypt a plaintext input file under a joint public key. Two modes: --function-def + --input-name (production; reads encoding rules from a signed function-definition file) OR --schema + per-schema flags (ad-hoc; specify encoding directly).");
    encrypt->add_option("--input", encrypt_args.input_path,
                        "Plaintext input file")->required();
    encrypt->add_option("--joint-public-key", encrypt_args.joint_public_key_path,
                        "Joint public key file (binary)")->required();
    encrypt->add_option("--output", encrypt_args.output_path,
                        "Output ciphertext file (binary)")->required();
    // Mode A: function-def-driven.
    encrypt->add_option("--function-def", encrypt_args.function_def_path,
                        "Signed function-definition JSON file (downloaded from the platform). "
                        "Exclusive with --schema.");
    encrypt->add_option("--input-name", encrypt_args.input_name,
                        "Which input in the function-def to encode for (e.g. 'dataset_a'). "
                        "Required when --function-def is set.");
    // Mode B: explicit-flag.
    encrypt->add_option("--schema", encrypt_args.schema,
                        "Encoding schema name: 'indicator-hash', 'weight-vector' "
                        "(one real value per line, CKKS only), or 'binary-indicator' "
                        "(one 0/1 per line, slot = line position). "
                        "Exclusive with --function-def.");
    encrypt->add_option("--separator", encrypt_args.separator,
                        "Field separator for indicator-hash (e.g. ',', '\\t', ';', '|'); "
                        "empty/omitted means hash the whole line. Mode B only.");
    encrypt->add_option("--columns", encrypt_args.columns,
                        "Columns to include in indicator-hash: 'all' or comma-separated 1-based "
                        "indices like '1,2'. Default 'all'. Mode B only.");
    encrypt->add_flag  ("--skip-header", encrypt_args.skip_header,
                        "Skip the first non-blank line of the input. Mode B only.");
    encrypt->add_option("--context-spec", encrypt_args.context_spec,
                        "Crypto context spec override (default: read from function-def in mode A, "
                        "or 'bfv-default-v1' in mode B)");
    encrypt->add_flag  ("--json", encrypt_args.emit_json, "Emit JSON output");
    encrypt->callback([&encrypt_args, exit_code]() {
        *exit_code = run_crypto_encrypt(encrypt_args);
    });

    auto* decrypt = crypto->add_subcommand("decrypt",
        "Decrypt a single-party ciphertext (for round-trip testing and inspection)");
    decrypt->add_option("--input",      decrypt_args.input_path,
                        "Ciphertext file (binary)")->required();
    decrypt->add_option("--secret-key", decrypt_args.secret_key_path,
                        "Secret key file (binary, cereal-serialized)")->required();
    decrypt->add_option("--context-spec", decrypt_args.context_spec,
                        "Crypto context spec (default: bfv-default-v1)");
    decrypt->add_option("--show-slots", decrypt_args.show_slots,
                        "Number of leading slots to print (default: 16)");
    decrypt->add_flag  ("--non-zero",   decrypt_args.non_zero_only,
                        "Print only slot positions with non-zero values");
    decrypt->add_flag  ("--json",       decrypt_args.emit_json, "Emit JSON output");
    decrypt->callback([&decrypt_args, exit_code]() {
        *exit_code = run_crypto_decrypt(decrypt_args);
    });

    // Per-party keysetup contribution. Customer runs this on their own
    // machine; secret never leaves. Lead = party 1 (no peer input). Main =
    // party 2+ (chains on previous party's public-key contribution; the
    // resulting public output IS the joint public key).
    auto* keysetup_contrib = crypto->add_subcommand("keysetup-contribute",
        "Generate this party's contribution to a joint key setup (offline; local files only)");
    keysetup_contrib->add_option("--role", keysetup_contribute_args.role,
                                 "'lead' (party 1, no peer input) or 'main' (party 2+, chains on peer)")
                    ->required();
    keysetup_contrib->add_option("--peer-share", keysetup_contribute_args.peer_share_path,
                                 "Path to peer's public contribution (required for --role main)");
    keysetup_contrib->add_option("--output-secret", keysetup_contribute_args.output_secret_path,
                                 "Where to write this party's secret share (stays local; NEVER upload)")
                    ->required();
    keysetup_contrib->add_option("--output-public", keysetup_contribute_args.output_public_path,
                                 "Where to write this party's public output. Lead: contribution to upload. Main: the joint public key.")
                    ->required();
    keysetup_contrib->add_option("--context-spec", keysetup_contribute_args.context_spec,
                                 "Crypto context spec (default: bfv-default-v1)");
    keysetup_contrib->add_flag  ("--json", keysetup_contribute_args.emit_json,
                                 "Emit JSON output");
    keysetup_contrib->callback([&keysetup_contribute_args, exit_code]() {
        *exit_code = run_crypto_keysetup_contribute(keysetup_contribute_args);
    });

    // Per-party joint relinearization key contribution.
    auto* relin_contrib = crypto->add_subcommand("relin-contribute",
        "Generate this party's contribution to a joint relinearization key (one round at a time; offline; local files only)");
    relin_contrib->add_option("--round", relin_contribute_args.round,
                              "Sub-round number: 1 or 2")->required();
    relin_contrib->add_option("--role", relin_contribute_args.role,
                              "'lead' or 'main' (required for round 1; ignored for round 2)");
    relin_contrib->add_option("--secret-key", relin_contribute_args.secret_key_path,
                              "This party's FHE secret share")->required();
    relin_contrib->add_option("--peer-share", relin_contribute_args.peer_share_path,
                              "Peer's contribution (required for round 1 + role=main)");
    relin_contrib->add_option("--combined-r1", relin_contribute_args.combined_r1_path,
                              "Combined round-1 output (required for round 2)");
    relin_contrib->add_option("--joint-pk", relin_contribute_args.joint_pk_path,
                              "Joint public key (required for round 2)");
    relin_contrib->add_option("--output", relin_contribute_args.output_path,
                              "Where to write this party's contribution")->required();
    relin_contrib->add_option("--context-spec", relin_contribute_args.context_spec,
                              "Crypto context spec (default: bfv-default-v1)");
    relin_contrib->add_flag  ("--json", relin_contribute_args.emit_json, "Emit JSON output");
    relin_contrib->callback([&relin_contribute_args, exit_code]() {
        *exit_code = run_crypto_relin_contribute(relin_contribute_args);
    });

    // Deterministic combine for joint relinearization key.
    auto* relin_combine = crypto->add_subcommand("relin-combine",
        "Deterministically combine two parties' relinearization contributions for the given round (offline; local files only)");
    relin_combine->add_option("--round", relin_combine_args.round,
                              "Sub-round number: 1 (intermediate) or 2 (final)")->required();
    relin_combine->add_option("--share-a", relin_combine_args.share_a_path,
                              "Party A's contribution for this round")->required();
    relin_combine->add_option("--share-b", relin_combine_args.share_b_path,
                              "Party B's contribution for this round")->required();
    relin_combine->add_option("--joint-pk", relin_combine_args.joint_pk_path,
                              "Joint public key (required for round 1)");
    relin_combine->add_option("--combined-r1", relin_combine_args.combined_r1_path,
                              "Combined round-1 output (required for round 2)");
    relin_combine->add_option("--output", relin_combine_args.output_path,
                              "Where to write the combined result")->required();
    relin_combine->add_option("--context-spec", relin_combine_args.context_spec,
                              "Crypto context spec (default: bfv-default-v1)");
    relin_combine->add_flag  ("--json", relin_combine_args.emit_json, "Emit JSON output");
    relin_combine->callback([&relin_combine_args, exit_code]() {
        *exit_code = run_crypto_relin_combine(relin_combine_args);
    });

    // Per-party joint sum key contribution.
    auto* sum_contrib = crypto->add_subcommand("sum-contribute",
        "Generate this party's contribution to a joint sum key (offline; local files only)");
    sum_contrib->add_option("--role", sum_contribute_args.role,
                            "'lead' or 'main'")->required();
    sum_contrib->add_option("--secret-key", sum_contribute_args.secret_key_path,
                            "This party's FHE secret share")->required();
    sum_contrib->add_option("--peer-share", sum_contribute_args.peer_share_path,
                            "Lead's contribution (required for role=main)");
    sum_contrib->add_option("--joint-pk", sum_contribute_args.joint_pk_path,
                            "Joint public key (required for role=main)");
    sum_contrib->add_option("--output", sum_contribute_args.output_path,
                            "Where to write this party's contribution")->required();
    sum_contrib->add_option("--context-spec", sum_contribute_args.context_spec,
                            "Crypto context spec (default: bfv-default-v1)");
    sum_contrib->add_flag  ("--json", sum_contribute_args.emit_json, "Emit JSON output");
    sum_contrib->callback([&sum_contribute_args, exit_code]() {
        *exit_code = run_crypto_sum_contribute(sum_contribute_args);
    });

    // Deterministic combine for joint sum key.
    auto* sum_combine = crypto->add_subcommand("sum-combine",
        "Deterministically combine two parties' sum-key contributions to produce the final joint sum key (offline; local files only)");
    sum_combine->add_option("--share-a", sum_combine_args.share_a_path,
                            "Party A's contribution")->required();
    sum_combine->add_option("--share-b", sum_combine_args.share_b_path,
                            "Party B's contribution")->required();
    sum_combine->add_option("--joint-pk", sum_combine_args.joint_pk_path,
                            "Joint public key")->required();
    sum_combine->add_option("--output", sum_combine_args.output_path,
                            "Where to write the final sum key")->required();
    sum_combine->add_option("--context-spec", sum_combine_args.context_spec,
                            "Crypto context spec (default: bfv-default-v1)");
    sum_combine->add_flag  ("--json", sum_combine_args.emit_json, "Emit JSON output");
    sum_combine->callback([&sum_combine_args, exit_code]() {
        *exit_code = run_crypto_sum_combine(sum_combine_args);
    });

    // Per-party joint rotation key contribution. Mirrors sum-contribute but
    // requires --indices specifying which rotation indices to generate keys
    // for. Used by CKKS functions (and any other function whose function-def
    // requiredEvalKeys includes "rotation").
    auto* rot_contrib = crypto->add_subcommand("rotation-contribute",
        "Generate this party's contribution to a joint rotation key (offline; local files only)");
    rot_contrib->add_option("--role", rotation_contribute_args.role,
                            "'lead' or 'main'")->required();
    rot_contrib->add_option("--secret-key", rotation_contribute_args.secret_key_path,
                            "This party's FHE secret share")->required();
    rot_contrib->add_option("--peer-share", rotation_contribute_args.peer_share_path,
                            "Lead's contribution (required for role=main)");
    rot_contrib->add_option("--joint-pk", rotation_contribute_args.joint_pk_path,
                            "Joint public key (required for role=main)");
    rot_contrib->add_option("--indices", rotation_contribute_args.indices_csv,
                            "Comma-separated rotation indices, e.g. '1,2,4,-1,-2'")->required();
    rot_contrib->add_option("--output", rotation_contribute_args.output_path,
                            "Where to write this party's contribution")->required();
    rot_contrib->add_option("--context-spec", rotation_contribute_args.context_spec,
                            "Crypto context spec (default: bfv-default-v1)");
    rot_contrib->add_flag  ("--json", rotation_contribute_args.emit_json, "Emit JSON output");
    rot_contrib->callback([&rotation_contribute_args, exit_code]() {
        *exit_code = run_crypto_rotation_contribute(rotation_contribute_args);
    });

    // Deterministic combine for joint rotation key.
    auto* rot_combine = crypto->add_subcommand("rotation-combine",
        "Deterministically combine two parties' rotation-key contributions to produce the final joint rotation key (offline; local files only)");
    rot_combine->add_option("--share-a", rotation_combine_args.share_a_path,
                            "Party A's contribution")->required();
    rot_combine->add_option("--share-b", rotation_combine_args.share_b_path,
                            "Party B's contribution")->required();
    rot_combine->add_option("--joint-pk", rotation_combine_args.joint_pk_path,
                            "Joint public key")->required();
    rot_combine->add_option("--output", rotation_combine_args.output_path,
                            "Where to write the final rotation key")->required();
    rot_combine->add_option("--context-spec", rotation_combine_args.context_spec,
                            "Crypto context spec (default: bfv-default-v1)");
    rot_combine->add_flag  ("--json", rotation_combine_args.emit_json, "Emit JSON output");
    rot_combine->callback([&rotation_combine_args, exit_code]() {
        *exit_code = run_crypto_rotation_combine(rotation_combine_args);
    });

    // Wrap a contribution .bin in the platform's signed JSON envelope.
    // This is a separate step from producing the share so the crypto code
    // and the signing/serialization code stay decoupled. Same wrap-and-sign
    // step is used for pk-share, relin-roundN, sum-roundN, etc; the round
    // number and messageType come from the platform's per-project manifest.
    auto* wrap_env = crypto->add_subcommand("wrap-envelope",
        "Wrap a binary share into the signed JSON envelope the platform's keysetup endpoint expects");
    wrap_env->add_option("--payload", wrap_envelope_args.payload_path,
                         "Binary share file (inline mode). Either this or --object-key is required.");
    wrap_env->add_option("--object-key", wrap_envelope_args.object_key,
                         "GCS object key for out-of-band uploads (large-payload mode). "
                         "Requires --size-bytes; pairs with the platform's keysetup-messages/upload-url endpoint.");
    wrap_env->add_option("--size-bytes", wrap_envelope_args.size_bytes,
                         "Raw payload size in bytes (required with --object-key).");
    wrap_env->add_option("--secret-key", wrap_envelope_args.secret_key_path,
                         "Ed25519 signing secret key (32-byte seed; from signing-keygen)")
            ->required();
    wrap_env->add_option("--output", wrap_envelope_args.output_path,
                         "Where to write the signed .json upload body")->required();
    wrap_env->add_option("--permission-id", wrap_envelope_args.permission_id,
                         "Permission ID this share is for")->required();
    wrap_env->add_option("--round", wrap_envelope_args.round,
                         "Manifest round number (1, 2, 3, ...)")->required();
    wrap_env->add_option("--message-type", wrap_envelope_args.message_type,
                         "Message type (e.g. pk-share, relin-round1, sum-round1-continue)")
            ->required();
    wrap_env->add_option("--timestamp", wrap_envelope_args.timestamp,
                         "Override the ISO 8601 timestamp (default: now-UTC). "
                         "Mostly useful for reproducible tests.");
    wrap_env->add_flag  ("--json", wrap_envelope_args.emit_json, "Emit JSON output");
    wrap_env->callback([&wrap_envelope_args, exit_code]() {
        *exit_code = run_crypto_wrap_envelope(wrap_envelope_args);
    });

    // Sign the multi-party keysetup finalization envelope. Final keys are
    // already uploaded to GCS by the caller (web UI or customer script); the
    // app's job is purely to sign the (keyType, objectKey, sha256Hex) tuples
    // with the company's Ed25519 key. Output is the POST body for
    // /keysetup/final-keys.
    auto* wrap_fk = crypto->add_subcommand("wrap-final-keys-envelope",
        "Sign the multi-party keysetup finalization envelope (final-keys submission)");
    wrap_fk->add_option("--to-sign", wrap_final_keys_envelope_args.to_sign_path,
                        "Input to-sign JSON file (emitted by the web UI's finalization flow, "
                        "or hand-built by a customer script; contains keys[], "
                        "permissionId, timestamp)")
           ->required();
    wrap_fk->add_option("--secret-key", wrap_final_keys_envelope_args.secret_key_path,
                        "Ed25519 signing secret key (32-byte seed; from signing-keygen)")
           ->required();
    wrap_fk->add_option("--output", wrap_final_keys_envelope_args.output_path,
                        "Where to write the signed .json upload body (POST to /keysetup/final-keys)")
           ->required();
    wrap_fk->add_flag  ("--json", wrap_final_keys_envelope_args.emit_json, "Emit JSON output");
    wrap_fk->callback([&wrap_final_keys_envelope_args, exit_code]() {
        *exit_code = run_crypto_wrap_final_keys_envelope(wrap_final_keys_envelope_args);
    });

    auto* partial = crypto->add_subcommand("partial-decrypt",
        "Produce this party's partial decryption of a ciphertext");
    partial->add_option("--input",      partial_args.input_path,
                        "Ciphertext file to partially decrypt (binary)")->required();
    partial->add_option("--secret-key", partial_args.secret_key_path,
                        "This party's secret key share (binary)")->required();
    partial->add_option("--output",     partial_args.output_path,
                        "Output partial-decryption file (binary)")->required();
    partial->add_option("--context-spec", partial_args.context_spec,
                        "Crypto context spec (default: bfv-default-v1)");
    partial->add_flag  ("--lead",       partial_args.lead,
                        "This party is the lead in the threshold protocol (use exactly once across all parties)");
    partial->add_flag  ("--json",       partial_args.emit_json, "Emit JSON output");
    partial->callback([&partial_args, exit_code]() {
        *exit_code = run_crypto_partial_decrypt(partial_args);
    });

    auto* combine = crypto->add_subcommand("combine",
        "Combine all parties' partial decryptions to recover the plaintext locally");
    combine->add_option("--partials",   combine_args.partial_paths,
                        "Partial-decryption files (one per party), space- or comma-separated")
            ->required()->expected(-2);  // at least 2
    combine->add_option("--context-spec", combine_args.context_spec,
                        "Crypto context spec (default: bfv-default-v1)");
    combine->add_option("--show-slots", combine_args.show_slots,
                        "Number of leading slots to print (default: 16)");
    combine->add_flag  ("--non-zero",   combine_args.non_zero_only,
                        "Print only slot positions with non-zero values");
    combine->add_flag  ("--real",       combine_args.real_output,
                        "Emit raw real-valued slots without integer rounding "
                        "(CKKS only; for weight-vector style outputs)");
    combine->add_flag  ("--json",       combine_args.emit_json, "Emit JSON output");
    combine->add_option("--out-file",   combine_args.out_file_path,
                        "Write the plaintext result to this file; stdout returns references "
                        "only (blind: no values printed). For agent/MCP use.");
    combine->add_flag  ("--full-vector", combine_args.full_vector,
                        "Include every slot in --out-file. Off by default: a count result is "
                        "one number, and writing all 8,192 slots made a 240KB file nobody "
                        "could read.");
    combine->callback([&combine_args, exit_code]() {
        *exit_code = run_crypto_combine(combine_args);
    });

    // Map decrypted indicator-hash non-zero slot positions back to the
    // original CSV records that produced them. Used by 06-decrypt for
    // itemized-overlap-style functions: after threshold decrypt produces a
    // sparse indicator vector, this rehashes each line of the local CSV the
    // same way crypto encrypt did, and emits the records whose hash falls
    // into the non-zero slot set. Strictly local; no network, no crypto.
    auto* resolve = crypto->add_subcommand("resolve-indicator",
        "Resolve indicator-hash non-zero slot positions back to local CSV records (post-decrypt step for itemized overlap)");
    resolve->add_option("--slots", resolve_indicator_args.slots_csv,
                        "Comma-separated non-zero slot indices (e.g. '3215,7890,12044')")->required();
    resolve->add_option("--input", resolve_indicator_args.input_csv_path,
                        "Local CSV to resolve against (this party's plaintext records)")->required();
    resolve->add_option("--function-def", resolve_indicator_args.function_def_path,
                        "Function-definition JSON (provides schema + schemaParams)")->required();
    resolve->add_option("--input-name", resolve_indicator_args.input_name,
                        "Which input in the function-def this CSV is for (e.g. 'dataset_a')")->required();
    resolve->add_option("--context-spec", resolve_indicator_args.context_spec,
                        "Crypto context spec (default: bfv-default-v1)");
    resolve->add_flag  ("--json", resolve_indicator_args.emit_json, "Emit JSON output");
    resolve->callback([&resolve_indicator_args, exit_code]() {
        *exit_code = run_crypto_resolve_indicator(resolve_indicator_args);
    });

    // Re-derive the rotation index set from local plaintext files. Defensive
    // cross-check used by 04.5-rotation-keysetup.sh against the platform's
    // pendingRotationKeySetup.indices. Pure local: no FHE crypto, no network.
    auto* resolve_rules = crypto->add_subcommand("resolve-rules",
        "Map itemized cross-match result slots back to the rule rows that fired (positional, not hash-based; use resolve-indicator for overlap results)");
    resolve_rules->add_option("--slots", resolve_rules_args.slots_csv,
                              "Comma-separated slot indices from the decrypted result")->required();
    resolve_rules->add_option("--rule-pairs", resolve_rules_args.rule_pairs_path,
                              "The same rule list that was declared as the plaintext input")->required();
    resolve_rules->add_option("--output", resolve_rules_args.output_path,
                              "File to write the matched rules to")->required();
    resolve_rules->add_flag  ("--json", resolve_rules_args.emit_json, "Emit JSON output");
    resolve_rules->callback([&resolve_rules_args, exit_code]() {
        *exit_code = run_crypto_resolve_rules(resolve_rules_args);
    });

    auto* derive_rot = crypto->add_subcommand("derive-rotation-indices",
        "Re-derive the rotation index set from a local rule_pairs file using FNV1a-64 hash mod slot count (toolkit-side mirror of the platform's derivation)");
    derive_rot->add_option("--rule-pairs", derive_rotation_indices_args.rule_pairs_path,
                           "Rule-pairs CSV: each row 'left_name,right_name' (split on first comma)")->required();
    derive_rot->add_option("--context-spec", derive_rotation_indices_args.context_spec,
                           "Crypto context spec (e.g. 'ckks-default-v1'); used to look up slot count")->required();
    derive_rot->add_flag  ("--json", derive_rotation_indices_args.emit_json, "Emit JSON output");
    derive_rot->callback([&derive_rotation_indices_args, exit_code]() {
        *exit_code = run_crypto_derive_rotation_indices(derive_rotation_indices_args);
    });

    // Diagnostic: dump a ciphertext file's metadata + embedded crypto context
    // parameters. No validation against a local context; pure inspection.
    auto* inspect = crypto->add_subcommand("inspect",
        "Dump a ciphertext file's metadata and its EMBEDDED crypto context parameters (diagnostic for cross-component 'ValidateCiphertext' mismatches)");
    inspect->add_option("--input", inspect_args.input_path,
                        "Ciphertext file (binary)")->required();
    inspect->add_option("--context-spec", inspect_args.context_spec,
                        "Context spec for the deserialization shim (default: ckks-default-v1)");
    inspect->add_flag  ("--json", inspect_args.emit_json, "Emit JSON output (non-secret metadata only)");
    inspect->callback([&inspect_args, exit_code]() {
        *exit_code = run_crypto_inspect(inspect_args);
    });
}

}  // namespace julenny_fhe::cli
