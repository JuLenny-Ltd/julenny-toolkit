#include "pch.h"
#include "ToolkitClient.h"

#include "fhe_toolkit/fhe_toolkit.h"

#include "crypto/context.h"
#include "crypto/keys.h"
#include "crypto/ciphertext.h"
#include "crypto/eval_keys.h"
#include "crypto/signing.h"
#include "registry/envelope.h"
#include "registry/signature.h"
#include "registry/trust_root.h"
#include "psi/count.h"
#include "psi/encoder.h"
#include "psi/itemized_result.h"
#include "psi/size_class.h"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace JuLennyToolkit::Services
{
    namespace
    {
        using nlohmann::json;

        // ASCII string to wide-string for log pane output.
        std::wstring widen(std::string_view s)
        {
            std::wstring out;
            out.reserve(s.size());
            for (char c : s) out.push_back(static_cast<wchar_t>(c));
            return out;
        }

        void write_bytes(const std::filesystem::path& path, std::span<const std::byte> bytes)
        {
            std::ofstream out(path, std::ios::binary | std::ios::trunc);
            if (!out) throw std::runtime_error("cannot open for writing: " + path.string());
            out.write(reinterpret_cast<const char*>(bytes.data()),
                      static_cast<std::streamsize>(bytes.size()));
            if (!out) throw std::runtime_error("write failed: " + path.string());
        }

        std::vector<std::byte> read_bytes(const std::filesystem::path& path)
        {
            std::ifstream in(path, std::ios::binary | std::ios::ate);
            if (!in) throw std::runtime_error("cannot open for reading: " + path.string());
            auto size = static_cast<std::size_t>(in.tellg());
            in.seekg(0, std::ios::beg);
            std::vector<std::byte> bytes(size);
            if (size > 0)
            {
                in.read(reinterpret_cast<char*>(bytes.data()),
                        static_cast<std::streamsize>(size));
                if (!in) throw std::runtime_error("read failed: " + path.string());
            }
            return bytes;
        }

        // FNV-1a 64-bit hash. Same hash used by the Linux CLI so ciphertexts
        // are byte-compatible across the two apps for the same input.
        std::uint64_t fnv1a_64(std::string_view s) noexcept
        {
            constexpr std::uint64_t offset = 14695981039346656037ULL;
            constexpr std::uint64_t prime  = 1099511628211ULL;
            std::uint64_t h = offset;
            for (unsigned char c : s) { h ^= c; h *= prime; }
            return h;
        }

        std::string trim(std::string s)
        {
            auto not_space = [](unsigned char c) { return !std::isspace(c); };
            s.erase(s.begin(), std::find_if(s.begin(), s.end(), not_space));
            s.erase(std::find_if(s.rbegin(), s.rend(), not_space).base(), s.end());
            return s;
        }

        // Map the Mode-B "comma"/"tab"/"semicolon"/"pipe"/"none" UI labels
        // to a single-char delimiter ('\0' for "none").
        char separator_char_from_mode_b(const std::string& sep_name)
        {
            if (sep_name == "comma")     return ',';
            if (sep_name == "tab")       return '\t';
            if (sep_name == "semicolon") return ';';
            if (sep_name == "pipe")      return '|';
            return '\0';  // "none" or unknown
        }

        // Map a function-def schemaParams.separator value (a single-char
        // string like ",", "\t", ";", "|", or empty) to a delimiter.
        char separator_char_from_fn_def(const std::string& sep_str)
        {
            if (sep_str.empty()) return '\0';
            return sep_str[0];
        }

        std::vector<std::string> split(const std::string& s, char delim)
        {
            std::vector<std::string> out;
            std::string field;
            std::stringstream ss(s);
            while (std::getline(ss, field, delim)) out.push_back(field);
            return out;
        }

        std::vector<int> parse_columns(const std::string& spec)
        {
            std::vector<int> out;
            if (spec.empty() || spec == "all") return out;
            for (auto& part : split(spec, ',')) {
                auto t = trim(part);
                if (!t.empty()) {
                    try { out.push_back(std::stoi(t)); }
                    catch (...) { /* skip non-numeric */ }
                }
            }
            return out;
        }

        // Compose a record from a line for indicator-hash. ASCII Unit
        // Separator (\x1F) joins columns; matches the Linux CLI exactly.
        std::string compose_record(const std::string& line,
                                    char sep_char,
                                    const std::vector<int>& cols)
        {
            if (sep_char == '\0') return trim(line);
            auto fields = split(line, sep_char);
            std::string composed;
            if (cols.empty())
            {
                for (std::size_t i = 0; i < fields.size(); ++i)
                {
                    if (i > 0) composed.push_back('\x1F');
                    composed.append(trim(fields[i]));
                }
            }
            else
            {
                for (std::size_t i = 0; i < cols.size(); ++i)
                {
                    int col = cols[i] - 1;
                    if (col >= 0 && col < static_cast<int>(fields.size()))
                    {
                        if (i > 0) composed.push_back('\x1F');
                        composed.append(trim(fields[col]));
                    }
                }
            }
            return composed;
        }

        // Resolved per-input encoding parameters. Populated from either the
        // function-def file (Mode A) or the explicit Mode-B fields.
        struct ResolvedEncoding
        {
            std::string context_spec_id = "bfv-default-v1";
            std::string schema;        // e.g. "indicator-hash"
            char separator = '\0';
            bool skip_header = false;
            std::vector<int> cols;
            // Provenance for the result summary; only populated in Mode A.
            std::string fn_slug;
            std::string fn_version;
            std::string fn_role;
        };

        // Large-dataset input (Joint Record Overlap for Large Datasets). The whole encode is
        // psi/encoder in core, the code the CLI runs, so the app writes the same files and
        // tells the platform the same thing: the platform report, never a record count.
        OperationResult encrypt_signature_table(const EncryptOptions& opts, const ResolvedEncoding& enc,
                                                const fhe_toolkit::crypto::CryptoContextSpec& spec,
                                                std::int64_t slot_count, const std::string& role,
                                                const std::string& domain)
        {
            namespace psi = fhe_toolkit::psi;
            OperationResult result;
            if (opts.psi_size_class.empty())
            {
                result.error = L"Choose the dataset size shown on the permission.";
                return result;
            }
            if (role.empty())
            {
                result.error = L"Input '" + widen(opts.input_name) + L"' cannot be encrypted for a dataset size.";
                return result;
            }

            psi::EncodeRequest req;
            req.input            = opts.input_path;
            req.joint_public_key = opts.joint_public_key_path;
            req.output           = opts.output_path;
            req.spec             = spec;
            req.slot_count       = static_cast<std::uint64_t>(slot_count);
            req.separator        = enc.separator;
            req.columns          = enc.cols;
            req.skip_header      = enc.skip_header;
            req.role             = role;
            req.domain           = domain.empty() ? std::string{ "julenny-psi-v1" } : domain;
            req.size_class       = opts.psi_size_class;
            req.function_slug    = enc.fn_slug;
            req.function_version = enc.fn_version;
            req.input_name       = opts.input_name;

            const psi::EncodeResult r = psi::encode_signature_table(req);

            // Plain words only: customers never see table settings. Too many records keeps the
            // encoder's own message; every other refusal means this file cannot be encrypted for
            // this size.
            if (r.status != psi::EncodeStatus::encoded)
            {
                result.error = r.status == psi::EncodeStatus::too_many_records
                    ? widen(r.reason)
                    : std::wstring{ L"This file could not be encrypted for this dataset size. Ask your partner "
                                    L"for a permission with a larger size." };
                return result;
            }

            std::wostringstream out;
            out << L"Encrypted " << r.totals.records << L" records for a dataset size of up to "
                << widen(opts.psi_size_class) << L" records";
            if (r.totals.duplicates > 0) out << L" (" << r.totals.duplicates << L" repeated rows counted once)";
            out << L".\n\n";
            out << L"Upload these with the dataset:\n";
            for (const auto& f : r.files) out << L"  " << f.wstring() << L"\n";
            if (r.shard_count > 1) out << L"  " << r.manifest_path.wstring() << L"\n";
            out << L"  " << r.platform_report_path.wstring() << L"\n";
            result.summary = out.str();
            result.success = true;
            return result;
        }
    }

    struct ToolkitClient::Impl
    {
        // Reserved for future per-instance state. Intentionally empty:
        // this client is strictly offline and stateless across operations.
    };

    ToolkitClient::ToolkitClient()
        : m_impl(std::make_unique<Impl>())
    {
    }

    ToolkitClient::~ToolkitClient() = default;

    std::wstring ToolkitClient::GetLocalStatus()
    {
        std::wostringstream out;
        out << L"Toolkit core: v" << widen(fhe_toolkit_version()) << L"\n";
        out << L"Mode:         offline (this app never contacts the platform)\n";
        out << L"Operations:   local key generation, joint key setup (public, multiplication, "
               L"sum and rotation keys), encryption (including large datasets), partial "
               L"decryption, combining results, signing.";
        return out.str();
    }

    OperationResult ToolkitClient::GenerateKeypair(const GenerateKeypairOptions& options)
    {
        OperationResult result;
        try
        {
            if (options.output_secret_path.empty() || options.output_public_path.empty())
            {
                result.error = L"output-secret and output-public paths are required";
                return result;
            }

            auto spec = fhe_toolkit::crypto::get_crypto_context_spec(options.context_spec);
            if (!spec)
            {
                result.error = L"unknown context spec: " + widen(options.context_spec);
                return result;
            }

            fhe_toolkit::crypto::Context ctx(*spec);
            auto kp = ctx.generate_keypair();

            auto pk_bytes = kp.public_key.serialize();
            auto sk_bytes = kp.secret_key.serialize();

            if (options.output_secret_path.has_parent_path())
                std::filesystem::create_directories(options.output_secret_path.parent_path());
            if (options.output_public_path.has_parent_path())
                std::filesystem::create_directories(options.output_public_path.parent_path());

            write_bytes(options.output_secret_path, sk_bytes);
            write_bytes(options.output_public_path, pk_bytes);

            try
            {
                std::filesystem::permissions(
                    options.output_secret_path,
                    std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
                    std::filesystem::perm_options::replace);
            }
            catch (...) { /* best-effort */ }

            std::wostringstream out;
            out << L"FHE keypair generated.\n\n";
            out << L"  Secret key: " << options.output_secret_path.wstring() << L"\n";
            out << L"              (" << sk_bytes.size() << L" bytes, owner-only, stays on this machine)\n";
            out << L"  Public key: " << options.output_public_path.wstring() << L"\n";
            out << L"              (" << pk_bytes.size() << L" bytes)\n\n";
            out << L"This keypair is scenario-agnostic. The public key can be used for:\n"
                << L"  - single-party encryption (encrypt your own data, decrypt it later yourself);\n"
                << L"  - registering as your company's FHE identity with the platform;\n"
                << L"  - starting a joint keysetup as the first party (a peer will chain on it "
                << L"    using the 'Keysetup share' screen to produce the joint public key).\n\n"
                << L"The secret key must NEVER be uploaded. Keep it on this machine.";
            result.summary = out.str();
            result.success = true;
        }
        catch (const std::exception& e)
        {
            result.error = widen(e.what());
        }
        catch (...)
        {
            result.error = L"unknown error during keypair generation";
        }
        return result;
    }

    OperationResult ToolkitClient::KeysetupChain(const KeysetupChainOptions& options)
    {
        OperationResult result;
        try
        {
            if (options.peer_share_path.empty() || options.output_secret_path.empty() ||
                options.output_public_path.empty())
            {
                result.error = L"peer-share, output-secret, and output-public paths are all required";
                return result;
            }

            auto spec = fhe_toolkit::crypto::get_crypto_context_spec(options.context_spec);
            if (!spec)
            {
                result.error = L"unknown context spec: " + widen(options.context_spec);
                return result;
            }

            fhe_toolkit::crypto::Context ctx(*spec);
            auto peer_bytes = read_bytes(options.peer_share_path);
            auto peer_pk = fhe_toolkit::crypto::PublicKey::deserialize(ctx, peer_bytes);
            auto kp = ctx.multiparty_keygen(peer_pk);

            auto pk_bytes = kp.public_key.serialize();
            auto sk_bytes = kp.secret_key.serialize();

            if (options.output_secret_path.has_parent_path())
                std::filesystem::create_directories(options.output_secret_path.parent_path());
            if (options.output_public_path.has_parent_path())
                std::filesystem::create_directories(options.output_public_path.parent_path());

            write_bytes(options.output_secret_path, sk_bytes);
            write_bytes(options.output_public_path, pk_bytes);

            try
            {
                std::filesystem::permissions(
                    options.output_secret_path,
                    std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
                    std::filesystem::perm_options::replace);
            }
            catch (...) { /* best-effort */ }

            std::wostringstream out;
            out << L"Joined the keysetup; joint public key derived.\n\n";
            out << L"  Peer's public key: " << options.peer_share_path.wstring() << L"\n";
            out << L"  My secret share:   " << options.output_secret_path.wstring() << L"\n";
            out << L"                     (" << sk_bytes.size()
                << L" bytes, owner-only, stays on this machine)\n";
            out << L"  Joint public key:  " << options.output_public_path.wstring() << L"\n";
            out << L"                     (" << pk_bytes.size() << L" bytes)\n\n";
            out << L"Upload the joint public key file to the platform. Both parties will use "
                << L"it to encrypt data for this collaboration. The secret share stays on "
                << L"this machine and is required later to partial-decrypt results.";
            result.summary = out.str();
            result.success = true;
        }
        catch (const std::exception& e)
        {
            result.error = widen(e.what());
        }
        catch (...)
        {
            result.error = L"unknown error during keysetup chain";
        }
        return result;
    }

    bool ToolkitClient::IsLargeItemizedPartial(const std::filesystem::path& path)
    {
        std::ifstream in(path, std::ios::binary);
        if (!in) return false;
        std::vector<char> head(64, '\0');
        in.read(head.data(), static_cast<std::streamsize>(head.size()));
        const auto got = static_cast<std::size_t>(in.gcount());
        std::vector<std::byte> bytes(got);
        std::memcpy(bytes.data(), head.data(), got);
        return fhe_toolkit::psi::itemized_kind(bytes) == fhe_toolkit::psi::ItemizedKind::partial;
    }

    OperationResult ToolkitClient::ResolveLargeItemized(const ItemizedResolveOptions& opts)
    {
        namespace psi = fhe_toolkit::psi;
        OperationResult result;
        try
        {
            if (opts.partial_paths.size() < 2)
            {
                result.error = L"Pick both partial files: yours and your partner's.";
                return result;
            }
            auto spec = fhe_toolkit::crypto::get_crypto_context_spec(opts.context_spec);
            if (!spec)
            {
                result.error = L"unknown context spec: " + widen(opts.context_spec);
                return result;
            }
            fhe_toolkit::crypto::Context ctx(*spec);
            std::vector<std::vector<std::byte>> files;
            for (const auto& p : opts.partial_paths) files.push_back(read_bytes(p));
            const auto masks = psi::combine_itemized(ctx, spec->plaintext_modulus, files);

            // The definition says how the rows were read; it must be the signed one, as when encrypting.
            json fn_def;
            {
                std::ifstream fn_in(opts.function_def_path);
                if (!fn_in)
                {
                    result.error = L"cannot open function-def file: " + opts.function_def_path.wstring();
                    return result;
                }
                fn_in >> fn_def;
            }
            if (!fhe_toolkit::registry::verify_function_definition_signature(
                    fn_def, fhe_toolkit::registry::registry_public_key()))
            {
                result.error = L"The function definition's signature check FAILED. Download it again from the platform.";
                return result;
            }
            // The result is laid out for the viewer's input: A is the first input, B the second.
            const std::size_t index = masks.header.viewer == 'A' ? 0 : 1;
            if (!fn_def.contains("inputs") || !fn_def["inputs"].is_array() || fn_def["inputs"].size() <= index)
            {
                result.error = L"This function definition does not match the result.";
                return result;
            }
            const json& input_def = fn_def["inputs"][index];
            if (input_def.value("schema", std::string{}) != "signature-table")
            {
                result.error = L"This function definition is not for a large-dataset function.";
                return result;
            }
            const json params = input_def.value("schemaParams", json::object());

            psi::EncodeRequest req;
            req.input       = opts.csv_path;
            req.separator   = separator_char_from_fn_def(params.value("separator", std::string{}));
            req.skip_header = params.value("skipHeader", false);
            req.columns     = parse_columns(opts.record_columns.empty()
                                                ? params.value("columns", std::string{"all"})
                                                : opts.record_columns);
            req.domain      = params.value("domainSeparator", std::string{"julenny-psi-v1"});
            if (req.domain.empty()) req.domain = "julenny-psi-v1";
            req.role        = std::string(1, masks.header.viewer);
            req.size_class  = opts.size_class;

            const auto rows = psi::resolve_itemized_rows(req, masks);
            std::string body;
            if (!rows.header_line.empty()) body += rows.header_line + "\n";
            for (const auto& r : rows.rows) body += r + "\n";
            {
                std::ofstream out(opts.output_path, std::ios::binary | std::ios::trunc);
                if (!out)
                {
                    result.error = L"cannot write " + opts.output_path.wstring();
                    return result;
                }
                out << body;
            }

            // The file is written even with no matches (header line kept), so automation always finds one.
            std::wostringstream summary;
            if (rows.rows.empty())
                summary << L"None of the rows of your data overlap with your partner's data. A file with no matching rows was saved in:\n";
            else if (rows.rows.size() == 1)
                summary << L"1 row of your data overlaps with your partner's data. It is saved in:\n";
            else
                summary << rows.rows.size() << L" rows of your data overlap with your partner's data. They are saved in:\n";
            summary << opts.output_path.wstring();
            result.summary = summary.str();
            result.success = true;
        }
        catch (const std::exception& e)
        {
            result.error = widen(e.what());
        }
        return result;
    }

    std::vector<std::string> ToolkitClient::PsiSizeClasses()
    {
        std::vector<std::string> ids;
        for (const auto& c : fhe_toolkit::psi::size_classes()) ids.emplace_back(c.id);
        return ids;
    }

    OperationResult ToolkitClient::Encrypt(const EncryptOptions& opts)
    {
        OperationResult result;
        try
        {
            if (opts.input_path.empty() || opts.joint_public_key_path.empty() || opts.output_path.empty())
            {
                result.error = L"input, joint-public-key, and output paths are all required";
                return result;
            }

            const bool has_fn_def = !opts.function_def_path.empty();
            const bool has_schema = !opts.schema.empty();
            if (has_fn_def == has_schema)
            {
                result.error = L"exactly one of function-def or schema must be set";
                return result;
            }

            ResolvedEncoding enc;
            // signature-table only: the first input is role A and the second role B, so the two
            // parties cannot both encode as A without disagreeing about the definition itself.
            std::string psi_role;
            std::string psi_domain;
            std::string psi_def_spec;  // the definition's own context, whatever the top bar says

            if (has_fn_def)
            {
                if (opts.input_name.empty())
                {
                    result.error = L"input-name is required when function-def is set";
                    return result;
                }
                json fn_def;
                try
                {
                    std::ifstream fn_in(opts.function_def_path);
                    if (!fn_in)
                    {
                        result.error = L"cannot open function-def file: " + opts.function_def_path.wstring();
                        return result;
                    }
                    fn_in >> fn_def;
                }
                catch (const std::exception& e)
                {
                    result.error = L"failed to parse function-def JSON: " + widen(e.what());
                    return result;
                }

                // Fail-closed, as the CLI: both parties must compute the SAME signed definition, so an
                // unsigned or altered file is refused before anything is encrypted against it. The
                // registry key is compiled into the app, never fetched from the server being checked.
                if (!fhe_toolkit::registry::verify_function_definition_signature(
                        fn_def, fhe_toolkit::registry::registry_public_key()))
                {
                    result.error = L"The function definition's signature check FAILED, so nothing was encrypted.\n"
                                   L"File: " + opts.function_def_path.wstring() + L"\n"
                                   L"The file is unsigned or has been altered. Download it again from the platform.";
                    return result;
                }

                json input_def;
                std::size_t input_index = 0;
                if (fn_def.contains("inputs") && fn_def["inputs"].is_array())
                {
                    std::size_t idx = 0;
                    for (const auto& in : fn_def["inputs"])
                    {
                        if (in.value("name", std::string{}) == opts.input_name)
                        {
                            input_def = in;
                            input_index = idx;
                            break;
                        }
                        ++idx;
                    }
                }
                if (input_def.is_null())
                {
                    result.error = L"function-def has no input named '" + widen(opts.input_name) + L"'";
                    return result;
                }

                enc.fn_slug    = fn_def.value("slug", std::string{});
                enc.fn_version = fn_def.value("version", std::string{});
                enc.fn_role    = input_def.value("role", std::string{});
                enc.context_spec_id = opts.context_spec.empty()
                    ? fn_def.value("cryptoContextSpec", std::string{"bfv-default-v1"})
                    : opts.context_spec;
                enc.schema = input_def.value("schema", std::string{});

                json params = input_def.value("schemaParams", json::object());
                enc.separator   = separator_char_from_fn_def(params.value("separator", std::string{}));
                enc.skip_header = params.value("skipHeader", false);
                // The operator's column choice overrides the definition's default, as the CLI's
                // --columns does. Checked here: parse_columns skips what it cannot read, which
                // would quietly match on fewer fields than the operator asked for.
                if (!opts.record_columns.empty() && opts.record_columns != "all")
                {
                    bool ok = true;
                    bool digit_seen = false;
                    for (char ch : opts.record_columns)
                    {
                        if (ch >= '0' && ch <= '9') digit_seen = true;
                        else if (ch == ',' && digit_seen) digit_seen = false;
                        else { ok = false; break; }
                    }
                    if (!ok || !digit_seen)
                    {
                        result.error = L"Columns must be empty (all columns), one column number such as 1, "
                                       L"or several such as 1,3. Got '" + widen(opts.record_columns) + L"'.";
                        return result;
                    }
                    for (int col : parse_columns(opts.record_columns))
                    {
                        if (col < 1)
                        {
                            result.error = L"Column numbers start at 1.";
                            return result;
                        }
                    }
                }
                enc.cols        = parse_columns(opts.record_columns.empty()
                                                    ? params.value("columns", std::string{"all"})
                                                    : opts.record_columns);
                if (input_index < 2) psi_role = input_index == 0 ? "A" : "B";
                psi_domain = params.value("domainSeparator", std::string{});
                psi_def_spec = fn_def.value("cryptoContextSpec", std::string{});
            }
            else
            {
                // Mode B: explicit-flag.
                enc.context_spec_id = opts.context_spec.empty() ? std::string{"bfv-default-v1"} : opts.context_spec;
                enc.schema      = opts.schema;
                enc.separator   = separator_char_from_mode_b(opts.separator);
                enc.skip_header = opts.skip_header;
                enc.cols        = parse_columns(opts.columns);
            }

            auto spec = fhe_toolkit::crypto::get_crypto_context_spec(enc.context_spec_id);
            if (!spec)
            {
                result.error = L"unknown context spec: " + widen(enc.context_spec_id);
                return result;
            }

            // Slot count per context spec (BFV: ringDim; CKKS: ringDim/2).
            // Mirrors the CLI's resolve_slot_count. This MUST match the
            // platform's FNV-mod-slotCount derivation; the old hardcoded
            // 16384 put CKKS indicators in the wrong slots entirely.
            std::int64_t slot_count = 0;
            if      (enc.context_spec_id == "bfv-default-v1")  slot_count = 16384;
            else if (enc.context_spec_id == "ckks-default-v1") slot_count = 8192;
            else if (enc.context_spec_id == "ckks-tree-v1")    slot_count = 32768;
            else if (enc.context_spec_id == "bfv-large-psi-v1") slot_count = 32768;
            else
            {
                result.error = L"no slot count known for context spec '"
                             + widen(enc.context_spec_id) + L"'";
                return result;
            }

            if (enc.schema == "signature-table")
            {
                if (!has_fn_def)
                {
                    result.error = L"Large-dataset inputs are encoded from the function definition file.";
                    return result;
                }
                // Another BFV context passes every check the encoder can make and writes a file the
                // platform cannot load, so the context must be the definition's.
                if (!psi_def_spec.empty() && psi_def_spec != enc.context_spec_id)
                {
                    result.error = L"This function uses the context '" + widen(psi_def_spec) + L"', but '"
                                 + widen(enc.context_spec_id) + L"' is selected at the top. Select '"
                                 + widen(psi_def_spec) + L"' there. Keys made under another context will "
                                   L"not work with this function either.";
                    return result;
                }
                return encrypt_signature_table(opts, enc, *spec, slot_count, psi_role, psi_domain);
            }

            // Dispatch on schema (parity with the CLI's crypto encrypt).
            const bool is_weight_vector    = (enc.schema == "weight-vector");
            const bool is_binary_indicator = (enc.schema == "binary-indicator");
            if (enc.schema != "indicator-hash" && !is_weight_vector && !is_binary_indicator)
            {
                result.error = L"unsupported schema '" + widen(enc.schema)
                             + L"' (supported: 'indicator-hash', 'weight-vector', 'binary-indicator')";
                return result;
            }
            if (is_weight_vector && spec->scheme != "CKKS")
            {
                result.error = L"schema 'weight-vector' requires a CKKS context spec; got '"
                             + widen(enc.context_spec_id) + L"'";
                return result;
            }

            std::vector<std::int64_t> slots;   // indicator-hash / binary-indicator
            std::vector<double> weights;       // weight-vector
            std::size_t records_read = 0;
            std::size_t lines_seen = 0;
            std::size_t lines_skipped = 0;
            std::size_t collisions = 0;
            std::size_t unique_slots = 0;

            std::ifstream in(opts.input_path);
            if (!in)
            {
                result.error = L"cannot open input file: " + opts.input_path.wstring();
                return result;
            }

            std::string line;
            if (is_weight_vector)
            {
                // One finite real value per line, encoded in file order.
                while (std::getline(in, line))
                {
                    ++lines_seen;
                    auto trimmed = trim(line);
                    if (trimmed.empty() || trimmed[0] == '#') { ++lines_skipped; continue; }
                    double v = 0.0;
                    std::size_t pos = 0;
                    try { v = std::stod(trimmed, &pos); }
                    catch (const std::exception&) { pos = std::string::npos; }
                    if (pos != trimmed.size() || !std::isfinite(v))
                    {
                        result.error = L"line " + std::to_wstring(lines_seen)
                                     + L" is not a number (weight-vector inputs are one real value per line)";
                        return result;
                    }
                    weights.push_back(v);
                    ++records_read;
                }
                if (static_cast<std::int64_t>(weights.size()) > slot_count)
                {
                    result.error = L"input has more weights than the context has slots";
                    return result;
                }
            }
            else if (is_binary_indicator)
            {
                // One 0/1 per line; slot index = line POSITION in the agreed
                // grid (comments/blank lines do not advance the position).
                slots.assign(static_cast<std::size_t>(slot_count), 0);
                std::size_t grid_pos = 0;
                while (std::getline(in, line))
                {
                    ++lines_seen;
                    auto trimmed = trim(line);
                    if (trimmed.empty() || trimmed[0] == '#') { ++lines_skipped; continue; }
                    if (trimmed != "0" && trimmed != "1")
                    {
                        result.error = L"line " + std::to_wstring(lines_seen)
                                     + L" must be 0 or 1 (binary-indicator inputs are one 0/1 per grid position)";
                        return result;
                    }
                    if (static_cast<std::int64_t>(grid_pos) >= slot_count)
                    {
                        result.error = L"input has more grid positions than the context has slots";
                        return result;
                    }
                    if (trimmed == "1") { slots[grid_pos] = 1; ++unique_slots; }
                    ++grid_pos;
                    ++records_read;
                }
            }
            else
            {
                slots.assign(static_cast<std::size_t>(slot_count), 0);
                bool header_consumed = false;
                while (std::getline(in, line))
                {
                    ++lines_seen;
                    auto trimmed = trim(line);
                    if (trimmed.empty() || trimmed[0] == '#') { ++lines_skipped; continue; }
                    if (enc.skip_header && !header_consumed)
                    {
                        header_consumed = true;
                        ++lines_skipped;
                        continue;
                    }
                    auto composed = compose_record(trimmed, enc.separator, enc.cols);
                    if (composed.empty()) { ++lines_skipped; continue; }
                    auto slot = static_cast<std::size_t>(
                        fnv1a_64(composed) % static_cast<std::uint64_t>(slot_count));
                    if (slots[slot] != 0) ++collisions; else ++unique_slots;
                    slots[slot] += 1;
                    ++records_read;
                }
            }

            if (records_read == 0)
            {
                result.error = L"no records found in input file";
                return result;
            }

            auto pk_bytes = read_bytes(opts.joint_public_key_path);
            fhe_toolkit::crypto::Context ctx(*spec);
            auto pk = fhe_toolkit::crypto::PublicKey::deserialize(ctx, pk_bytes);
            // Encode under the scheme: CKKS takes doubles (real-cast for the
            // indicator schemas), BFV takes int64. Same dispatch as the CLI.
            fhe_toolkit::crypto::PlaintextPacked pt;
            if (is_weight_vector)
            {
                pt = ctx.encode_ckks_packed(weights);
            }
            else if (spec->scheme == "CKKS")
            {
                std::vector<double> real_vals;
                real_vals.reserve(slots.size());
                for (std::int64_t s : slots) real_vals.push_back(static_cast<double>(s));
                pt = ctx.encode_ckks_packed(real_vals);
            }
            else
            {
                pt = ctx.encode_packed(slots);
            }
            auto ct = ctx.encrypt(pk, pt);
            auto ct_bytes = ct.serialize();

            if (opts.output_path.has_parent_path())
                std::filesystem::create_directories(opts.output_path.parent_path());
            write_bytes(opts.output_path, ct_bytes);

            std::wostringstream out;
            out << L"Encrypted " << records_read << L" records.\n\n";
            if (has_fn_def)
            {
                out << L"  Function:      " << widen(enc.fn_slug.empty() ? std::string{"?"} : enc.fn_slug)
                    << L" v" << widen(enc.fn_version.empty() ? std::string{"?"} : enc.fn_version) << L"\n";
                out << L"  Input role:    " << widen(opts.input_name)
                    << L" (" << widen(enc.fn_role.empty() ? std::string{"?"} : enc.fn_role) << L")\n";
            }
            else
            {
                out << L"  Mode:          explicit-flag (no function-def)\n";
            }
            out << L"  Schema:        " << widen(enc.schema) << L"\n";
            if (!is_weight_vector)
            {
                out << L"  Unique slots:  " << unique_slots << L"\n";
                out << L"  Collisions:    " << collisions << L" (records hashing to a slot already in use)\n";
            }
            out << L"  Skipped lines: " << lines_skipped << L" (blank, comment, or header)\n";
            out << L"  Output:        " << opts.output_path.wstring() << L"\n";
            out << L"                 (" << ct_bytes.size() << L" bytes)\n\n";
            out << L"Next: upload this file to the platform as a dataset.";
            result.summary = out.str();
            result.success = true;
        }
        catch (const std::exception& e)
        {
            result.error = widen(e.what());
        }
        catch (...)
        {
            result.error = L"unknown error during encryption";
        }
        return result;
    }

    OperationResult ToolkitClient::PartialDecrypt(const PartialDecryptOptions& options)
    {
        OperationResult result;
        try
        {
            if (options.ciphertext_path.empty() || options.secret_key_path.empty() || options.output_path.empty())
            {
                result.error = L"ciphertext, secret-key, and output paths are all required";
                return result;
            }

            auto spec = fhe_toolkit::crypto::get_crypto_context_spec(options.context_spec);
            if (!spec)
            {
                result.error = L"unknown context spec: " + widen(options.context_spec);
                return result;
            }

            fhe_toolkit::crypto::Context ctx(*spec);

            auto ct_bytes = read_bytes(options.ciphertext_path);
            auto sk_bytes = read_bytes(options.secret_key_path);
            auto ct = fhe_toolkit::crypto::Ciphertext::deserialize(ctx, ct_bytes);
            auto sk = fhe_toolkit::crypto::SecretKey::deserialize(ctx, sk_bytes);

            auto partial = options.is_lead
                ? ctx.partial_decrypt_lead(sk, ct)
                : ctx.partial_decrypt_main(sk, ct);
            auto partial_bytes = partial.serialize();

            if (options.output_path.has_parent_path())
                std::filesystem::create_directories(options.output_path.parent_path());
            write_bytes(options.output_path, partial_bytes);

            std::wostringstream out;
            out << L"Partial decryption produced (role: "
                << (options.is_lead ? L"lead" : L"main") << L").\n\n";
            out << L"  Output: " << options.output_path.wstring() << L"\n";
            out << L"          (" << partial_bytes.size() << L" bytes)\n\n";
            out << L"Upload this partial-decryption file to the platform via the web UI's "
                << L"release-result page (data owner) or hand it to the recipient party "
                << L"(if you are doing an offline combine).";
            result.summary = out.str();
            result.success = true;
        }
        catch (const std::exception& e)
        {
            result.error = widen(e.what());
        }
        catch (...)
        {
            result.error = L"unknown error during partial decryption";
        }
        return result;
    }

    OperationResult ToolkitClient::SigningKeygen(const SigningKeygenOptions& options)
    {
        OperationResult result;
        try
        {
            if (options.output_secret_path.empty() || options.output_public_path.empty())
            {
                result.error = L"output-secret and output-public paths are required";
                return result;
            }

            auto kp = fhe_toolkit::signing::generate_keypair();

            if (options.output_secret_path.has_parent_path())
                std::filesystem::create_directories(options.output_secret_path.parent_path());
            if (options.output_public_path.has_parent_path())
                std::filesystem::create_directories(options.output_public_path.parent_path());

            write_bytes(options.output_secret_path,
                        std::span<const std::byte>(kp.secret_key.bytes.data(), kp.secret_key.bytes.size()));
            write_bytes(options.output_public_path,
                        std::span<const std::byte>(kp.public_key.bytes.data(), kp.public_key.bytes.size()));

            try
            {
                std::filesystem::permissions(
                    options.output_secret_path,
                    std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
                    std::filesystem::perm_options::replace);
            }
            catch (...) { /* best-effort */ }

            std::wostringstream out;
            out << L"Ed25519 signing keypair generated.\n\n";
            out << L"  Secret key:  " << options.output_secret_path.wstring() << L"\n";
            out << L"               (32 bytes, owner-only, stays on this machine)\n";
            out << L"  Public key:  " << options.output_public_path.wstring() << L"\n";
            out << L"               (32 bytes)\n\n";
            out << L"Upload the PUBLIC key to the platform via the company settings page "
                   L"(Settings > Signing key). The secret stays here and is used to sign "
                   L"contributions you upload, so the platform can verify they came from you.";
            result.summary = out.str();
            result.success = true;
        }
        catch (const std::exception& e) { result.error = widen(e.what()); }
        catch (...) { result.error = L"unknown error during signing keygen"; }
        return result;
    }

    OperationResult ToolkitClient::Sign(const SignOptions& options)
    {
        OperationResult result;
        try
        {
            if (options.input_path.empty() || options.secret_key_path.empty() || options.output_path.empty())
            {
                result.error = L"input, secret-key, and output paths are all required";
                return result;
            }

            auto sk_bytes = read_bytes(options.secret_key_path);
            auto sk = fhe_toolkit::signing::load_secret_key(sk_bytes);
            auto message = read_bytes(options.input_path);
            auto sig = fhe_toolkit::signing::sign(sk, message);

            if (options.output_path.has_parent_path())
                std::filesystem::create_directories(options.output_path.parent_path());
            write_bytes(options.output_path,
                        std::span<const std::byte>(sig.bytes.data(), sig.bytes.size()));

            std::wostringstream out;
            out << L"Signed " << message.size() << L" bytes of " << options.input_path.wstring() << L".\n\n";
            out << L"  Signature: " << options.output_path.wstring() << L"\n";
            out << L"             (64 bytes)";
            result.summary = out.str();
            result.success = true;
        }
        catch (const std::exception& e) { result.error = widen(e.what()); }
        catch (...) { result.error = L"unknown error during sign"; }
        return result;
    }

    OperationResult ToolkitClient::WrapEnvelope(const WrapEnvelopeOptions& options)
    {
        OperationResult result;
        try
        {
            if (options.payload_path.empty() || options.secret_key_path.empty() ||
                options.output_path.empty())
            {
                result.error = L"payload, secret-key, and output paths are all required";
                return result;
            }
            if (options.permission_id.empty())
            {
                result.error = L"permission-id is required";
                return result;
            }
            if (options.round < 1)
            {
                result.error = L"round must be >= 1 (manifest round number)";
                return result;
            }
            if (options.message_type.empty())
            {
                result.error = L"message-type is required "
                               L"(e.g. pk-share, relin-round1, sum-round1-continue)";
                return result;
            }

            auto payload  = read_bytes(options.payload_path);
            auto sk_bytes = read_bytes(options.secret_key_path);
            auto sk = fhe_toolkit::signing::load_secret_key(sk_bytes);

            fhe_toolkit::registry::EnvelopeFields fields;
            fields.permission_id   = options.permission_id;
            fields.round           = options.round;
            fields.message_type    = options.message_type;
            fields.timestamp       = fhe_toolkit::registry::iso8601_now_utc();

            const std::string body = fhe_toolkit::registry::make_signed_envelope(
                std::span<const std::byte>(payload.data(), payload.size()),
                fields, sk);

            if (options.output_path.has_parent_path())
                std::filesystem::create_directories(options.output_path.parent_path());

            {
                std::ofstream out(options.output_path, std::ios::trunc);
                if (!out) throw std::runtime_error("cannot open for writing: " + options.output_path.string());
                out << body;
                if (!out) throw std::runtime_error("write failed: " + options.output_path.string());
            }

            std::wostringstream out;
            out << L"Signed envelope written.\n\n";
            out << L"  Output:        " << options.output_path.wstring()
                << L" (" << body.size() << L" bytes)\n";
            out << L"  Round:         " << options.round << L"\n";
            out << L"  Message type:  " << widen(options.message_type) << L"\n";
            out << L"  Payload bytes: " << payload.size() << L"\n";
            out << L"  Timestamp:     " << widen(fields.timestamp) << L"\n\n";
            out << L"Upload this .json file via the keysetup page on the platform. "
                   L"The file IS the HTTP request body; the platform reconstructs "
                   L"the signed payload from auth + URL and verifies against your "
                   L"registered signing public key.\n\n"
                   L"The original .bin stays on this machine for use as input to "
                   L"any subsequent rounds.";
            result.summary = out.str();
            result.success = true;
        }
        catch (const std::exception& e) { result.error = widen(e.what()); }
        catch (...) { result.error = L"unknown error during wrap-envelope"; }
        return result;
    }

    OperationResult ToolkitClient::WrapFinalKeysEnvelope(const WrapFinalKeysEnvelopeOptions& options)
    {
        OperationResult result;
        try
        {
            if (options.to_sign_path.empty() || options.secret_key_path.empty() ||
                options.output_path.empty())
            {
                result.error = L"to-sign, secret-key, and output paths are all required";
                return result;
            }

            // Read the to-sign file (emitted by the web UI's finalization
            // flow, or assembled by a customer script).
            json to_sign;
            {
                std::ifstream in(options.to_sign_path);
                if (!in)
                    throw std::runtime_error("cannot open to-sign file: " + options.to_sign_path.string());
                try { in >> to_sign; }
                catch (const std::exception& e)
                {
                    throw std::runtime_error(std::string("to-sign file is not valid JSON: ") + e.what());
                }
            }
            if (!to_sign.is_object())
                throw std::runtime_error("to-sign file must be a JSON object");

            auto req_string = [&](const char* name) -> std::string {
                if (!to_sign.contains(name) || !to_sign.at(name).is_string())
                    throw std::runtime_error(std::string("to-sign file missing required string field: ") + name);
                return to_sign.at(name).get<std::string>();
            };

            // fromCompanyId is not part of the canonical signed payload
            // (the platform derives the signer from authentication).
            // Older to-sign files may still contain it; it is ignored.
            fhe_toolkit::registry::FinalKeysEnvelopeFields fields;
            fields.permission_id   = req_string("permissionId");
            fields.timestamp       = req_string("timestamp");

            std::vector<fhe_toolkit::registry::FinalKeyRef> refs;
            if (!to_sign.contains("keys") || !to_sign.at("keys").is_array())
                throw std::runtime_error("to-sign file missing required array field: keys");
            for (const auto& k : to_sign.at("keys"))
            {
                if (!k.is_object())
                    throw std::runtime_error("keys[] entry is not an object");
                fhe_toolkit::registry::FinalKeyRef r;
                r.key_type   = k.at("keyType").get<std::string>();
                r.object_key = k.at("objectKey").get<std::string>();
                r.sha256_hex = k.at("sha256Hex").get<std::string>();
                refs.push_back(std::move(r));
            }

            // Load signing key.
            auto sk_bytes = read_bytes(options.secret_key_path);
            auto sk = fhe_toolkit::signing::load_secret_key(sk_bytes);

            // Sign.
            const std::string body =
                fhe_toolkit::registry::make_signed_final_keys_envelope(refs, fields, sk);

            if (options.output_path.has_parent_path())
                std::filesystem::create_directories(options.output_path.parent_path());

            {
                std::ofstream out(options.output_path, std::ios::trunc);
                if (!out) throw std::runtime_error("cannot open for writing: " + options.output_path.string());
                out << body;
                if (!out) throw std::runtime_error("write failed: " + options.output_path.string());
            }

            std::wostringstream out;
            out << L"Signed final-keys envelope written.\n\n";
            out << L"  Output:           " << options.output_path.wstring()
                << L" (" << body.size() << L" bytes)\n";
            out << L"  Permission ID:    " << widen(fields.permission_id) << L"\n";
            out << L"  Timestamp:        " << widen(fields.timestamp) << L"\n";
            out << L"  Key count:        " << refs.size() << L"\n\n";
            out << L"Bring this .json file back to the platform's keysetup page. The platform's "
                   L"finalization flow will POST it to /api/fhe-permissions/{id}/keysetup/final-keys "
                   L"and report whether the byte-equality check against your peer's submission passed.";
            result.summary = out.str();
            result.success = true;
        }
        catch (const std::exception& e) { result.error = widen(e.what()); }
        catch (...) { result.error = L"unknown error during wrap-final-keys-envelope"; }
        return result;
    }

    OperationResult ToolkitClient::Verify(const VerifyOptions& options)
    {
        OperationResult result;
        try
        {
            if (options.input_path.empty() || options.public_key_path.empty() || options.signature_path.empty())
            {
                result.error = L"input, public-key, and signature paths are all required";
                return result;
            }

            auto pk_bytes  = read_bytes(options.public_key_path);
            auto sig_bytes = read_bytes(options.signature_path);
            auto message   = read_bytes(options.input_path);

            auto pk  = fhe_toolkit::signing::load_public_key(pk_bytes);
            auto sig = fhe_toolkit::signing::load_signature(sig_bytes);
            bool ok  = fhe_toolkit::signing::verify(pk, message, sig);

            std::wostringstream out;
            out << (ok ? L"VALID" : L"INVALID")
                << L": Ed25519 signature on " << options.input_path.wstring() << L"\n\n";
            if (!ok)
            {
                out << L"The signature does NOT match the file content under this public key. "
                       L"Either the file was modified, the signature is from a different key, "
                       L"or one of the inputs is corrupted.";
            }
            else
            {
                out << L"The signature is valid: the file content matches what was signed, "
                       L"by the holder of the secret key corresponding to the supplied public key.";
            }
            result.summary = out.str();
            result.success = ok;
            if (!ok) result.error = L"signature does not verify";
        }
        catch (const std::exception& e) { result.error = widen(e.what()); }
        catch (...) { result.error = L"unknown error during verify"; }
        return result;
    }

    OperationResult ToolkitClient::RelinContribute(const RelinContributeOptions& options)
    {
        OperationResult result;
        try
        {
            if (options.round != 1 && options.round != 2)
            {
                result.error = L"round must be 1 or 2";
                return result;
            }
            if (options.secret_key_path.empty() || options.output_path.empty())
            {
                result.error = L"secret-key and output paths are required";
                return result;
            }
            if (options.round == 1)
            {
                if (options.role != "lead" && options.role != "main")
                {
                    result.error = L"role must be 'lead' or 'main' for round 1";
                    return result;
                }
                if (options.role == "main" && options.peer_share_path.empty())
                {
                    result.error = L"peer-share is required for round 1, role=main";
                    return result;
                }
            }
            else
            {
                if (options.combined_r1_path.empty() || options.joint_pk_path.empty())
                {
                    result.error = L"combined-r1 and joint-pk are required for round 2";
                    return result;
                }
            }

            auto spec = fhe_toolkit::crypto::get_crypto_context_spec(options.context_spec);
            if (!spec) { result.error = L"unknown context spec: " + widen(options.context_spec); return result; }

            fhe_toolkit::crypto::Context ctx(*spec);
            auto sk_bytes = read_bytes(options.secret_key_path);
            auto sk = fhe_toolkit::crypto::SecretKey::deserialize(ctx, sk_bytes);

            fhe_toolkit::crypto::EvalKey out;
            if (options.round == 1 && options.role == "lead")
            {
                out = ctx.relin_round1_initial(sk);
            }
            else if (options.round == 1 && options.role == "main")
            {
                auto prev_bytes = read_bytes(options.peer_share_path);
                auto prev = fhe_toolkit::crypto::EvalKey::deserialize(ctx, prev_bytes);
                out = ctx.relin_round1_continue(sk, prev);
            }
            else
            {
                auto c1_bytes = read_bytes(options.combined_r1_path);
                auto c1 = fhe_toolkit::crypto::EvalKey::deserialize(ctx, c1_bytes);
                auto jpk_bytes = read_bytes(options.joint_pk_path);
                auto jpk = fhe_toolkit::crypto::PublicKey::deserialize(ctx, jpk_bytes);
                out = ctx.relin_round2(sk, c1, jpk);
            }

            auto out_bytes = out.serialize();
            if (options.output_path.has_parent_path())
                std::filesystem::create_directories(options.output_path.parent_path());
            write_bytes(options.output_path, out_bytes);

            std::wostringstream summary;
            summary << L"Relinearization key contribution (round " << options.round;
            if (options.round == 1) summary << L", role " << widen(options.role);
            summary << L").\n\n";
            summary << L"  Output: " << options.output_path.wstring() << L"\n";
            summary << L"          (" << out_bytes.size() << L" bytes)\n\n";
            summary << L"Upload this file to the platform's keysetup page for the current "
                       L"sub-round; the peer will download it and produce the matching contribution.";
            result.summary = summary.str();
            result.success = true;
        }
        catch (const std::exception& e) { result.error = widen(e.what()); }
        catch (...) { result.error = L"unknown error during relin contribute"; }
        return result;
    }

    OperationResult ToolkitClient::RelinCombine(const RelinCombineOptions& options)
    {
        OperationResult result;
        try
        {
            if (options.round != 1 && options.round != 2)
            {
                result.error = L"round must be 1 or 2";
                return result;
            }
            if (options.share_a_path.empty() || options.share_b_path.empty() || options.output_path.empty())
            {
                result.error = L"share-a, share-b, and output paths are required";
                return result;
            }
            if (options.round == 1 && options.joint_pk_path.empty())
            {
                result.error = L"joint-pk is required for round 1 combine";
                return result;
            }
            if (options.round == 2 && options.combined_r1_path.empty())
            {
                result.error = L"combined-r1 is required for round 2 combine";
                return result;
            }

            auto spec = fhe_toolkit::crypto::get_crypto_context_spec(options.context_spec);
            if (!spec) { result.error = L"unknown context spec: " + widen(options.context_spec); return result; }

            fhe_toolkit::crypto::Context ctx(*spec);
            auto a = fhe_toolkit::crypto::EvalKey::deserialize(ctx, read_bytes(options.share_a_path));
            auto b = fhe_toolkit::crypto::EvalKey::deserialize(ctx, read_bytes(options.share_b_path));

            fhe_toolkit::crypto::EvalKey out;
            if (options.round == 1)
            {
                auto jpk = fhe_toolkit::crypto::PublicKey::deserialize(ctx, read_bytes(options.joint_pk_path));
                out = ctx.relin_combine_round1(a, b, jpk);
            }
            else
            {
                auto c1 = fhe_toolkit::crypto::EvalKey::deserialize(ctx, read_bytes(options.combined_r1_path));
                out = ctx.relin_combine_round2(a, b, c1);
            }

            auto out_bytes = out.serialize();
            if (options.output_path.has_parent_path())
                std::filesystem::create_directories(options.output_path.parent_path());
            write_bytes(options.output_path, out_bytes);

            std::wostringstream summary;
            summary << L"Relinearization key " << (options.round == 1 ? L"round-1 intermediate" : L"final")
                    << L" combine.\n\n";
            summary << L"  Output: " << options.output_path.wstring() << L"\n";
            summary << L"          (" << out_bytes.size() << L" bytes)\n\n";
            summary << L"Both parties should produce byte-identical output. Upload "
                       L"(or upload the hash) for byte-equality verification against the peer.";
            result.summary = summary.str();
            result.success = true;
        }
        catch (const std::exception& e) { result.error = widen(e.what()); }
        catch (...) { result.error = L"unknown error during relin combine"; }
        return result;
    }

    OperationResult ToolkitClient::SumContribute(const SumContributeOptions& options)
    {
        OperationResult result;
        try
        {
            if (options.role != "lead" && options.role != "main")
            {
                result.error = L"role must be 'lead' or 'main'";
                return result;
            }
            if (options.secret_key_path.empty() || options.output_path.empty())
            {
                result.error = L"secret-key and output paths are required";
                return result;
            }
            if (options.role == "main" && (options.peer_share_path.empty() || options.joint_pk_path.empty()))
            {
                result.error = L"peer-share and joint-pk are required for role=main";
                return result;
            }

            auto spec = fhe_toolkit::crypto::get_crypto_context_spec(options.context_spec);
            if (!spec) { result.error = L"unknown context spec: " + widen(options.context_spec); return result; }

            fhe_toolkit::crypto::Context ctx(*spec);
            auto sk = fhe_toolkit::crypto::SecretKey::deserialize(ctx, read_bytes(options.secret_key_path));

            fhe_toolkit::crypto::SumKeyMap out;
            if (options.role == "lead")
            {
                out = ctx.sum_round1_initial(sk);
            }
            else
            {
                auto prev = fhe_toolkit::crypto::SumKeyMap::deserialize(ctx, read_bytes(options.peer_share_path));
                auto jpk = fhe_toolkit::crypto::PublicKey::deserialize(ctx, read_bytes(options.joint_pk_path));
                out = ctx.sum_round1_continue(sk, prev, jpk);
            }

            auto out_bytes = out.serialize();
            if (options.output_path.has_parent_path())
                std::filesystem::create_directories(options.output_path.parent_path());
            write_bytes(options.output_path, out_bytes);

            std::wostringstream summary;
            summary << L"Sum key contribution (role " << widen(options.role) << L").\n\n";
            summary << L"  Output: " << options.output_path.wstring() << L"\n";
            summary << L"          (" << out_bytes.size() << L" bytes)\n\n";
            summary << L"Upload this file to the platform; the peer will download it next.";
            result.summary = summary.str();
            result.success = true;
        }
        catch (const std::exception& e) { result.error = widen(e.what()); }
        catch (...) { result.error = L"unknown error during sum contribute"; }
        return result;
    }

    OperationResult ToolkitClient::SumCombine(const SumCombineOptions& options)
    {
        OperationResult result;
        try
        {
            if (options.share_a_path.empty() || options.share_b_path.empty() ||
                options.joint_pk_path.empty() || options.output_path.empty())
            {
                result.error = L"share-a, share-b, joint-pk, and output paths are required";
                return result;
            }

            auto spec = fhe_toolkit::crypto::get_crypto_context_spec(options.context_spec);
            if (!spec) { result.error = L"unknown context spec: " + widen(options.context_spec); return result; }

            fhe_toolkit::crypto::Context ctx(*spec);
            auto a = fhe_toolkit::crypto::SumKeyMap::deserialize(ctx, read_bytes(options.share_a_path));
            auto b = fhe_toolkit::crypto::SumKeyMap::deserialize(ctx, read_bytes(options.share_b_path));
            auto jpk = fhe_toolkit::crypto::PublicKey::deserialize(ctx, read_bytes(options.joint_pk_path));

            auto out = ctx.sum_combine(a, b, jpk);
            auto out_bytes = out.serialize();
            if (options.output_path.has_parent_path())
                std::filesystem::create_directories(options.output_path.parent_path());
            write_bytes(options.output_path, out_bytes);

            std::wostringstream summary;
            summary << L"Sum key final combine.\n\n";
            summary << L"  Output: " << options.output_path.wstring() << L"\n";
            summary << L"          (" << out_bytes.size() << L" bytes)\n\n";
            summary << L"Both parties should produce byte-identical output. Upload "
                       L"(or upload the hash) for byte-equality verification against the peer.";
            result.summary = summary.str();
            result.success = true;
        }
        catch (const std::exception& e) { result.error = widen(e.what()); }
        catch (...) { result.error = L"unknown error during sum combine"; }
        return result;
    }

    // Parse "1,2,4,-1,-2" -> vector<int32_t>. Whitespace tolerated, empty
    // entries skipped. Throws on any non-integer token.
    static std::vector<int32_t> parse_indices_csv(const std::string& csv)
    {
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
        for (char c : csv)
        {
            if (c == ' ' || c == '\t') continue;
            if (c == ',') flush();
            else buf.push_back(c);
        }
        flush();
        return out;
    }

    OperationResult ToolkitClient::RotationContribute(const RotationContributeOptions& options)
    {
        OperationResult result;
        try
        {
            if (options.role != "lead" && options.role != "main")
            {
                result.error = L"role must be 'lead' or 'main'";
                return result;
            }
            if (options.secret_key_path.empty() || options.output_path.empty())
            {
                result.error = L"secret-key and output paths are required";
                return result;
            }
            if (options.indices_csv.empty())
            {
                result.error = L"rotation indices are required (e.g. '1,2,4,-1,-2')";
                return result;
            }
            if (options.role == "main" && (options.peer_share_path.empty() || options.joint_pk_path.empty()))
            {
                result.error = L"peer-share and joint-pk are required for role=main";
                return result;
            }

            std::vector<int32_t> indices;
            try { indices = parse_indices_csv(options.indices_csv); }
            catch (const std::exception& e) { result.error = L"indices parse error: " + widen(e.what()); return result; }
            if (indices.empty()) { result.error = L"indices parsed to empty list"; return result; }

            auto spec = fhe_toolkit::crypto::get_crypto_context_spec(options.context_spec);
            if (!spec) { result.error = L"unknown context spec: " + widen(options.context_spec); return result; }

            fhe_toolkit::crypto::Context ctx(*spec);
            auto sk = fhe_toolkit::crypto::SecretKey::deserialize(ctx, read_bytes(options.secret_key_path));

            fhe_toolkit::crypto::RotationKeyMap out;
            if (options.role == "lead")
            {
                out = ctx.rotation_round1_initial(sk, indices);
            }
            else
            {
                auto prev = fhe_toolkit::crypto::RotationKeyMap::deserialize(ctx, read_bytes(options.peer_share_path));
                auto jpk = fhe_toolkit::crypto::PublicKey::deserialize(ctx, read_bytes(options.joint_pk_path));
                out = ctx.rotation_round1_continue(sk, prev, indices, jpk);
            }

            auto out_bytes = out.serialize();
            if (options.output_path.has_parent_path())
                std::filesystem::create_directories(options.output_path.parent_path());
            write_bytes(options.output_path, out_bytes);

            std::wostringstream summary;
            summary << L"Rotation key contribution (role " << widen(options.role)
                    << L", " << indices.size() << L" indices).\n\n";
            summary << L"  Output: " << options.output_path.wstring() << L"\n";
            summary << L"          (" << out_bytes.size() << L" bytes)\n\n";
            summary << L"Upload this file to the platform; the peer will download it next.";
            result.summary = summary.str();
            result.success = true;
        }
        catch (const std::exception& e) { result.error = widen(e.what()); }
        catch (...) { result.error = L"unknown error during rotation contribute"; }
        return result;
    }

    OperationResult ToolkitClient::RotationCombine(const RotationCombineOptions& options)
    {
        OperationResult result;
        try
        {
            if (options.share_a_path.empty() || options.share_b_path.empty() ||
                options.joint_pk_path.empty() || options.output_path.empty())
            {
                result.error = L"share-a, share-b, joint-pk, and output paths are required";
                return result;
            }

            auto spec = fhe_toolkit::crypto::get_crypto_context_spec(options.context_spec);
            if (!spec) { result.error = L"unknown context spec: " + widen(options.context_spec); return result; }

            fhe_toolkit::crypto::Context ctx(*spec);
            auto a = fhe_toolkit::crypto::RotationKeyMap::deserialize(ctx, read_bytes(options.share_a_path));
            auto b = fhe_toolkit::crypto::RotationKeyMap::deserialize(ctx, read_bytes(options.share_b_path));
            auto jpk = fhe_toolkit::crypto::PublicKey::deserialize(ctx, read_bytes(options.joint_pk_path));

            auto out = ctx.rotation_combine(a, b, jpk);
            auto out_bytes = out.serialize();
            if (options.output_path.has_parent_path())
                std::filesystem::create_directories(options.output_path.parent_path());
            write_bytes(options.output_path, out_bytes);

            std::wostringstream summary;
            summary << L"Rotation key final combine.\n\n";
            summary << L"  Output: " << options.output_path.wstring() << L"\n";
            summary << L"          (" << out_bytes.size() << L" bytes)\n\n";
            summary << L"Both parties should produce byte-identical output. Upload "
                       L"(or upload the hash) for byte-equality verification against the peer.";
            result.summary = summary.str();
            result.success = true;
        }
        catch (const std::exception& e) { result.error = widen(e.what()); }
        catch (...) { result.error = L"unknown error during rotation combine"; }
        return result;
    }

    CombineResult ToolkitClient::CombinePartials(const CombineOptions& options)
    {
        CombineResult result;
        try
        {
            if (options.partial_paths.size() < 2)
            {
                result.error = L"need at least two partial-decryption files to combine";
                return result;
            }

            auto spec = fhe_toolkit::crypto::get_crypto_context_spec(options.context_spec);
            if (!spec)
            {
                result.error = L"unknown context spec: " + widen(options.context_spec);
                return result;
            }

            fhe_toolkit::crypto::Context ctx(*spec);

            std::vector<fhe_toolkit::crypto::Ciphertext> partials;
            partials.reserve(options.partial_paths.size());
            std::vector<const fhe_toolkit::crypto::Ciphertext*> ptrs;
            ptrs.reserve(options.partial_paths.size());

            for (const auto& path : options.partial_paths)
            {
                auto bytes = read_bytes(path);
                partials.push_back(fhe_toolkit::crypto::Ciphertext::deserialize(ctx, bytes));
            }
            for (const auto& p : partials) ptrs.push_back(&p);

            auto plaintext = ctx.combine_partials(ptrs);
            auto values = plaintext.values();

            // Joint Record Overlap for Large Datasets (Count): the total of the count groups and
            // nothing else, read by psi/count in core, which refuses a result of any other shape.
            if (options.count_groups > 0)
            {
                std::vector<std::int64_t> as_int(values.begin(), values.end());
                result.count = static_cast<long long>(fhe_toolkit::psi::count_answer(as_int, options.count_groups));
                result.is_count = true;
                std::wostringstream count_out;
                count_out << L"Combined " << options.partial_paths.size() << L" partial decryptions.\n\n"
                          << L"Answer: " << result.count;
                result.summary = count_out.str();
                result.success = true;
                return result;
            }

            result.slots.reserve(values.size());
            for (auto v : values)
            {
                result.slots.push_back(static_cast<long long>(v));
                if (v != 0) ++result.non_zero_slots;
                result.sum_of_slots += v;
                if (v > result.max_slot_value) result.max_slot_value = v;
            }

            std::wostringstream out;
            out << L"Combined " << options.partial_paths.size() << L" partial decryptions.\n\n";
            out << L"  Total slots:    " << values.size() << L"\n";
            out << L"  Non-zero slots: " << result.non_zero_slots << L"\n";
            out << L"  Sum of slots:   " << result.sum_of_slots << L"\n";
            out << L"  Max slot value: " << result.max_slot_value << L"\n\n";
            out << L"For functions whose output is a scalar (like joint-record-overlap), "
                << L"the answer is in slot 0 (which equals the sum of all slots / total "
                << L"slot count due to BFV's broadcast-sum semantics). For vector outputs, "
                << L"inspect individual slots in the table below.";
            result.summary = out.str();
            result.success = true;
        }
        catch (const std::exception& e)
        {
            result.error = widen(e.what());
        }
        catch (...)
        {
            result.error = L"unknown error during combine";
        }
        return result;
    }
}
