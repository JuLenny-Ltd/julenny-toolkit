#include "commands.h"

#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <map>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

#include "prompts.h"
#include "storage/filesystem_store.h"
#include "crypto/context.h"
#include "crypto/keys.h"

namespace julenny_fhe::cli {

using nlohmann::json;
using fhe_toolkit::storage::FilesystemSecretStore;
using fhe_toolkit::crypto::Context;
using fhe_toolkit::crypto::get_crypto_context_spec;

namespace {

// Per-OS default secret-store path. Local-only; no network involvement.
//   Linux/macOS: $XDG_DATA_HOME/julenny-fhe/secrets
//                ($HOME/.local/share/julenny-fhe/secrets as fallback)
//   Windows:     %APPDATA%/julenny-fhe/secrets
std::filesystem::path default_secret_store_path() {
#ifdef _WIN32
    const char* appdata = std::getenv("APPDATA");
    if (appdata && *appdata) {
        return std::filesystem::path(appdata) / "julenny-fhe" / "secrets";
    }
#else
    if (const char* xdg = std::getenv("XDG_DATA_HOME"); xdg && *xdg) {
        return std::filesystem::path(xdg) / "julenny-fhe" / "secrets";
    }
    if (const char* home = std::getenv("HOME"); home && *home) {
        return std::filesystem::path(home) / ".local" / "share" / "julenny-fhe" / "secrets";
    }
#endif
    return std::filesystem::path("julenny-fhe-secrets");
}

std::string resolve_store_path(const std::string& flag_value) {
    if (!flag_value.empty()) return flag_value;
    return default_secret_store_path().string();
}

std::string prefix_of(std::string_view key) {
    auto pos = key.find('/');
    if (pos == std::string_view::npos) return "(no prefix)";
    auto pos2 = key.find('/', pos + 1);
    if (pos2 == std::string_view::npos) return std::string(key.substr(0, pos));
    return std::string(key.substr(0, pos2));
}

int run_keys_status(const KeysStatusArgs& args) {
    auto passphrase = resolve_passphrase(args.passphrase, "Passphrase: ");
    if (!passphrase) {
        std::cerr << "error: no passphrase available\n";
        return 2;
    }

    const std::string store_path = resolve_store_path(args.secret_store_path);
    FilesystemSecretStore store(store_path, *passphrase);
    auto keys = store.list("");

    std::map<std::string, size_t> by_prefix;
    for (const auto& k : keys) by_prefix[prefix_of(k)] += 1;

    if (args.emit_json) {
        json out;
        out["secretStorePath"] = store_path;
        out["total"]    = keys.size();
        out["byPrefix"] = json::object();
        for (const auto& [p, n] : by_prefix) out["byPrefix"][p] = n;
        out["keys"]     = keys;
        std::cout << out.dump(2) << "\n";
    } else {
        std::cout << "Secret store: " << store_path << "\n";
        std::cout << "Total keys:   " << keys.size() << "\n";
        if (keys.empty()) {
            std::cout << "(none)\n";
        } else {
            std::cout << "\nBy prefix:\n";
            for (const auto& [p, n] : by_prefix) {
                std::cout << "  " << p << ": " << n << "\n";
            }
        }
    }
    return 0;
}


int run_keys_generate(const KeysGenerateArgs& args) {
    auto passphrase = resolve_passphrase(args.passphrase, "Passphrase: ");
    if (!passphrase) {
        std::cerr << "error: no passphrase available\n";
        return 2;
    }

    auto spec = get_crypto_context_spec(args.context_spec);
    if (!spec) {
        std::cerr << "error: unknown context spec: " << args.context_spec << "\n";
        std::cerr << "       known: bfv-default-v1, ckks-default-v1\n";
        return 2;
    }

    const std::string store_path = resolve_store_path(args.secret_store_path);
    FilesystemSecretStore store(store_path, *passphrase);
    const std::string pk_key = "share/companies/" + args.context_spec + "/public";
    const std::string sk_key = "share/companies/" + args.context_spec + "/secret";

    if (!args.force && (store.exists(pk_key) || store.exists(sk_key))) {
        std::cerr << "error: keys for context '" << args.context_spec << "' already exist; "
                  << "pass --force to overwrite\n";
        return 1;
    }

    // Real key generation - the slow step (~hundreds of milliseconds).
    Context ctx(*spec);
    auto kp = ctx.generate_keypair();
    auto pk_bytes = kp.public_key.serialize();
    auto sk_bytes = kp.secret_key.serialize();

    store.put(pk_key, pk_bytes);
    store.put(sk_key, sk_bytes);

    if (args.emit_json) {
        json out;
        out["status"]          = "ok";
        out["secretStorePath"] = store_path;
        out["contextSpec"]     = args.context_spec;
        out["publicKeyKey"]    = pk_key;
        out["secretKeyKey"]    = sk_key;
        out["publicKeyBytes"]  = pk_bytes.size();
        out["secretKeyBytes"]  = sk_bytes.size();
        std::cout << out.dump(2) << "\n";
    } else {
        std::cout << "Generated keypair for context: " << args.context_spec << "\n";
        std::cout << "  Secret store: " << store_path << "\n";
        std::cout << "  Public key:   " << pk_bytes.size() << " bytes -> " << pk_key << "\n";
        std::cout << "  Secret key:   " << sk_bytes.size() << " bytes -> " << sk_key << "\n";
        std::cout << "\nBoth keys stay on this machine. To share the public key with a\n";
        std::cout << "partner or the platform, export it via your own out-of-band channel.\n";
    }
    return 0;
}

}  // namespace

void register_keys(CLI::App& app,
                   KeysStatusArgs& status_args,
                   KeysGenerateArgs& gen_args,
                   int* exit_code) {
    auto* keys = app.add_subcommand("keys", "Inspect or manage locally-stored keys");

    auto* status = keys->add_subcommand("status", "Show key counts and store status");
    status->add_option("--secret-store-path", status_args.secret_store_path,
                       "Path to the local secret store (default: per-OS default)");
    status->add_option("--passphrase", status_args.passphrase, "Passphrase for the secret store");
    status->add_flag  ("--json",       status_args.emit_json,  "Emit JSON output");
    status->callback([&status_args, exit_code]() { *exit_code = run_keys_status(status_args); });

    auto* gen = keys->add_subcommand("generate", "Generate a local FHE keypair");
    gen->add_option("--secret-store-path", gen_args.secret_store_path,
                    "Path to the local secret store (default: per-OS default)");
    gen->add_option("--context-spec", gen_args.context_spec,
                    "Crypto context spec (default: bfv-default-v1)");
    gen->add_option("--passphrase",   gen_args.passphrase, "Passphrase for the secret store");
    gen->add_flag  ("--force",        gen_args.force,
                    "Overwrite existing keys for this context");
    gen->add_flag  ("--json",         gen_args.emit_json,  "Emit JSON output");
    gen->callback([&gen_args, exit_code]() { *exit_code = run_keys_generate(gen_args); });
}

}  // namespace julenny_fhe::cli
