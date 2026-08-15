// JuLenny FHE Toolkit CLI - entry point.
//
// This CLI is strictly offline. It performs local key generation, signing,
// encryption, threshold-FHE protocol steps, and signed-envelope wrapping.
// It does not make network calls. No HTTP client is linked. All platform
// interaction lives in the web UI or the customer's own scripts.

#include <iostream>
#include <string>

#include <CLI/CLI.hpp>

#include "commands/commands.h"
#include "fhe_toolkit/fhe_toolkit.h"

int main(int argc, char** argv) {
    CLI::App app{"JuLenny FHE Toolkit - offline customer-side crypto client"};
    app.require_subcommand(0, 1);

    app.set_version_flag("-v,--version", []() {
        return std::string("julenny-toolkit ") + fhe_toolkit_version();
    });

    int exit_code = 0;

    julenny_fhe::cli::KeysStatusArgs          keys_status_args;
    julenny_fhe::cli::KeysGenerateArgs        keys_generate_args;
    julenny_fhe::cli::CryptoSelftestArgs      crypto_selftest_args;
    julenny_fhe::cli::CryptoSigningKeygenArgs crypto_signing_keygen_args;
    julenny_fhe::cli::CryptoSignArgs          crypto_sign_args;
    julenny_fhe::cli::CryptoVerifyArgs        crypto_verify_args;
    julenny_fhe::cli::CryptoEncryptArgs       crypto_encrypt_args;
    julenny_fhe::cli::CryptoDecryptArgs       crypto_decrypt_args;
    julenny_fhe::cli::CryptoKeysetupContributeArgs crypto_keysetup_contribute_args;
    julenny_fhe::cli::CryptoRelinContributeArgs crypto_relin_contribute_args;
    julenny_fhe::cli::CryptoRelinCombineArgs    crypto_relin_combine_args;
    julenny_fhe::cli::CryptoSumContributeArgs   crypto_sum_contribute_args;
    julenny_fhe::cli::CryptoSumCombineArgs      crypto_sum_combine_args;
    julenny_fhe::cli::CryptoRotationContributeArgs crypto_rotation_contribute_args;
    julenny_fhe::cli::CryptoRotationCombineArgs    crypto_rotation_combine_args;
    julenny_fhe::cli::CryptoWrapEnvelopeArgs    crypto_wrap_envelope_args;
    julenny_fhe::cli::CryptoWrapFinalKeysEnvelopeArgs crypto_wrap_final_keys_envelope_args;
    julenny_fhe::cli::CryptoPartialDecryptArgs  crypto_partial_args;
    julenny_fhe::cli::CryptoCombineArgs         crypto_combine_args;
    julenny_fhe::cli::CryptoResolveIndicatorArgs crypto_resolve_indicator_args;
    julenny_fhe::cli::CryptoDeriveRotationIndicesArgs crypto_derive_rotation_indices_args;
    julenny_fhe::cli::CryptoInspectArgs         crypto_inspect_args;

    julenny_fhe::cli::register_keys(app, keys_status_args, keys_generate_args, &exit_code);
    julenny_fhe::cli::register_crypto(app, crypto_selftest_args,
                                       crypto_signing_keygen_args,
                                       crypto_sign_args,
                                       crypto_verify_args,
                                       crypto_encrypt_args, crypto_decrypt_args,
                                       crypto_keysetup_contribute_args,
                                       crypto_relin_contribute_args,
                                       crypto_relin_combine_args,
                                       crypto_sum_contribute_args,
                                       crypto_sum_combine_args,
                                       crypto_rotation_contribute_args,
                                       crypto_rotation_combine_args,
                                       crypto_wrap_envelope_args,
                                       crypto_wrap_final_keys_envelope_args,
                                       crypto_partial_args,
                                       crypto_combine_args,
                                       crypto_resolve_indicator_args,
                                       crypto_derive_rotation_indices_args,
                                       crypto_inspect_args, &exit_code);

    CLI11_PARSE(app, argc, argv);

    if (app.get_subcommands().empty()) {
        std::cout << app.help() << std::endl;
    }
    return exit_code;
}
