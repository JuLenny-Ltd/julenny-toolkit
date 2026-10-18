#ifndef JULENNY_TOOLKIT_CLI_PROMPTS_H
#define JULENNY_TOOLKIT_CLI_PROMPTS_H

#include <optional>
#include <string>

namespace julenny_fhe::cli {

// The value of an environment variable, or nullopt if it is unset or empty.
// On Windows this reads via _dupenv_s (the CRT deprecates getenv there).
std::optional<std::string> env_value(const char* name);

// Resolves a passphrase in priority order:
//   1. explicit_arg (if non-empty)
//   2. FHE_TOOLKIT_PASSPHRASE env var (if set and non-empty)
//   3. interactive prompt via /dev/tty (with echo disabled)
// Returns nullopt if none of the three sources is available.
std::optional<std::string> resolve_passphrase(
    const std::string& explicit_arg,
    const std::string& prompt = "Passphrase: "
);

}  // namespace julenny_fhe::cli

#endif
