#ifndef FHE_TOOLKIT_STORAGE_FILESYSTEM_STORE_H
#define FHE_TOOLKIT_STORAGE_FILESYSTEM_STORE_H

// SecretStore implementation that persists values to encrypted files on disk.
//
// Each value is stored in its own file under `base_dir`, with the key
// encoded as the filename via base64url. File contents are encrypted with
// AES-256-GCM using a key derived from the user-supplied passphrase via
// scrypt.
//
// Threat model: this adapter protects against:
//   - Casual filesystem inspection (files are unreadable without the passphrase)
//   - Filesystem backups leaking secrets in plaintext
//
// It does NOT protect against:
//   - Active compromise of the running process or the user account
//   - An attacker who has both the encrypted files AND the passphrase
//
// Customers wanting hardware-backed protection should use the AWS KMS,
// HashiCorp Vault, or HSM adapters (TODO, added in a later chunk).

#include <filesystem>

#include "secret_store.h"

namespace fhe_toolkit::storage {

class FilesystemSecretStore : public SecretStore {
public:
    // Creates or opens a store at `base_dir` using `passphrase` for key derivation.
    //
    // On first use, `base_dir` must be empty or non-existent (will be created).
    // A random 32-byte master salt is generated and stored in `base_dir/.master_salt`.
    // On subsequent uses, the existing salt is reused.
    //
    // Throws std::runtime_error on I/O errors or if the salt file is corrupt.
    FilesystemSecretStore(std::filesystem::path base_dir, std::string_view passphrase);

    void put(std::string_view key, std::span<const std::byte> value) override;
    std::optional<Bytes> get(std::string_view key) override;
    bool remove(std::string_view key) override;
    bool exists(std::string_view key) override;
    std::vector<std::string> list(std::string_view prefix) override;

private:
    std::filesystem::path path_for_key(std::string_view key) const;

    std::filesystem::path base_dir_;
    Bytes master_key_;  // 32 bytes, derived from passphrase + master_salt_ via scrypt
};

}  // namespace fhe_toolkit::storage

#endif
