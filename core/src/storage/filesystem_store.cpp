#include "filesystem_store.h"

#include <array>
#include <cstring>
#include <fstream>
#include <stdexcept>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include "base64url.h"

namespace fhe_toolkit::storage {

namespace {

constexpr size_t kMasterKeyLen = 32;        // AES-256 key
constexpr size_t kMasterSaltLen = 32;       // scrypt salt
constexpr size_t kNonceLen = 12;            // AES-GCM nonce
constexpr size_t kTagLen = 16;              // AES-GCM authentication tag
constexpr std::array<std::byte, 4> kMagic = {
    std::byte{'F'}, std::byte{'H'}, std::byte{'E'}, std::byte{'1'},
};

// scrypt parameters (RFC 7914 §2). N=2^15 gives ~100ms on modern hardware.
constexpr uint64_t kScryptN = 1u << 15;
constexpr uint64_t kScryptR = 8;
constexpr uint64_t kScryptP = 1;
constexpr uint64_t kScryptMaxMem = 64u * 1024u * 1024u;  // 64 MiB cap

Bytes random_bytes(size_t n) {
    Bytes out(n);
    if (RAND_bytes(reinterpret_cast<unsigned char*>(out.data()),
                   static_cast<int>(n)) != 1) {
        throw std::runtime_error("RAND_bytes failed");
    }
    return out;
}

Bytes derive_key(std::string_view passphrase, std::span<const std::byte> salt) {
    Bytes key(kMasterKeyLen);
    if (EVP_PBE_scrypt(passphrase.data(), passphrase.size(),
                       reinterpret_cast<const unsigned char*>(salt.data()), salt.size(),
                       kScryptN, kScryptR, kScryptP, kScryptMaxMem,
                       reinterpret_cast<unsigned char*>(key.data()), kMasterKeyLen) != 1) {
        throw std::runtime_error("EVP_PBE_scrypt failed");
    }
    return key;
}

Bytes read_file(const std::filesystem::path& p) {
    std::ifstream in(p, std::ios::binary);
    if (!in) throw std::runtime_error("cannot open file for reading: " + p.string());
    in.seekg(0, std::ios::end);
    std::streamsize size = in.tellg();
    in.seekg(0, std::ios::beg);
    Bytes buf(static_cast<size_t>(size));
    if (size > 0 && !in.read(reinterpret_cast<char*>(buf.data()), size)) {
        throw std::runtime_error("read failed: " + p.string());
    }
    return buf;
}

void write_file_atomically(const std::filesystem::path& p, std::span<const std::byte> bytes) {
    auto tmp = p;
    tmp += ".tmp";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) throw std::runtime_error("cannot open for writing: " + tmp.string());
        out.write(reinterpret_cast<const char*>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()));
        if (!out) throw std::runtime_error("write failed: " + tmp.string());
    }
    std::filesystem::rename(tmp, p);
}

Bytes aes_gcm_encrypt(std::span<const std::byte> key,
                      std::span<const std::byte> nonce,
                      std::span<const std::byte> plaintext) {
    if (key.size() != kMasterKeyLen) throw std::runtime_error("bad key length");
    if (nonce.size() != kNonceLen) throw std::runtime_error("bad nonce length");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    Bytes out(plaintext.size() + kTagLen);
    int outlen = 0, total = 0;

    try {
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
            throw std::runtime_error("EVP_EncryptInit_ex failed");
        }
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) != 1) {
            throw std::runtime_error("EVP_CTRL_GCM_SET_IVLEN failed");
        }
        if (EVP_EncryptInit_ex(ctx, nullptr, nullptr,
                               reinterpret_cast<const unsigned char*>(key.data()),
                               reinterpret_cast<const unsigned char*>(nonce.data())) != 1) {
            throw std::runtime_error("EVP_EncryptInit_ex (key/iv) failed");
        }
        if (EVP_EncryptUpdate(ctx,
                              reinterpret_cast<unsigned char*>(out.data()), &outlen,
                              reinterpret_cast<const unsigned char*>(plaintext.data()),
                              static_cast<int>(plaintext.size())) != 1) {
            throw std::runtime_error("EVP_EncryptUpdate failed");
        }
        total += outlen;
        if (EVP_EncryptFinal_ex(ctx,
                                reinterpret_cast<unsigned char*>(out.data()) + total, &outlen) != 1) {
            throw std::runtime_error("EVP_EncryptFinal_ex failed");
        }
        total += outlen;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, kTagLen,
                                reinterpret_cast<unsigned char*>(out.data()) + total) != 1) {
            throw std::runtime_error("EVP_CTRL_GCM_GET_TAG failed");
        }
    } catch (...) {
        EVP_CIPHER_CTX_free(ctx);
        throw;
    }
    EVP_CIPHER_CTX_free(ctx);

    out.resize(static_cast<size_t>(total) + kTagLen);
    return out;
}

std::optional<Bytes> aes_gcm_decrypt(std::span<const std::byte> key,
                                     std::span<const std::byte> nonce,
                                     std::span<const std::byte> ciphertext_and_tag) {
    if (key.size() != kMasterKeyLen || nonce.size() != kNonceLen ||
        ciphertext_and_tag.size() < kTagLen) {
        return std::nullopt;
    }

    const size_t ct_len = ciphertext_and_tag.size() - kTagLen;
    const auto ciphertext = ciphertext_and_tag.subspan(0, ct_len);
    const auto tag = ciphertext_and_tag.subspan(ct_len, kTagLen);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return std::nullopt;

    Bytes out(ct_len);
    int outlen = 0, total = 0;

    auto cleanup = [&]() { EVP_CIPHER_CTX_free(ctx); };

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) { cleanup(); return std::nullopt; }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) != 1) { cleanup(); return std::nullopt; }
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr,
                           reinterpret_cast<const unsigned char*>(key.data()),
                           reinterpret_cast<const unsigned char*>(nonce.data())) != 1) { cleanup(); return std::nullopt; }
    if (EVP_DecryptUpdate(ctx,
                          reinterpret_cast<unsigned char*>(out.data()), &outlen,
                          reinterpret_cast<const unsigned char*>(ciphertext.data()),
                          static_cast<int>(ciphertext.size())) != 1) { cleanup(); return std::nullopt; }
    total += outlen;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, kTagLen,
                            const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(tag.data()))) != 1) { cleanup(); return std::nullopt; }
    if (EVP_DecryptFinal_ex(ctx,
                            reinterpret_cast<unsigned char*>(out.data()) + total, &outlen) != 1) {
        // Tag mismatch - either tampered or wrong key.
        cleanup();
        return std::nullopt;
    }
    total += outlen;
    cleanup();

    out.resize(static_cast<size_t>(total));
    return out;
}

}  // namespace

FilesystemSecretStore::FilesystemSecretStore(std::filesystem::path base_dir,
                                             std::string_view passphrase)
    : base_dir_(std::move(base_dir)) {
    std::filesystem::create_directories(base_dir_);

    const auto salt_path = base_dir_ / ".master_salt";
    Bytes salt;
    if (std::filesystem::exists(salt_path)) {
        salt = read_file(salt_path);
        if (salt.size() != kMasterSaltLen) {
            throw std::runtime_error("corrupt master salt file: " + salt_path.string());
        }
    } else {
        salt = random_bytes(kMasterSaltLen);
        write_file_atomically(salt_path, salt);
        std::filesystem::permissions(salt_path,
                                     std::filesystem::perms::owner_read |
                                         std::filesystem::perms::owner_write,
                                     std::filesystem::perm_options::replace);
    }

    master_key_ = derive_key(passphrase, salt);
}

std::filesystem::path FilesystemSecretStore::path_for_key(std::string_view key) const {
    return base_dir_ / base64url_encode(key);
}

void FilesystemSecretStore::put(std::string_view key, std::span<const std::byte> value) {
    const Bytes nonce = random_bytes(kNonceLen);
    const Bytes ciphertext = aes_gcm_encrypt(master_key_, nonce, value);

    // File layout: magic (4) | nonce (12) | ciphertext+tag
    Bytes file_bytes;
    file_bytes.reserve(kMagic.size() + nonce.size() + ciphertext.size());
    file_bytes.insert(file_bytes.end(), kMagic.begin(), kMagic.end());
    file_bytes.insert(file_bytes.end(), nonce.begin(), nonce.end());
    file_bytes.insert(file_bytes.end(), ciphertext.begin(), ciphertext.end());

    const auto p = path_for_key(key);
    write_file_atomically(p, file_bytes);
    std::filesystem::permissions(p,
                                 std::filesystem::perms::owner_read |
                                     std::filesystem::perms::owner_write,
                                 std::filesystem::perm_options::replace);
}

std::optional<Bytes> FilesystemSecretStore::get(std::string_view key) {
    const auto p = path_for_key(key);
    if (!std::filesystem::exists(p)) return std::nullopt;

    const Bytes file_bytes = read_file(p);
    if (file_bytes.size() < kMagic.size() + kNonceLen + kTagLen) {
        throw std::runtime_error("secret file too short: " + p.string());
    }
    if (!std::equal(kMagic.begin(), kMagic.end(), file_bytes.begin())) {
        throw std::runtime_error("secret file has wrong magic: " + p.string());
    }

    const auto bytes = std::span<const std::byte>(file_bytes);
    const auto nonce = bytes.subspan(kMagic.size(), kNonceLen);
    const auto ciphertext = bytes.subspan(kMagic.size() + kNonceLen);

    auto decrypted = aes_gcm_decrypt(master_key_, nonce, ciphertext);
    if (!decrypted) {
        throw std::runtime_error("secret decryption failed (wrong passphrase, or file tampered): " +
                                 p.string());
    }
    return decrypted;
}

bool FilesystemSecretStore::remove(std::string_view key) {
    const auto p = path_for_key(key);
    return std::filesystem::remove(p);
}

bool FilesystemSecretStore::exists(std::string_view key) {
    return std::filesystem::exists(path_for_key(key));
}

std::vector<std::string> FilesystemSecretStore::list(std::string_view prefix) {
    std::vector<std::string> out;
    if (!std::filesystem::exists(base_dir_)) return out;
    for (const auto& entry : std::filesystem::directory_iterator(base_dir_)) {
        if (!entry.is_regular_file()) continue;
        const std::string name = entry.path().filename().string();
        if (name.empty() || name[0] == '.') continue;  // Skip .master_salt and friends.
        auto decoded = base64url_decode_to_string(name);
        if (!decoded) continue;
        if (decoded->rfind(prefix, 0) == 0) out.push_back(std::move(*decoded));
    }
    return out;
}

}  // namespace fhe_toolkit::storage
