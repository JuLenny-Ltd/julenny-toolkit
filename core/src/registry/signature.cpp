#include "registry/signature.h"

#include <cstring>
#include <vector>

#include <openssl/evp.h>

#include "registry/canonical_json.h"

namespace fhe_toolkit::registry {

namespace {

constexpr size_t kEd25519PubKeyLen = 32;
constexpr size_t kEd25519SigLen    = 64;

// Decodes standard base64 (with optional padding) into bytes.
// Returns empty vector on malformed input.
std::vector<std::byte> base64_decode(std::string_view s) {
    static int decode_table[256];
    static bool initialized = false;
    if (!initialized) {
        for (auto& v : decode_table) v = -1;
        const char* alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (int i = 0; i < 64; ++i) decode_table[static_cast<unsigned char>(alphabet[i])] = i;
        initialized = true;
    }

    std::vector<std::byte> out;
    out.reserve((s.size() * 3) / 4);

    uint32_t buf = 0;
    int bits = 0;
    for (char c : s) {
        if (c == '=' || c == '\n' || c == '\r' || c == ' ' || c == '\t') continue;
        const int v = decode_table[static_cast<unsigned char>(c)];
        if (v < 0) return {};
        buf = (buf << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<std::byte>((buf >> bits) & 0xff));
        }
    }
    return out;
}

}  // namespace

bool verify_ed25519(std::span<const std::byte> public_key,
                    std::span<const std::byte> message,
                    std::span<const std::byte> signature) {
    if (public_key.size() != kEd25519PubKeyLen) return false;
    if (signature.size()  != kEd25519SigLen)    return false;

    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519, nullptr,
        reinterpret_cast<const unsigned char*>(public_key.data()),
        public_key.size());
    if (!pkey) return false;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pkey);
        return false;
    }

    bool ok = false;
    if (EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) == 1) {
        const int rc = EVP_DigestVerify(
            ctx,
            reinterpret_cast<const unsigned char*>(signature.data()),
            signature.size(),
            reinterpret_cast<const unsigned char*>(message.data()),
            message.size());
        ok = (rc == 1);
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return ok;
}

bool verify_function_definition_signature(const nlohmann::json& fn_def,
                                          std::span<const std::byte> public_key) {
    if (!fn_def.is_object())                  return false;
    if (!fn_def.contains("registry"))         return false;
    const auto& reg = fn_def.at("registry");
    if (!reg.is_object())                     return false;
    if (!reg.contains("signature"))           return false;
    if (!reg.at("signature").is_string())     return false;

    const std::string sig_b64 = reg.at("signature").get<std::string>();
    const auto sig_bytes = base64_decode(sig_b64);
    if (sig_bytes.size() != kEd25519SigLen)   return false;

    const auto canonical = function_definition_canonical_bytes(fn_def);
    return verify_ed25519(public_key, canonical, sig_bytes);
}

}  // namespace fhe_toolkit::registry
