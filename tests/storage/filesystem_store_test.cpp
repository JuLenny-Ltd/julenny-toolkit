#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <random>
#include <string>
#include <vector>

#include "storage/base64url.h"
#include "storage/filesystem_store.h"

namespace fs = std::filesystem;
using namespace fhe_toolkit::storage;

namespace {

class TempDir {
public:
    TempDir() {
        std::random_device rd;
        const auto suffix = std::to_string(rd()) + "_" + std::to_string(rd());
        path_ = fs::temp_directory_path() / ("fhe_toolkit_test_" + suffix);
        fs::create_directories(path_);
    }
    ~TempDir() {
        std::error_code ec;
        fs::remove_all(path_, ec);
    }
    const fs::path& path() const { return path_; }

private:
    fs::path path_;
};

std::vector<std::byte> to_bytes(std::string_view s) {
    std::vector<std::byte> b;
    b.reserve(s.size());
    for (char c : s) b.push_back(static_cast<std::byte>(c));
    return b;
}

std::string from_bytes(const std::vector<std::byte>& b) {
    std::string s;
    s.reserve(b.size());
    for (auto x : b) s.push_back(static_cast<char>(x));
    return s;
}

}  // namespace

TEST_CASE("base64url encodes and decodes correctly", "[base64url]") {
    SECTION("empty input round-trips") {
        REQUIRE(base64url_encode("").empty());
        auto decoded = base64url_decode("");
        REQUIRE(decoded.has_value());
        REQUIRE(decoded->empty());
    }

    SECTION("ASCII text round-trips") {
        auto encoded = base64url_encode("hello world");
        auto decoded = base64url_decode_to_string(encoded);
        REQUIRE(decoded == "hello world");
    }

    SECTION("filesystem-unsafe characters become safe") {
        auto encoded = base64url_encode("share/grants/abc/bfv-default-v1");
        REQUIRE(encoded.find('/') == std::string::npos);
        REQUIRE(encoded.find('+') == std::string::npos);
        REQUIRE(encoded.find('=') == std::string::npos);
        auto decoded = base64url_decode_to_string(encoded);
        REQUIRE(decoded == "share/grants/abc/bfv-default-v1");
    }

    SECTION("invalid input returns nullopt") {
        REQUIRE_FALSE(base64url_decode("invalid$").has_value());
        REQUIRE_FALSE(base64url_decode("a").has_value());  // bad length
    }
}

TEST_CASE("FilesystemSecretStore basic operations", "[storage]") {
    TempDir tmp;
    FilesystemSecretStore store(tmp.path(), "test-passphrase");

    SECTION("get returns nullopt for missing key") {
        REQUIRE_FALSE(store.exists("foo"));
        REQUIRE_FALSE(store.get("foo").has_value());
    }

    SECTION("put then get returns the same value") {
        const auto value = to_bytes("secret value");
        store.put("foo", value);
        REQUIRE(store.exists("foo"));
        auto got = store.get("foo");
        REQUIRE(got.has_value());
        REQUIRE(*got == value);
    }

    SECTION("remove deletes the key") {
        store.put("foo", to_bytes("hello"));
        REQUIRE(store.remove("foo"));
        REQUIRE_FALSE(store.exists("foo"));
        REQUIRE_FALSE(store.get("foo").has_value());
    }

    SECTION("remove of missing key returns false") {
        REQUIRE_FALSE(store.remove("nonexistent"));
    }

    SECTION("overwriting works") {
        store.put("key", to_bytes("first"));
        store.put("key", to_bytes("second"));
        REQUIRE(from_bytes(*store.get("key")) == "second");
    }

    SECTION("empty value works") {
        store.put("empty", std::vector<std::byte>{});
        auto got = store.get("empty");
        REQUIRE(got.has_value());
        REQUIRE(got->empty());
    }

    SECTION("1 MiB value works") {
        std::vector<std::byte> big(1024 * 1024);
        for (size_t i = 0; i < big.size(); ++i) {
            big[i] = static_cast<std::byte>(i & 0xff);
        }
        store.put("big", big);
        auto got = store.get("big");
        REQUIRE(got.has_value());
        REQUIRE(*got == big);
    }
}

TEST_CASE("FilesystemSecretStore list with prefix", "[storage]") {
    TempDir tmp;
    FilesystemSecretStore store(tmp.path(), "p");

    store.put("share/grants/A/bfv-default", to_bytes("v1"));
    store.put("share/grants/B/bfv-default", to_bytes("v2"));
    store.put("eval/something",              to_bytes("v3"));

    auto grant_keys = store.list("share/grants/");
    REQUIRE(grant_keys.size() == 2);

    auto all_keys = store.list("");
    REQUIRE(all_keys.size() == 3);

    auto eval_keys = store.list("eval");
    REQUIRE(eval_keys.size() == 1);
    REQUIRE(eval_keys[0] == "eval/something");
}

TEST_CASE("FilesystemSecretStore list excludes .master_salt", "[storage]") {
    TempDir tmp;
    FilesystemSecretStore store(tmp.path(), "p");
    store.put("just-one", to_bytes("v"));

    auto keys = store.list("");
    REQUIRE(keys.size() == 1);
    REQUIRE(keys[0] == "just-one");
}

TEST_CASE("FilesystemSecretStore persists across reopens", "[storage]") {
    TempDir tmp;
    const auto value = to_bytes("durable secret");

    {
        FilesystemSecretStore store(tmp.path(), "passphrase");
        store.put("k", value);
    }
    {
        FilesystemSecretStore store(tmp.path(), "passphrase");
        auto got = store.get("k");
        REQUIRE(got.has_value());
        REQUIRE(*got == value);
    }
}

TEST_CASE("FilesystemSecretStore rejects wrong passphrase", "[storage]") {
    TempDir tmp;
    {
        FilesystemSecretStore store(tmp.path(), "right-passphrase");
        store.put("k", to_bytes("data"));
    }
    FilesystemSecretStore wrong(tmp.path(), "WRONG-passphrase");
    REQUIRE_THROWS_AS(wrong.get("k"), std::runtime_error);
}

TEST_CASE("FilesystemSecretStore detects tampering", "[storage]") {
    TempDir tmp;
    FilesystemSecretStore store(tmp.path(), "pp");
    store.put("k", to_bytes("data to protect"));

    fs::path key_file;
    for (const auto& entry : fs::directory_iterator(tmp.path())) {
        const auto name = entry.path().filename().string();
        if (!name.empty() && name[0] != '.') {
            key_file = entry.path();
            break;
        }
    }
    REQUIRE(!key_file.empty());

    // Flip a byte at offset 20 (in the ciphertext region, past magic + nonce).
    {
        std::fstream f(key_file, std::ios::in | std::ios::out | std::ios::binary);
        REQUIRE(f.good());
        f.seekg(20);
        char b;
        f.read(&b, 1);
        f.seekp(20);
        b = static_cast<char>(b ^ 0x01);
        f.write(&b, 1);
    }

    REQUIRE_THROWS_AS(store.get("k"), std::runtime_error);
}
