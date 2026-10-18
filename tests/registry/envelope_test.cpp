#include <catch2/catch_test_macros.hpp>

#include <cstring>
#include <span>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "crypto/signing.h"
#include "registry/canonical_json.h"
#include "registry/envelope.h"
#include "registry/hex.h"
#include "registry/signature.h"

using namespace fhe_toolkit;
using nlohmann::json;

namespace {

std::vector<std::byte> str_to_bytes(std::string_view s) {
    std::vector<std::byte> out(s.size());
    if (!s.empty()) std::memcpy(out.data(), s.data(), s.size());
    return out;
}

// Reconstruct the platform-side signed payload from the upload body, so we
// can verify Ed25519 directly against canonical bytes. This mirrors what the
// backend's POST keysetup/messages route does: take upload body fields,
// inject permissionId (from URL), canonicalize.
std::string rebuild_canonical(const json& upload_body,
                              std::string_view permission_id) {
    json signed_obj = {
        {"messageType",   upload_body.at("messageType").get<std::string>()},
        {"payloadB64",    upload_body.at("payloadB64").get<std::string>()},
        {"permissionId",  std::string{permission_id}},
        {"round",         upload_body.at("round").get<int>()},
        {"timestamp",     upload_body.at("timestamp").get<std::string>()},
    };
    return registry::canonical_json(signed_obj);
}

}  // namespace

TEST_CASE("envelope: signed payload verifies under registered public key",
          "[registry][envelope]") {
    const auto kp = signing::generate_keypair();
    const auto payload = str_to_bytes("opaque-binary-share-bytes-for-tests");

    registry::EnvelopeFields fields;
    fields.permission_id   = "perm-xyz-123";
    fields.round           = 2;
    fields.message_type    = "relin-round1";
    fields.timestamp       = "2026-05-18T12:34:56.789Z";

    const auto details = registry::make_signed_envelope_with_details(
        std::span<const std::byte>(payload.data(), payload.size()),
        fields, kp.secret_key);

    const auto upload_body = json::parse(details.upload_json);

    SECTION("upload body contains exactly the five expected fields") {
        REQUIRE(upload_body.is_object());
        REQUIRE(upload_body.size() == 5);
        REQUIRE(upload_body.contains("round"));
        REQUIRE(upload_body.contains("messageType"));
        REQUIRE(upload_body.contains("payloadB64"));
        REQUIRE(upload_body.contains("signatureHex"));
        REQUIRE(upload_body.contains("timestamp"));
        // fromCompanyId and permissionId are NOT in the upload body; the
        // platform infers them from auth + URL.
        REQUIRE_FALSE(upload_body.contains("fromCompanyId"));
        REQUIRE_FALSE(upload_body.contains("permissionId"));
    }

    SECTION("signatureHex is 128 lowercase hex chars (64-byte Ed25519 sig)") {
        const auto sig_hex = upload_body.at("signatureHex").get<std::string>();
        REQUIRE(sig_hex.size() == 128);
        for (char c : sig_hex) {
            REQUIRE(((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')));
        }
    }

    SECTION("signature verifies against the rebuilt canonical bytes") {
        const auto canonical = rebuild_canonical(upload_body, fields.permission_id);
        REQUIRE(canonical == details.canonical_signed_payload);

        const auto sig_hex = upload_body.at("signatureHex").get<std::string>();
        const auto sig_bytes = registry::hex_decode(sig_hex);
        REQUIRE(sig_bytes.has_value());
        REQUIRE(sig_bytes->size() == 64);

        const auto canonical_bytes = str_to_bytes(canonical);
        const auto pk_bytes = std::span<const std::byte>(
            kp.public_key.bytes.data(), kp.public_key.bytes.size());

        REQUIRE(registry::verify_ed25519(
            pk_bytes,
            std::span<const std::byte>(canonical_bytes.data(), canonical_bytes.size()),
            std::span<const std::byte>(sig_bytes->data(), sig_bytes->size())));
    }

    SECTION("tampered payloadB64 breaks verification") {
        json tampered = upload_body;
        tampered["payloadB64"] = "AAAA";  // valid base64, wrong content
        const auto canonical = rebuild_canonical(tampered, fields.permission_id);
        const auto canonical_bytes = str_to_bytes(canonical);

        const auto sig_hex   = upload_body.at("signatureHex").get<std::string>();
        const auto sig_bytes = registry::hex_decode(sig_hex);
        REQUIRE(sig_bytes.has_value());

        REQUIRE_FALSE(registry::verify_ed25519(
            std::span<const std::byte>(kp.public_key.bytes.data(), kp.public_key.bytes.size()),
            std::span<const std::byte>(canonical_bytes.data(), canonical_bytes.size()),
            std::span<const std::byte>(sig_bytes->data(), sig_bytes->size())));
    }

    SECTION("tampered round number breaks verification") {
        json tampered = upload_body;
        tampered["round"] = 99;
        const auto canonical = rebuild_canonical(tampered, fields.permission_id);
        const auto canonical_bytes = str_to_bytes(canonical);

        const auto sig_hex   = upload_body.at("signatureHex").get<std::string>();
        const auto sig_bytes = registry::hex_decode(sig_hex);
        REQUIRE(sig_bytes.has_value());

        REQUIRE_FALSE(registry::verify_ed25519(
            std::span<const std::byte>(kp.public_key.bytes.data(), kp.public_key.bytes.size()),
            std::span<const std::byte>(canonical_bytes.data(), canonical_bytes.size()),
            std::span<const std::byte>(sig_bytes->data(), sig_bytes->size())));
    }
}

TEST_CASE("envelope: rejects bad input fields",
          "[registry][envelope]") {
    const auto kp = signing::generate_keypair();
    const auto payload = str_to_bytes("share");

    registry::EnvelopeFields base;
    base.permission_id   = "p";
    base.round           = 1;
    base.message_type    = "pk-share";
    base.timestamp       = "2026-05-18T00:00:00.000Z";

    SECTION("empty payload throws") {
        std::vector<std::byte> empty_payload;
        REQUIRE_THROWS_AS(
            registry::make_signed_envelope(
                std::span<const std::byte>(empty_payload.data(), 0),
                base, kp.secret_key),
            std::invalid_argument);
    }

    SECTION("round 0 throws") {
        auto fields = base;
        fields.round = 0;
        REQUIRE_THROWS_AS(
            registry::make_signed_envelope(
                std::span<const std::byte>(payload.data(), payload.size()),
                fields, kp.secret_key),
            std::invalid_argument);
    }

    SECTION("empty messageType throws") {
        auto fields = base;
        fields.message_type.clear();
        REQUIRE_THROWS_AS(
            registry::make_signed_envelope(
                std::span<const std::byte>(payload.data(), payload.size()),
                fields, kp.secret_key),
            std::invalid_argument);
    }
}

TEST_CASE("envelope: base64_std_encode matches RFC 4648 §4 vectors",
          "[registry][envelope][base64]") {
    using registry::base64_std_encode;

    auto b = [](std::string_view s) { return str_to_bytes(s); };

    // RFC 4648 test vectors (standard alphabet, with padding).
    auto bytes = b("");      auto out = base64_std_encode(std::span<const std::byte>(bytes.data(), bytes.size()));
    REQUIRE(out == "");
    bytes = b("f");          out = base64_std_encode(std::span<const std::byte>(bytes.data(), bytes.size()));
    REQUIRE(out == "Zg==");
    bytes = b("fo");         out = base64_std_encode(std::span<const std::byte>(bytes.data(), bytes.size()));
    REQUIRE(out == "Zm8=");
    bytes = b("foo");        out = base64_std_encode(std::span<const std::byte>(bytes.data(), bytes.size()));
    REQUIRE(out == "Zm9v");
    bytes = b("foob");       out = base64_std_encode(std::span<const std::byte>(bytes.data(), bytes.size()));
    REQUIRE(out == "Zm9vYg==");
    bytes = b("fooba");      out = base64_std_encode(std::span<const std::byte>(bytes.data(), bytes.size()));
    REQUIRE(out == "Zm9vYmE=");
    bytes = b("foobar");     out = base64_std_encode(std::span<const std::byte>(bytes.data(), bytes.size()));
    REQUIRE(out == "Zm9vYmFy");
}

TEST_CASE("envelope: iso8601_now_utc produces well-formed timestamp",
          "[registry][envelope]") {
    const auto ts = registry::iso8601_now_utc();
    // YYYY-MM-DDTHH:MM:SS.mmmZ  -> 24 chars exactly
    REQUIRE(ts.size() == 24);
    REQUIRE(ts[4]  == '-');
    REQUIRE(ts[7]  == '-');
    REQUIRE(ts[10] == 'T');
    REQUIRE(ts[13] == ':');
    REQUIRE(ts[16] == ':');
    REQUIRE(ts[19] == '.');
    REQUIRE(ts[23] == 'Z');
}

// ----------------------------------------------------------------------------
// Final-keys submission envelope tests.
// ----------------------------------------------------------------------------

namespace {

// Reconstruct the platform-side signed payload for the final-keys endpoint
// from the upload body, mirroring what the backend does: take {keys,
// timestamp} from the upload body, inject {permissionId}
// from auth + URL, canonicalize.
std::string rebuild_final_keys_canonical(const json& upload_body,
                                         std::string_view permission_id) {
    json signed_obj = {
        {"keys",          upload_body.at("keys")},
        {"permissionId",  std::string{permission_id}},
        {"timestamp",     upload_body.at("timestamp").get<std::string>()},
    };
    return registry::canonical_json(signed_obj);
}

}  // namespace

TEST_CASE("final-keys envelope: signed payload verifies under registered public key",
          "[registry][envelope][final-keys]") {
    const auto kp = signing::generate_keypair();

    std::vector<registry::FinalKeyRef> refs = {
        {"joint_public_key", "final-keys/perm-1/co-a/joint_public_key.bin",
         "1111111111111111111111111111111111111111111111111111111111111111"},
        {"joint_relin_key",  "final-keys/perm-1/co-a/joint_relin_key.bin",
         "2222222222222222222222222222222222222222222222222222222222222222"},
        {"eval_sum_key",     "final-keys/perm-1/co-a/eval_sum_key.bin",
         "3333333333333333333333333333333333333333333333333333333333333333"},
    };

    registry::FinalKeysEnvelopeFields fields;
    fields.permission_id   = "perm-1";
    fields.timestamp       = "2026-05-21T12:00:00.000Z";

    const auto details = registry::make_signed_final_keys_envelope_with_details(
        refs, fields, kp.secret_key);

    const auto upload_body = json::parse(details.upload_json);

    SECTION("upload body contains exactly the three expected fields") {
        REQUIRE(upload_body.is_object());
        REQUIRE(upload_body.size() == 3);
        REQUIRE(upload_body.contains("keys"));
        REQUIRE(upload_body.contains("signatureHex"));
        REQUIRE(upload_body.contains("timestamp"));
        REQUIRE_FALSE(upload_body.contains("fromCompanyId"));
        REQUIRE_FALSE(upload_body.contains("permissionId"));
    }

    SECTION("keys array is sorted alphabetically by keyType") {
        const auto& keys = upload_body.at("keys");
        REQUIRE(keys.is_array());
        REQUIRE(keys.size() == 3);
        REQUIRE(keys[0].at("keyType").get<std::string>() == "eval_sum_key");
        REQUIRE(keys[1].at("keyType").get<std::string>() == "joint_public_key");
        REQUIRE(keys[2].at("keyType").get<std::string>() == "joint_relin_key");
    }

    SECTION("signatureHex is 128 lowercase hex chars") {
        const auto sig_hex = upload_body.at("signatureHex").get<std::string>();
        REQUIRE(sig_hex.size() == 128);
        for (char c : sig_hex) {
            REQUIRE(((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')));
        }
    }

    SECTION("signature verifies against the rebuilt canonical bytes") {
        const auto canonical = rebuild_final_keys_canonical(upload_body, fields.permission_id);
        REQUIRE(canonical == details.canonical_signed_payload);

        const auto sig_hex   = upload_body.at("signatureHex").get<std::string>();
        const auto sig_bytes = registry::hex_decode(sig_hex);
        REQUIRE(sig_bytes.has_value());
        REQUIRE(sig_bytes->size() == 64);

        const auto canonical_bytes = str_to_bytes(canonical);
        REQUIRE(registry::verify_ed25519(
            std::span<const std::byte>(kp.public_key.bytes.data(), kp.public_key.bytes.size()),
            std::span<const std::byte>(canonical_bytes.data(), canonical_bytes.size()),
            std::span<const std::byte>(sig_bytes->data(), sig_bytes->size())));
    }

    SECTION("tampered sha256Hex breaks verification") {
        json tampered = upload_body;
        tampered["keys"][0]["sha256Hex"] =
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        const auto canonical = rebuild_final_keys_canonical(tampered, fields.permission_id);
        const auto canonical_bytes = str_to_bytes(canonical);

        const auto sig_hex   = upload_body.at("signatureHex").get<std::string>();
        const auto sig_bytes = registry::hex_decode(sig_hex);
        REQUIRE(sig_bytes.has_value());

        REQUIRE_FALSE(registry::verify_ed25519(
            std::span<const std::byte>(kp.public_key.bytes.data(), kp.public_key.bytes.size()),
            std::span<const std::byte>(canonical_bytes.data(), canonical_bytes.size()),
            std::span<const std::byte>(sig_bytes->data(), sig_bytes->size())));
    }
}

TEST_CASE("final-keys envelope: input order is irrelevant (pre-sort is enforced)",
          "[registry][envelope][final-keys]") {
    const auto kp = signing::generate_keypair();

    registry::FinalKeyRef rk_pk  = {"joint_public_key", "objA",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"};
    registry::FinalKeyRef rk_rel = {"joint_relin_key",  "objB",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"};
    registry::FinalKeyRef rk_sum = {"eval_sum_key",     "objC",
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"};

    registry::FinalKeysEnvelopeFields fields;
    fields.permission_id   = "perm-x";
    fields.timestamp       = "2026-05-21T12:00:00.000Z";

    // Two callers, two different input orderings, must produce byte-identical
    // canonical signed payloads and byte-identical signatures.
    const auto detA = registry::make_signed_final_keys_envelope_with_details(
        std::vector<registry::FinalKeyRef>{rk_pk, rk_rel, rk_sum}, fields, kp.secret_key);
    const auto detB = registry::make_signed_final_keys_envelope_with_details(
        std::vector<registry::FinalKeyRef>{rk_sum, rk_rel, rk_pk}, fields, kp.secret_key);
    const auto detC = registry::make_signed_final_keys_envelope_with_details(
        std::vector<registry::FinalKeyRef>{rk_rel, rk_pk, rk_sum}, fields, kp.secret_key);

    REQUIRE(detA.canonical_signed_payload == detB.canonical_signed_payload);
    REQUIRE(detA.canonical_signed_payload == detC.canonical_signed_payload);
    REQUIRE(std::equal(detA.signature.bytes.begin(), detA.signature.bytes.end(),
                       detB.signature.bytes.begin()));
    REQUIRE(std::equal(detA.signature.bytes.begin(), detA.signature.bytes.end(),
                       detC.signature.bytes.begin()));
}

TEST_CASE("final-keys envelope: rejects bad input",
          "[registry][envelope][final-keys]") {
    const auto kp = signing::generate_keypair();

    registry::FinalKeysEnvelopeFields base;
    base.permission_id   = "p";
    base.timestamp       = "2026-05-21T12:00:00.000Z";

    const auto good_sha = std::string(64, 'a');

    std::vector<registry::FinalKeyRef> good_refs = {
        {"joint_public_key", "obj1", good_sha},
        {"joint_relin_key",  "obj2", good_sha},
        {"eval_sum_key",     "obj3", good_sha},
    };

    SECTION("empty refs throws") {
        REQUIRE_THROWS_AS(
            registry::make_signed_final_keys_envelope(
                {}, base, kp.secret_key),
            std::invalid_argument);
    }


    SECTION("empty permissionId throws") {
        auto fields = base;
        fields.permission_id.clear();
        REQUIRE_THROWS_AS(
            registry::make_signed_final_keys_envelope(
                good_refs, fields, kp.secret_key),
            std::invalid_argument);
    }

    SECTION("empty timestamp throws") {
        auto fields = base;
        fields.timestamp.clear();
        REQUIRE_THROWS_AS(
            registry::make_signed_final_keys_envelope(
                good_refs, fields, kp.secret_key),
            std::invalid_argument);
    }

    SECTION("unrecognized keyType throws") {
        auto bad = good_refs;
        bad[0].key_type = "not_a_real_key_type";
        REQUIRE_THROWS_AS(
            registry::make_signed_final_keys_envelope(
                bad, base, kp.secret_key),
            std::invalid_argument);
    }

    SECTION("duplicate keyType throws") {
        std::vector<registry::FinalKeyRef> dup = {
            {"joint_public_key", "obj1", good_sha},
            {"joint_public_key", "obj2", good_sha},
        };
        REQUIRE_THROWS_AS(
            registry::make_signed_final_keys_envelope(
                dup, base, kp.secret_key),
            std::invalid_argument);
    }

    SECTION("empty objectKey throws") {
        auto bad = good_refs;
        bad[0].object_key.clear();
        REQUIRE_THROWS_AS(
            registry::make_signed_final_keys_envelope(
                bad, base, kp.secret_key),
            std::invalid_argument);
    }

    SECTION("malformed sha256Hex throws (wrong length)") {
        auto bad = good_refs;
        bad[0].sha256_hex = "abc123";
        REQUIRE_THROWS_AS(
            registry::make_signed_final_keys_envelope(
                bad, base, kp.secret_key),
            std::invalid_argument);
    }

    SECTION("malformed sha256Hex throws (uppercase hex rejected)") {
        auto bad = good_refs;
        bad[0].sha256_hex = std::string(64, 'A');
        REQUIRE_THROWS_AS(
            registry::make_signed_final_keys_envelope(
                bad, base, kp.secret_key),
            std::invalid_argument);
    }
}
