// Reading out a large-dataset itemized result (psi/itemized_result), end to end under a real
// two-party key: the reference answer is laid out exactly as the wrapper lays it out,
// encrypted, partially decrypted by each party, combined, decoded, and mapped back to rows. What
// comes back must be exactly the shared rows, and nothing the viewer may not read.
#include <catch2/catch_test_macros.hpp>

#include <cstring>
#include <filesystem>
#include <fstream>
#include <set>
#include <string>
#include <vector>

#include "crypto/ciphertext.h"
#include "crypto/context.h"
#include "crypto/keys.h"
#include "psi/digest.h"
#include "psi/encoder.h"
#include "psi/itemized_result.h"
#include "psi/reference.h"
#include "psi/size_class.h"
#include "psi/table.h"

using namespace fhe_toolkit;
using namespace fhe_toolkit::psi;

namespace {

constexpr const char* kDomain = "julenny-psi-v1";

std::vector<std::string> rows_for(int from, int to) {
    std::vector<std::string> out;
    for (int i = from; i < to; ++i) out.push_back("person" + std::to_string(i) + ",19" + std::to_string(50 + i % 40));
    return out;
}

std::vector<Digest> digests_of(const std::vector<std::string>& rows) {
    std::vector<Digest> out;
    for (const auto& r : rows) out.push_back(record_digest(kDomain, compose_record(r, ',', {})));
    return out;
}

/** One PSI-ITEMIZED v1 file, as the wrapper writes it: header, PAYLOAD, one archive. */
std::vector<std::byte> result_file(const crypto::Context& ctx, const crypto::PublicKey& pk,
                                   const std::vector<std::vector<std::uint32_t>>& masks,
                                   std::uint64_t cells, unsigned tables, std::uint64_t slots) {
    std::vector<crypto::Ciphertext> cts;
    for (const auto& mask : masks) {
        std::vector<std::int64_t> v(slots);
        for (std::uint64_t s = 0; s < slots; ++s) v[s] = mask[s % cells];  // prealigned: cells repeat
        cts.push_back(ctx.encrypt(pk, ctx.encode_packed(v)));
    }
    const auto payload = ctx.serialize_ciphertext_vector(cts);
    const std::string header = "PSI-ITEMIZED v1\nVIEWER A\nCELLS " + std::to_string(cells) + "\nTABLES "
        + std::to_string(tables) + "\nMASKS " + std::to_string(masks.size()) + "\nSLOTS " + std::to_string(slots)
        + "\nLAYOUT prealigned\nCIPHERTEXTS " + std::to_string(masks.size()) + "\nPAYLOAD\n";
    std::vector<std::byte> out(header.size() + payload.size());
    std::memcpy(out.data(), header.data(), header.size());
    std::memcpy(out.data() + header.size(), payload.data(), payload.size());
    return out;
}

}  // namespace

TEST_CASE("a large-dataset itemized result reads back to exactly the shared rows", "[psi][itemized][crypto]") {
    const auto spec = crypto::get_crypto_context_spec("bfv-large-psi-v1");
    REQUIRE(spec);
    crypto::Context ctx(*spec);
    const std::uint64_t slots = 32768;

    // Size 1K: 256 cells x 19 tables, prealigned, so two masks: levels 0-15, then 16-18.
    const SizeClass* size = size_class("1K");
    REQUIRE(size);
    Plan plan;
    plan.cells_total = size->cells;
    plan.levels = size->tables;
    plan.limbs = size->limbs;
    plan.count_groups = size->count_groups;
    plan.shards = size->shards;

    // The viewer (A) holds person0..299, the other party person150..449: 150 shared.
    const auto rows_a = rows_for(0, 300);
    const auto rows_b = rows_for(150, 450);
    const Table viewer = build_table(digests_of(rows_a), plan.table_params(0), Role::A, OverflowPolicy::fail);
    const Table other = build_table(digests_of(rows_b), plan.table_params(0), Role::B, OverflowPolicy::fail);
    const auto reference = reference_itemized(viewer, other);
    REQUIRE(reference.masks.size() == 2);

    const auto kp_lead = ctx.multiparty_keygen();
    const auto kp_main = ctx.multiparty_keygen(kp_lead.public_key);
    const auto file = result_file(ctx, kp_main.public_key, reference.masks, size->cells, size->tables, slots);
    REQUIRE(itemized_kind(file) == ItemizedKind::result);

    const auto partial_lead = partial_decrypt_itemized(ctx, kp_lead.secret_key, file, true);
    const auto partial_main = partial_decrypt_itemized(ctx, kp_main.secret_key, file, false);
    REQUIRE(itemized_kind(partial_lead) == ItemizedKind::partial);

    const auto masks = combine_itemized(ctx, spec->plaintext_modulus, { partial_lead, partial_main });
    CHECK(masks.masks == reference.masks);
    CHECK_THROWS_AS(combine_itemized(ctx, spec->plaintext_modulus, { partial_lead, partial_lead }), ItemizedError);

    const auto reread = itemized_masks_from_json(itemized_masks_json(masks));
    CHECK(reread.masks == masks.masks);

    // Back to rows, from the viewer's CSV, with its header row and a repeated row.
    const auto csv = std::filesystem::temp_directory_path() / "itemized_result_test_a.csv";
    {
        std::ofstream out(csv, std::ios::trunc);
        out << "name,dob\n";
        for (const auto& r : rows_a) out << r << "\n";
        out << rows_a[200] << "\n";  // a repeated row: one record, both rows match
    }
    EncodeRequest req;
    req.input = csv;
    req.separator = ',';
    req.skip_header = true;
    req.domain = kDomain;
    req.role = "A";
    req.size_class = "1K";
    const auto found = resolve_itemized_rows(req, reread);
    CHECK(found.header_line == "name,dob");
    CHECK(found.matched_records == 150);
    CHECK(found.rows.size() == 151);
    const std::set<std::string> shared(rows_b.begin(), rows_b.end());
    for (const auto& r : found.rows) CHECK(shared.count(r) == 1);

    // Not the other party's to read, and not with another size's table.
    req.role = "B";
    CHECK_THROWS_AS(resolve_itemized_rows(req, reread), ItemizedError);
    req.role = "A";
    req.size_class = "2K";
    CHECK_THROWS_AS(resolve_itemized_rows(req, reread), ItemizedError);
    std::filesystem::remove(csv);
}

TEST_CASE("itemized masks above 32768 decode to their true value, not a negative one", "[psi][itemized][crypto]") {
    // OpenFHE reports a residue above (t-1)/2 as negative; a mask with level 15 set is one.
    const auto spec = crypto::get_crypto_context_spec("bfv-large-psi-v1");
    REQUIRE(spec);
    crypto::Context ctx(*spec);
    const std::uint64_t cells = 256;
    std::vector<std::vector<std::uint32_t>> masks(1, std::vector<std::uint32_t>(cells, 0));
    masks[0][0] = 0xFFFF;
    masks[0][1] = 0x8001;
    masks[0][2] = 0x7FFF;
    const auto kp_lead = ctx.multiparty_keygen();
    const auto kp_main = ctx.multiparty_keygen(kp_lead.public_key);
    const auto file = result_file(ctx, kp_main.public_key, masks, cells, 16, 32768);
    const auto decoded = combine_itemized(ctx, spec->plaintext_modulus, {
        partial_decrypt_itemized(ctx, kp_lead.secret_key, file, true),
        partial_decrypt_itemized(ctx, kp_main.secret_key, file, false),
    });
    CHECK(decoded.masks == masks);
}
