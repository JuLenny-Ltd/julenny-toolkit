#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <random>
#include <span>
#include <string>
#include <vector>

#include "psi/bundle.h"
#include "psi/digest.h"
#include "psi/reference.h"
#include "psi/table.h"

using namespace fhe_toolkit::psi;

namespace {

std::vector<Digest> digests_of(const std::string& prefix, unsigned count, unsigned from = 0) {
    std::vector<Digest> out;
    out.reserve(count);
    for (unsigned i = from; i < from + count; ++i) out.push_back(record_digest("d2-test", prefix + std::to_string(i)));
    return out;
}

// The server's own indexing, transcribed from wrapper-service/cpp/ops.cpp (psiOperands): which two
// ciphertexts it subtracts for chunk c, limb j. A test that re-derived this from the encoder would
// prove nothing; it is here to be an independent copy of what the other side does.
std::pair<std::uint64_t, std::uint64_t> server_operands(const BundleLayout& l, std::uint64_t c, std::uint64_t j) {
    if (!l.per_level) return {c * l.limbs + j, c * l.limbs + j};
    const std::uint64_t pair = c / l.blocks, block = c % l.blocks;
    const std::uint64_t ja = pair / l.tables, jb = pair % l.tables;
    return {(ja * l.blocks + block) * l.limbs + j, (jb * l.blocks + block) * l.limbs + j};
}

// Every ciphertext of one party's bundle, as slot vectors.
std::vector<std::vector<std::int64_t>> encode(const Table& t, const BundleLayout& l) {
    std::vector<std::vector<std::int64_t>> cts(l.ciphertexts, std::vector<std::int64_t>(l.slots));
    for (std::uint64_t i = 0; i < l.ciphertexts; ++i) bundle_slots(t, l, i, std::span<std::int64_t>(cts[i]));
    return cts;
}

}  // namespace

TEST_CASE("bundle_layout matches the storage form the server derives", "[psi][bundle]") {
    SECTION("prealigned while a ciphertext holds more cells than the table has") {
        const auto l = bundle_layout({.cells = 1024, .levels = 4, .limbs = 8}, 1, 32768);
        CHECK_FALSE(l.per_level);
        CHECK(std::string(l.layout_name()) == "prealigned");
        CHECK(l.blocks == 1);
        CHECK(l.chunks == 1);          // 4*4*1024 = 16384 positions, one 32768-slot chunk
        CHECK(l.ciphertexts == 8);     // chunks * limbs
    }
    SECTION("per-level from the cell count alone, not a choice") {
        const auto l = bundle_layout({.cells = 65536, .levels = 3, .limbs = 8}, 1, 32768);
        CHECK(l.per_level);
        CHECK(l.blocks == 2);
        CHECK(l.chunks == 18);         // T^2 * blocks
        CHECK(l.ciphertexts == 48);    // T * blocks * limbs
    }
    SECTION("the boundary: cells == slots is per-level") {
        const auto l = bundle_layout({.cells = 512, .levels = 2, .limbs = 1}, 1, 512);
        CHECK(l.per_level);
        CHECK(l.blocks == 1);
        CHECK(l.ciphertexts == 2);
    }
    SECTION("several chunks when the positions exceed one ciphertext") {
        const auto l = bundle_layout({.cells = 256, .levels = 8, .limbs = 2}, 1, 512);
        CHECK_FALSE(l.per_level);
        CHECK(l.chunks == 32);         // ceil(8*8*256 / 512)
        CHECK(l.ciphertexts == 64);
    }
}

TEST_CASE("bundle_layout refuses what the server would refuse", "[psi][bundle]") {
    const TableParams ok{.cells = 1024, .levels = 4, .limbs = 8};
    CHECK_THROWS_AS(bundle_layout({.cells = 1000, .levels = 4, .limbs = 8}, 1, 512), std::invalid_argument);
    CHECK_THROWS_AS(bundle_layout({.cells = 1024, .levels = 0, .limbs = 8}, 1, 512), std::invalid_argument);
    CHECK_THROWS_AS(bundle_layout({.cells = 1024, .levels = 4, .limbs = 0}, 1, 512), std::invalid_argument);
    CHECK_THROWS_AS(bundle_layout({.cells = 1024, .levels = 4, .limbs = 15}, 1, 512), std::invalid_argument);
    CHECK_THROWS_AS(bundle_layout(ok, 3, 512), std::invalid_argument);       // GROUPS not a power of two
    CHECK_THROWS_AS(bundle_layout(ok, 2048, 32768), std::invalid_argument);  // GROUPS above CELLS
    CHECK_THROWS_AS(bundle_layout(ok, 1024, 512), std::invalid_argument);    // GROUPS above SLOTS
    CHECK_THROWS_AS(bundle_layout(ok, 1, 1000), std::invalid_argument);      // SLOTS not a power of two
    CHECK_NOTHROW(bundle_layout(ok, 512, 512));
}

TEST_CASE("the header is the nine lines the server parses", "[psi][bundle]") {
    const auto l = bundle_layout({.cells = 1024, .levels = 4, .limbs = 8}, 2, 32768);
    CHECK(bundle_header(l, Role::A) ==
          "PSI-TABLE v1\nROLE A\nCELLS 1024\nTABLES 4\nLIMBS 8\nGROUPS 2\nSLOTS 32768\n"
          "LAYOUT prealigned\nCIPHERTEXTS 8\nPAYLOAD\n");
    CHECK(bundle_header(bundle_layout({.cells = 512, .levels = 2, .limbs = 3}, 1, 512), Role::B) ==
          "PSI-TABLE v1\nROLE B\nCELLS 512\nTABLES 2\nLIMBS 3\nGROUPS 1\nSLOTS 512\n"
          "LAYOUT per-level\nCIPHERTEXTS 6\nPAYLOAD\n");
}

// The point of the whole module: when the server pairs slots the way it does, the values it finds
// are the limbs of the same cell at each party's own level - and counting the pairs whose limbs all
// agree gives the plaintext oracle's answer.
TEST_CASE("the server's pairing sees the cells the design says, and counts what the oracle counts",
          "[psi][bundle]") {
    // Record counts are kept well under each table's capacity, so build_table never drops and the
    // comparison below is over a complete set (OverflowPolicy::fail makes a miscount loud).
    struct Case { std::uint64_t cells; unsigned levels, limbs; std::uint64_t slots; unsigned shared, only; };
    const std::vector<Case> cases = {
        {64, 3, 2, 512, 10, 5},      // prealigned, one chunk, padding at the end
        {256, 4, 2, 512, 30, 15},    // prealigned, several chunks
        {512, 2, 3, 512, 20, 10},    // per-level, one block
        {1024, 2, 2, 512, 30, 15},   // per-level, two blocks
    };
    for (const auto& c : cases) {
        INFO("cells " << c.cells << " tables " << c.levels << " limbs " << c.limbs << " slots " << c.slots);
        const TableParams params{.cells = c.cells, .levels = c.levels, .limbs = c.limbs};
        auto shared = digests_of("shared", c.shared);
        auto only_a = digests_of("a-only", c.only);
        auto only_b = digests_of("b-only", c.only);
        std::vector<Digest> rows_a = shared, rows_b = shared;
        rows_a.insert(rows_a.end(), only_a.begin(), only_a.end());
        rows_b.insert(rows_b.end(), only_b.begin(), only_b.end());
        const Table a = build_table(rows_a, params, Role::A, OverflowPolicy::fail);
        const Table b = build_table(rows_b, params, Role::B, OverflowPolicy::fail);

        const auto l = bundle_layout(params, 1, c.slots);
        const auto cts_a = encode(a, l), cts_b = encode(b, l);
        REQUIRE(cts_a.size() == l.ciphertexts);

        std::uint64_t matches = 0, compared = 0, padding = 0;
        for (std::uint64_t chunk = 0; chunk < l.chunks; ++chunk) {
            for (std::uint64_t s = 0; s < l.slots; ++s) {
                // What this slot of this chunk stands for, per the layout contract.
                std::uint64_t cell = 0, ja = 0, jb = 0;
                if (l.per_level) {
                    const std::uint64_t pair = chunk / l.blocks, block = chunk % l.blocks;
                    ja = pair / l.tables; jb = pair % l.tables; cell = block * l.slots + s;
                } else {
                    const std::uint64_t pos = chunk * l.slots + s;
                    if (pos >= l.tables * l.tables * l.cells) {  // padding: this role's sentinel, never a match
                        for (std::uint64_t j = 0; j < l.limbs; ++j) {
                            const auto ops = server_operands(l, chunk, j);
                            CHECK(cts_a[ops.first][s] == sentinel(Role::A, c.limbs)[j]);
                            CHECK(cts_b[ops.second][s] == sentinel(Role::B, c.limbs)[j]);
                        }
                        ++padding;
                        continue;
                    }
                    const std::uint64_t pair = pos / l.cells;
                    ja = pair / l.tables; jb = pair % l.tables; cell = pos % l.cells;
                }
                bool all_equal = true;
                for (std::uint64_t j = 0; j < l.limbs; ++j) {
                    const auto ops = server_operands(l, chunk, j);
                    const std::int64_t va = cts_a[ops.first][s], vb = cts_b[ops.second][s];
                    // Each side's slot is its own level's limb of that cell.
                    REQUIRE(va == a.limb_at(static_cast<unsigned>(ja), static_cast<unsigned>(j), cell));
                    REQUIRE(vb == b.limb_at(static_cast<unsigned>(jb), static_cast<unsigned>(j), cell));
                    if (va != vb) all_equal = false;
                }
                ++compared;
                if (all_equal) ++matches;
            }
        }
        CHECK(compared == l.tables * l.tables * l.cells);
        CHECK(matches == reference_count(a, b).matches);
        if (!l.per_level && l.chunks * l.slots > l.tables * l.tables * l.cells) CHECK(padding > 0);
    }
}

TEST_CASE("bundle_slots refuses a table that is not the one the layout describes", "[psi][bundle]") {
    const TableParams params{.cells = 64, .levels = 2, .limbs = 2};
    const Table t = build_table(digests_of("x", 10), params, Role::A, OverflowPolicy::fail);
    const auto l = bundle_layout(params, 1, 512);
    std::vector<std::int64_t> slots(l.slots);
    CHECK_NOTHROW(bundle_slots(t, l, 0, std::span<std::int64_t>(slots)));
    CHECK_THROWS_AS(bundle_slots(t, l, l.ciphertexts, std::span<std::int64_t>(slots)), std::invalid_argument);
    std::vector<std::int64_t> wrong(l.slots - 1);
    CHECK_THROWS_AS(bundle_slots(t, l, 0, std::span<std::int64_t>(wrong)), std::invalid_argument);
    const auto other = bundle_layout({.cells = 128, .levels = 2, .limbs = 2}, 1, 512);
    std::vector<std::int64_t> other_slots(other.slots);
    CHECK_THROWS_AS(bundle_slots(t, other, 0, std::span<std::int64_t>(other_slots)), std::invalid_argument);
}

// Dynamic T: per-level bundles whose TABLES differ. The server pairs A's level ja with B's
// level jb, ja = pair / T_B and jb = pair % T_B, over T_A * T_B * blocks chunks.
TEST_CASE("per-level bundles with unequal TABLES pair every level, and count what the oracle counts",
          "[psi][bundle]") {
    // Each side takes the levels its own data needs (fullest_cell), plus `spare` empty ones.
    struct Case { std::uint64_t cells; unsigned spare_a, spare_b, limbs; std::uint64_t slots; unsigned shared, only_a, only_b; };
    const std::vector<Case> cases = {
        {512, 0, 2, 2, 512, 40, 20, 250},    // one block, B fuller and with empty levels
        {1024, 1, 0, 3, 512, 200, 600, 40},  // two blocks, A fuller
    };
    for (const auto& c : cases) {
        auto rows_a = digests_of("shared", c.shared), rows_b = rows_a;
        const auto extra_a = digests_of("a-only", c.only_a), extra_b = digests_of("b-only", c.only_b);
        rows_a.insert(rows_a.end(), extra_a.begin(), extra_a.end());
        rows_b.insert(rows_b.end(), extra_b.begin(), extra_b.end());
        const TableParams pa{.cells = c.cells, .levels = static_cast<unsigned>(fullest_cell(rows_a, c.cells)) + c.spare_a,
                             .limbs = c.limbs};
        const TableParams pb{.cells = c.cells, .levels = static_cast<unsigned>(fullest_cell(rows_b, c.cells)) + c.spare_b,
                             .limbs = c.limbs};
        const struct { unsigned ta, tb; } c2{pa.levels, pb.levels};
        INFO("cells " << c.cells << " T_A " << c2.ta << " T_B " << c2.tb);
        REQUIRE(c2.ta != c2.tb);
        const Table a = build_table(rows_a, pa, Role::A, OverflowPolicy::fail);
        const Table b = build_table(rows_b, pb, Role::B, OverflowPolicy::fail);
        const auto la = bundle_layout(pa, 1, c.slots), lb = bundle_layout(pb, 1, c.slots);
        REQUIRE(la.per_level);
        REQUIRE(la.ciphertexts == c2.ta * la.blocks * c.limbs);
        REQUIRE(lb.ciphertexts == c2.tb * lb.blocks * c.limbs);
        const auto cts_a = encode(a, la), cts_b = encode(b, lb);

        std::uint64_t matches = 0, compared = 0;
        const std::uint64_t chunks = std::uint64_t{c2.ta} * c2.tb * la.blocks;
        for (std::uint64_t chunk = 0; chunk < chunks; ++chunk) {
            const std::uint64_t pair = chunk / la.blocks, block = chunk % la.blocks;
            const std::uint64_t ja = pair / c2.tb, jb = pair % c2.tb;  // transcribed from psiOperands
            for (std::uint64_t s = 0; s < c.slots; ++s) {
                bool all_equal = true;
                for (std::uint64_t j = 0; j < c.limbs; ++j) {
                    const std::int64_t va = cts_a[(ja * la.blocks + block) * c.limbs + j][s];
                    const std::int64_t vb = cts_b[(jb * lb.blocks + block) * c.limbs + j][s];
                    const std::uint64_t cell = block * c.slots + s;
                    REQUIRE(va == a.limb_at(static_cast<unsigned>(ja), static_cast<unsigned>(j), cell));
                    REQUIRE(vb == b.limb_at(static_cast<unsigned>(jb), static_cast<unsigned>(j), cell));
                    if (va != vb) all_equal = false;
                }
                ++compared;
                if (all_equal) ++matches;
            }
        }
        CHECK(compared == std::uint64_t{c2.ta} * c2.tb * c.cells);
        CHECK(matches == reference_count(a, b).matches);
    }
}
