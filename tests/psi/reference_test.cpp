#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <algorithm>
#include <bit>
#include <cmath>
#include <cstdint>
#include <iterator>
#include <map>
#include <optional>
#include <random>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "psi/digest.h"
#include "psi/reference.h"
#include "psi/table.h"

using namespace fhe_toolkit::psi;

namespace {

constexpr std::string_view kDomain = "julenny/joint-record-overlap/exact/v1";

std::vector<Digest> hashed(const std::string& prefix, std::uint64_t first, std::uint64_t count) {
    std::vector<Digest> out;
    out.reserve(count);
    for (std::uint64_t i = first; i < first + count; ++i) {
        out.push_back(record_digest(kDomain, prefix + std::to_string(i)));
    }
    return out;
}

// A digest at a chosen address with a pseudo-random body.
Digest at_address(std::uint32_t address, std::uint64_t id) {
    Digest d = sha256("synthetic-" + std::to_string(id));
    for (unsigned b = 0; b < address_bytes; ++b) d[b] = static_cast<std::uint8_t>(address >> (8 * b));
    return d;
}

std::vector<Digest> sorted_set(const std::vector<Digest>& v) {
    const std::set<Digest> s(v.begin(), v.end());
    return { s.begin(), s.end() };
}

std::vector<Digest> intersect(const std::vector<Digest>& x, const std::vector<Digest>& y) {
    std::vector<Digest> out;
    std::set_intersection(x.begin(), x.end(), y.begin(), y.end(), std::back_inserter(out));
    return out;
}

std::vector<Digest> minus(const std::vector<Digest>& x, const std::vector<Digest>& y) {
    std::vector<Digest> out;
    std::set_difference(x.begin(), x.end(), y.begin(), y.end(), std::back_inserter(out));
    return out;
}

Table build(const std::vector<Digest>& in, const TableParams& p, Role role) {
    return build_table(in, p, role, OverflowPolicy::drop);
}

// Cross-party pairs no circuit can tell apart: DIFFERENT records, same cell,
// equal stored signature - design §2.3's accepted 2^-S false-match mode. Found
// from the digests directly (position + stored_signature), not through the
// reference's comparison loop. `expected` is the model: 2^-16k per such pair.
struct FalsePairs {
    std::vector<Digest> a_side, b_side;  // each sorted
    double              expected = 0.0;
};
FalsePairs false_pairs(const std::vector<Digest>& placed_a, const std::vector<Digest>& placed_b,
                       const TableParams& p) {
    std::map<std::uint64_t, std::vector<const Digest*>> b_by_cell;
    for (const auto& d : placed_b) b_by_cell[position(d, p.cells)].push_back(&d);
    const double per_pair = std::ldexp(1.0, -16 * static_cast<int>(p.limbs));
    FalsePairs out;
    for (const auto& x : placed_a) {
        const auto it = b_by_cell.find(position(x, p.cells));
        if (it == b_by_cell.end()) continue;
        const auto sx = stored_signature(x, p.limbs);
        for (const Digest* y : it->second) {
            if (*y == x) continue;
            out.expected += per_pair;
            if (stored_signature(*y, p.limbs) == sx) {
                out.a_side.push_back(x);
                out.b_side.push_back(*y);
            }
        }
    }
    std::sort(out.a_side.begin(), out.a_side.end());
    std::sort(out.b_side.begin(), out.b_side.end());
    return out;
}

std::vector<Digest> united(const std::vector<Digest>& x, const std::vector<Digest>& y) {
    std::vector<Digest> out;
    std::set_union(x.begin(), x.end(), y.begin(), y.end(), std::back_inserter(out));
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

// What every viewer slot's itemized indicator must be, straight from the digests:
// how many of the other party's placed records sit in the same cell with the same
// stored value. 0/1 - unless a false pair lands on a record the other side really
// holds, when it is 2.
std::vector<std::uint32_t> expected_indicators(const Table& viewer, const std::vector<Digest>& other_placed) {
    const auto& p = viewer.params();
    std::map<std::uint64_t, std::vector<std::vector<std::uint16_t>>> by_cell;
    for (const auto& d : other_placed) by_cell[position(d, p.cells)].push_back(stored_signature(d, p.limbs));
    std::vector<std::uint32_t> out(static_cast<std::size_t>(p.levels * p.cells), 0);
    for (unsigned level = 0; level < p.levels; ++level) {
        for (std::uint64_t cell = 0; cell < p.cells; ++cell) {
            const auto occ = viewer.occupant(level, cell);
            const auto it = by_cell.find(cell);
            if (occ == Table::empty || it == by_cell.end()) continue;
            const auto sv = stored_signature(viewer.records()[occ], p.limbs);
            for (const auto& s : it->second) out[level * p.cells + cell] += s == sv ? 1 : 0;
        }
    }
    return out;
}

// The masks those indicators must pack into: Σ_j 2^(j mod 16) · ind mod t.
std::vector<std::vector<std::uint32_t>> expected_masks(const std::vector<std::uint32_t>& ind,
                                                       const TableParams& p) {
    std::vector<std::vector<std::uint32_t>> out((p.levels + 15) / 16,
                                                std::vector<std::uint32_t>(p.cells, 0));
    for (unsigned level = 0; level < p.levels; ++level) {
        for (std::uint64_t cell = 0; cell < p.cells; ++cell) {
            auto& v = out[level / 16][cell];
            v = static_cast<std::uint32_t>((std::uint64_t{v} + (std::uint64_t{1} << (level % 16))
                                            * ind[level * p.cells + cell]) % plaintext_modulus);
        }
    }
    return out;
}

}  // namespace

// ---------------------------------------------------------------------------
// The circuit's arithmetic
// ---------------------------------------------------------------------------

TEST_CASE("the Fermat indicator is exactly [d == 0], over every residue mod t", "[psi][reference]") {
    std::uint32_t ones = 0;
    for (std::uint32_t d = 0; d < plaintext_modulus; ++d) {
        const auto z = fermat_indicator(d);
        if (d == 0) {
            REQUIRE(z == 1);
        } else if (z != 0) {
            FAIL("1 - d^(t-1) = " << z << " at d = " << d);
        }
        ones += z;
    }
    REQUIRE(ones == 1);
    CHECK_THROWS_AS(fermat_indicator(plaintext_modulus), std::out_of_range);

    // A limb difference is 0 mod t only when the limbs are equal: |a - b| <= 65535 < t.
    for (const auto& [a, b] : { std::pair{ 0u, 65535u }, std::pair{ 65535u, 0u }, std::pair{ 1u, 0u },
                                std::pair{ 32768u, 32767u } }) {
        REQUIRE(fermat_indicator((a + plaintext_modulus - b) % plaintext_modulus) == 0);
    }
}

// Pinned to what OpenFHE 1.5 actually returned (scratch/psi-spike/B3-RESULTS.md §1):
// encode 32768 -> 32768, 32769 -> -32768, 65535 -> -2, 65536 -> -1;
// an EvalSum whose true total was 40960 decrypted to -24577.
TEST_CASE("centered() reproduces OpenFHE's measured decode, and residue() inverts it",
          "[psi][reference]") {
    CHECK(centered(1) == 1);
    CHECK(centered(32767) == 32767);
    CHECK(centered(32768) == 32768);
    CHECK(centered(32769) == -32768);
    CHECK(centered(65535) == -2);
    CHECK(centered(65536) == -1);
    CHECK(centered(40960) == -24577);
    for (std::uint32_t r = 0; r < plaintext_modulus; ++r) {
        if (residue(centered(r)) != r) FAIL("residue(centered(" << r << ")) != " << r);
    }
}

// ---------------------------------------------------------------------------
// The count, against std::set_intersection
// ---------------------------------------------------------------------------

// Thousands of random cases across shapes and parameters. The expected answer
// comes from std::set_intersection over the input rows - no tables, no hashing
// structure, no shared code with the reference.
TEST_CASE("the reference count is exactly |A ∩ B|, over thousands of random cases",
          "[psi][reference]") {
    enum Shape { random_sets, both_empty, a_empty, b_empty, identical, disjoint, subset, near_ceiling, shapes };
    const char* shape_names[] = { "random", "both empty", "A empty", "B empty", "identical",
                                  "disjoint", "subset", "overflow near the 1 % ceiling" };
    constexpr unsigned wanted = 3000;
    unsigned run = 0, refused = 0, with_drops = 0, exact_cases = 0;
    unsigned per_shape[shapes] = {};
    std::uint64_t false_found = 0;
    double false_expected = 0.0;
    unsigned corrupted_masks = 0;

    for (std::uint64_t c = 0; run < wanted; ++c) {
        REQUIRE(c < 3 * wanted);  // refusals must not starve the test
        std::mt19937_64 rng(c);
        auto uniform = [&rng](std::uint64_t lo, std::uint64_t hi) {  // inclusive
            return std::uniform_int_distribution<std::uint64_t>(lo, hi)(rng);
        };
        const auto shape = static_cast<Shape>(c % shapes);
        const unsigned k_choices[] = { 1, 2, 3, 4, 8 };
        TableParams p{ .cells = std::uint64_t{1} << uniform(0, 10),
                       .levels = static_cast<unsigned>(uniform(1, 6)),
                       .limbs = k_choices[uniform(0, 4)] };

        // Up to T/8 records per cell per side: dense enough to collide, sparse
        // enough that B2 accepts most tables. near_ceiling pushes into overflow.
        const std::uint64_t side = std::max<std::uint64_t>(1, p.cells * p.levels / 8);
        const std::uint64_t half = std::max<std::uint64_t>(1, side / 2);
        std::uint64_t n_shared = 0, n_a = 0, n_b = 0;  // n_a / n_b: records only on that side
        switch (shape) {
            case random_sets: n_shared = uniform(0, half); n_a = uniform(0, half); n_b = uniform(0, half); break;
            case both_empty: break;
            case a_empty: n_b = uniform(1, side); break;
            case b_empty: n_a = uniform(1, side); break;
            case identical: n_shared = uniform(1, side); break;
            case disjoint: n_a = uniform(1, half); n_b = uniform(1, half); break;
            case subset: n_shared = uniform(1, half); n_b = uniform(1, half); break;
            case near_ceiling: {
                // (T, lambda) with a Poisson drop rate of ~0.2-0.4 %: drops happen,
                // mostly under the 1 % ceiling.
                const std::pair<unsigned, double> points[] = { { 3, 0.5 }, { 4, 1.0 }, { 5, 1.5 } };
                const auto [levels, lambda] = points[uniform(0, 2)];
                p.cells = std::uint64_t{1} << uniform(9, 11);
                p.levels = levels;
                const auto n = static_cast<std::uint64_t>(lambda * static_cast<double>(p.cells));
                n_shared = n / 2; n_a = n - n_shared; n_b = n - n_shared;
                break;
            }
            case shapes: break;
        }

        const std::string tag = "c" + std::to_string(c) + "-";
        const auto shared = hashed(tag + "s-", 0, n_shared);
        std::vector<Digest> rows_a = shared, rows_b = shared;
        const auto only_a = hashed(tag + "a-", 0, n_a), only_b = hashed(tag + "b-", 0, n_b);
        rows_a.insert(rows_a.end(), only_a.begin(), only_a.end());
        rows_b.insert(rows_b.end(), only_b.begin(), only_b.end());
        for (auto* rows : { &rows_a, &rows_b }) {  // repeated rows on both sides (Q8)
            const auto repeats = rows->empty() ? 0 : uniform(0, rows->size() / 4);
            for (std::uint64_t i = 0; i < repeats; ++i) rows->push_back((*rows)[uniform(0, rows->size() - 1)]);
            std::shuffle(rows->begin(), rows->end(), rng);
        }

        CAPTURE(c, shape_names[shape], p.cells, p.levels, p.limbs, rows_a.size(), rows_b.size());
        std::optional<Table> ta, tb;
        try {
            ta.emplace(build(rows_a, p, Role::A));
            tb.emplace(build(rows_b, p, Role::B));
        } catch (const TableOverflow&) {
            ++refused;  // over the 1 % ceiling: B2 refuses, so there is nothing to compare
            continue;
        }

        const auto set_a = sorted_set(rows_a), set_b = sorted_set(rows_b);
        const auto truth = intersect(set_a, set_b);  // |A ∩ B|, independently
        const auto placed_a = minus(set_a, ta->dropped()), placed_b = minus(set_b, tb->dropped());
        const auto survived = intersect(placed_a, placed_b);
        const auto fp = false_pairs(placed_a, placed_b, p);
        const auto r = reference_count(*ta, *tb);
        CAPTURE(survived.size(), fp.a_side.size());

        // Exactly: every shared record both sides placed, plus every false pair.
        // The shared part is never more than |A ∩ B| (drops cannot create
        // matches) and short of it by at most the drops; with no drops and no
        // false pairs the count IS |A ∩ B|.
        REQUIRE(r.matches == survived.size() + fp.a_side.size());
        REQUIRE(survived.size() <= truth.size());
        REQUIRE(truth.size() - survived.size() <= ta->dropped().size() + tb->dropped().size());
        if (ta->dropped().empty() && tb->dropped().empty() && fp.a_side.empty()) {
            REQUIRE(r.matches == truth.size());
        }
        REQUIRE(r.count_mod_t == r.matches % plaintext_modulus);
        if (fp.a_side.empty()) {
            for (const auto v : r.per_cell) REQUIRE(v <= p.levels);  // at most T records per cell match
        }

        // The itemized variant, in each party's layout: every indicator and every
        // mask against the digests directly. When every indicator is 0/1, the
        // masks resolve to exactly the records that party placed and the other
        // side also placed (plus that party's half of any false pair).
        for (const Table* viewer : { &*ta, &*tb }) {
            const bool is_a = viewer == &*ta;
            const Table& other = is_a ? *tb : *ta;
            const auto it = reference_itemized(*viewer, other);
            const auto want = expected_indicators(*viewer, is_a ? placed_b : placed_a);
            REQUIRE(it.indicators == want);
            REQUIRE(it.masks == expected_masks(want, p));
            if (std::all_of(want.begin(), want.end(), [](auto v) { return v <= 1; })) {
                std::uint64_t bits = 0;
                for (const auto& mask : it.masks) {
                    for (const auto v : mask) bits += static_cast<std::uint64_t>(std::popcount(v));
                }
                REQUIRE(bits == r.matches);
                REQUIRE(resolve_matches(*viewer, it.masks) == united(survived, is_a ? fp.a_side : fp.b_side));
            } else {
                // A false pair landed on a record the other side really holds: that
                // slot's indicator is 2, and 2 * 2^j carries into bit j+1. Needs a
                // 2^-16k coincidence, so it only shows up in the k = 1 cases.
                REQUIRE(!fp.a_side.empty());
                ++corrupted_masks;
            }
        }

        ++run;
        ++per_shape[shape];
        with_drops += !ta->dropped().empty() || !tb->dropped().empty();
        false_found += fp.a_side.size();
        false_expected += fp.expected;
        exact_cases += fp.a_side.empty() && r.matches == truth.size();
    }

    // The false matches that did occur are the ones the 2^-S model predicts:
    // a Poisson count against its expectation, 5 sigma.
    CAPTURE(run, refused, with_drops, exact_cases, false_found, false_expected, corrupted_masks);
    REQUIRE(std::abs(static_cast<double>(false_found) - false_expected) <= 5.0 * std::sqrt(false_expected) + 1.0);
    for (unsigned s = 0; s < shapes; ++s) {
        CAPTURE(shape_names[s], per_shape[s]);
        REQUIRE(per_shape[s] >= wanted / shapes / 2);
    }
    REQUIRE(with_drops >= 100);  // the lower-bound half of the property is really exercised
}

TEST_CASE("repeated rows do not inflate the count", "[psi][reference]") {
    const TableParams p{ .cells = 1 << 10, .levels = 6, .limbs = 8 };
    const auto shared = hashed("dup-", 0, 400);
    std::vector<Digest> rows_a, rows_b;
    for (int copy = 0; copy < 3; ++copy) rows_a.insert(rows_a.end(), shared.begin(), shared.end());
    for (int copy = 0; copy < 5; ++copy) rows_b.insert(rows_b.end(), shared.begin(), shared.end());
    const auto r = reference_count(build(rows_a, p, Role::A), build(rows_b, p, Role::B));
    REQUIRE(r.matches == 400);  // not 1 200, 2 000 or 6 000
}

// ---------------------------------------------------------------------------
// What can and cannot match
// ---------------------------------------------------------------------------

TEST_CASE("empty cells never match, over whole tables of sentinels", "[psi][reference]") {
    const std::uint64_t cells = GENERATE(1u, 64u, 1u << 12);
    const unsigned levels = GENERATE(1u, 5u, 17u);
    const unsigned limbs = GENERATE(1u, 8u);
    const TableParams p{ .cells = cells, .levels = levels, .limbs = limbs };
    CAPTURE(cells, levels, limbs);

    const auto empty_a = build({}, p, Role::A);
    const auto empty_b = build({}, p, Role::B);
    const auto r = reference_count(empty_a, empty_b);
    REQUIRE(r.matches == 0);
    REQUIRE(std::all_of(r.per_cell.begin(), r.per_cell.end(), [](auto v) { return v == 0; }));
    const auto it = reference_itemized(empty_a, empty_b);
    for (const auto& mask : it.masks) REQUIRE(std::all_of(mask.begin(), mask.end(), [](auto v) { return v == 0; }));

    // One side with a record in every cell, the other all sentinels.
    std::vector<Digest> one_per_cell;
    for (std::uint32_t cell = 0; cell < cells; ++cell) one_per_cell.push_back(at_address(cell, cell));
    const auto full_b = build_table(one_per_cell, p, Role::B, OverflowPolicy::fail);
    REQUIRE(reference_count(empty_a, full_b).matches == 0);
    const auto full_a = build_table(one_per_cell, p, Role::A, OverflowPolicy::fail);
    REQUIRE(reference_count(full_a, empty_b).matches == 0);
}

// The AND over limbs is where a sloppy circuit would leak false positives, and
// random data cannot exercise it: two random signatures agree on k-1 limbs with
// probability ~2^-16(k-1). So build the cases: two different records in the same
// cell whose stored signatures differ in exactly ONE limb, at every position.
TEST_CASE("records differing in exactly one limb, at any position, never match", "[psi][reference]") {
    const unsigned k = GENERATE(1u, 2u, 4u, 8u);
    const TableParams p{ .cells = 16, .levels = 2, .limbs = k };
    const Digest x = at_address(7, 1);
    for (unsigned j = 0; j < k; ++j) {
        Digest y = x;
        y[signature_offset + 2 * j] ^= 0x01;  // flip the low bit of limb j only
        REQUIRE(position(y, p.cells) == position(x, p.cells));
        CAPTURE(k, j);
        REQUIRE(reference_count(build({ x }, p, Role::A), build({ y }, p, Role::B)).matches == 0);
        REQUIRE(reference_count(build({ x }, p, Role::A), build({ x, y }, p, Role::B)).matches == 1);
    }
}

// The one false positive the design accepts (§2.3): different records whose
// stored signatures agree. The reference reports it, as the circuit will - it
// does not quietly compare full digests.
TEST_CASE("different records with equal stored signatures do match (the 2^-S mode)",
          "[psi][reference]") {
    const TableParams p{ .cells = 16, .levels = 2, .limbs = 4 };
    const Digest x = at_address(3, 1);
    Digest y = x;
    y[digest_bytes - 1] ^= 0x01;  // beyond the 4 stored limbs
    REQUIRE(x != y);
    REQUIRE(reference_count(build({ x }, p, Role::A), build({ y }, p, Role::B)).matches == 1);
}

// ---------------------------------------------------------------------------
// Itemized masks
// ---------------------------------------------------------------------------

TEST_CASE("itemized masks mark exactly the matching (level, cell) pairs, for T beyond 16",
          "[psi][reference]") {
    const unsigned levels = GENERATE(1u, 16u, 17u, 33u);
    const TableParams p{ .cells = 8, .levels = levels, .limbs = 8 };
    // The viewer's table is full to the top level in every cell; the other party
    // holds every second of those records.
    std::vector<Digest> rows_v, rows_o;
    for (std::uint32_t cell = 0; cell < p.cells; ++cell) {
        for (unsigned i = 0; i < levels; ++i) {
            const auto d = at_address(cell, std::uint64_t{cell} * 1000 + i);
            rows_v.push_back(d);
            if (i % 2 == 0) rows_o.push_back(d);
        }
    }
    const auto viewer = build_table(rows_v, p, Role::B, OverflowPolicy::fail);
    const auto other = build_table(rows_o, p, Role::A, OverflowPolicy::fail);
    const auto it = reference_itemized(viewer, other);
    CAPTURE(levels);

    REQUIRE(it.masks.size() == (levels + 15) / 16);
    const std::set<Digest> held_by_other(rows_o.begin(), rows_o.end());
    unsigned top_level_matches = 0;
    for (unsigned level = 0; level < levels; ++level) {
        for (std::uint64_t cell = 0; cell < p.cells; ++cell) {
            const auto occ = viewer.occupant(level, cell);
            REQUIRE(occ != Table::empty);
            const bool should = held_by_other.count(viewer.records()[occ]) > 0;
            const bool bit = (it.masks[level / 16][cell] >> (level % 16)) & 1u;
            CAPTURE(level, cell);
            REQUIRE(bit == should);
            REQUIRE(it.indicators[level * p.cells + cell] == (should ? 1u : 0u));
            top_level_matches += should && level == levels - 1;
        }
    }
    for (const auto& mask : it.masks) {
        for (const auto v : mask) REQUIRE(v < (1u << 16));  // 16 bits never wrap mod t
    }
    REQUIRE(top_level_matches > 0);  // the last bit of the last mask is exercised
    REQUIRE(resolve_matches(viewer, it.masks) == sorted_set(rows_o));
}

// ---------------------------------------------------------------------------
// The ceiling: what the single-slot count circuit (§2.3) actually decrypts
// ---------------------------------------------------------------------------

// Not a property the design wants - a property the design HAS. The reference's
// job is to predict what decrypts, so it predicts this too. See B3-RESULTS.md.
TEST_CASE("the single-slot count wraps: centered above 32768, lost above 65536", "[psi][reference]") {
    struct Case { std::uint64_t shared; std::uint64_t cells; std::int64_t decrypts; };
    const Case cs = GENERATE(Case{ 30'000, 1 << 16, 30'000 },    // fine
                             Case{ 40'000, 1 << 16, -25'537 },   // decodes negative; recoverable
                             Case{ 70'000, 1 << 17, 4'463 });    // wrapped; the count is gone
    const TableParams p{ .cells = cs.cells, .levels = 8, .limbs = 8 };
    const auto rows = hashed("wrap-", 0, cs.shared);
    const auto ta = build_table(rows, p, Role::A, OverflowPolicy::fail);
    const auto tb = build_table(rows, p, Role::B, OverflowPolicy::fail);
    const auto r = reference_count(ta, tb);  // one group: the single-slot form
    CAPTURE(cs.shared);
    REQUIRE(r.matches == cs.shared);
    REQUIRE(centered(r.count_mod_t) == cs.decrypts);
    REQUIRE(residue(cs.decrypts) == r.count_mod_t);
    REQUIRE(r.group_wrapped == (cs.shared >= plaintext_modulus));

    SECTION("grouping resolves it, including the case the single slot loses") {
        const auto grouped = reference_count(ta, tb, 4);
        REQUIRE(grouped.group_sums.size() == 4);
        REQUIRE_FALSE(grouped.group_wrapped);
        for (const auto v : grouped.group_sums) REQUIRE(v < plaintext_modulus);
        REQUIRE(count_from_groups(grouped.group_sums) == cs.shared);  // exact, at every size
    }
}

// group(cell) = cell mod L, which is what rotating by the strides L, 2L, ... N/2
// leaves in slot i. Checked against the per-cell accumulator directly.
TEST_CASE("the grouped count splits the total by cell mod L, and the parts add up",
          "[psi][reference]") {
    const unsigned groups = GENERATE(1u, 2u, 4u, 16u);
    const TableParams p{ .cells = 1 << 10, .levels = 8, .limbs = 8 };
    const auto shared = hashed("grp-", 0, 700);
    std::vector<Digest> rows_a = shared, rows_b = shared;
    const auto only_a = hashed("grp-a-", 0, 300), only_b = hashed("grp-b-", 0, 300);
    rows_a.insert(rows_a.end(), only_a.begin(), only_a.end());
    rows_b.insert(rows_b.end(), only_b.begin(), only_b.end());

    const auto r = reference_count(build(rows_a, p, Role::A), build(rows_b, p, Role::B), groups);
    CAPTURE(groups);
    REQUIRE(r.groups == groups);
    REQUIRE(r.group_sums.size() == groups);
    REQUIRE_FALSE(r.group_wrapped);
    REQUIRE(r.matches == 700);
    REQUIRE(count_from_groups(r.group_sums) == r.matches);

    for (unsigned g = 0; g < groups; ++g) {
        std::uint64_t want = 0;
        for (std::uint64_t cell = g; cell < p.cells; cell += groups) want += r.per_cell[cell];
        CAPTURE(g, want);
        REQUIRE(r.group_sums[g] == want);
        REQUIRE(r.group_sums[g] < plaintext_modulus);
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

TEST_CASE("tables that cannot be compared are refused", "[psi][reference]") {
    const TableParams p{ .cells = 64, .levels = 5, .limbs = 8 };
    const auto rows = hashed("v-", 0, 50);
    const auto a = build(rows, p, Role::A);
    const auto b = build(rows, p, Role::B);
    const auto a2 = build(rows, p, Role::A);

    SECTION("same role: shared sentinels would match every empty cell") {
        CHECK_THROWS_AS(reference_count(a, a2), std::invalid_argument);
        CHECK_THROWS_AS(reference_itemized(a, a2), std::invalid_argument);
    }
    SECTION("an invalid grouping is refused") {
        CHECK_THROWS_AS(reference_count(a, b, 0), std::invalid_argument);
        CHECK_THROWS_AS(reference_count(a, b, 3), std::invalid_argument);          // not a power of two
        CHECK_THROWS_AS(reference_count(a, b, 2 * p.cells), std::invalid_argument);  // more groups than cells
        CHECK_NOTHROW(reference_count(a, b, p.cells));
        // Partial sums must be residues: a raw centered slot value is refused.
        CHECK_THROWS_AS(count_from_groups({ plaintext_modulus }), std::invalid_argument);
    }
    SECTION("mismatched m or k is a hard error, never a count; T may differ (dynamic T)") {
        for (const TableParams q : { TableParams{ .cells = 128, .levels = 5, .limbs = 8 },
                                     TableParams{ .cells = 64, .levels = 5, .limbs = 7 } }) {
            CHECK_THROWS_AS(reference_count(a, build(rows, q, Role::B)), std::invalid_argument);
        }
        CHECK_NOTHROW(reference_count(a, build(rows, TableParams{ .cells = 64, .levels = 6, .limbs = 8 }, Role::B)));
    }
    SECTION("malformed masks are refused, not decoded") {
        const auto it = reference_itemized(a, b);
        auto wrong_count = it.masks;
        wrong_count.push_back(wrong_count[0]);
        CHECK_THROWS_AS(resolve_matches(a, wrong_count), std::invalid_argument);
        auto short_mask = it.masks;
        short_mask[0].pop_back();
        CHECK_THROWS_AS(resolve_matches(a, short_mask), std::invalid_argument);

        std::uint64_t empty_cell = p.cells;  // a bit on an empty slot: only a broken circuit sets one
        for (std::uint64_t cell = 0; cell < p.cells && empty_cell == p.cells; ++cell) {
            if (a.occupant(p.levels - 1, cell) == Table::empty) empty_cell = cell;
        }
        REQUIRE(empty_cell < p.cells);
        auto bogus = it.masks;
        bogus[0][empty_cell] |= 1u << (p.levels - 1);
        CHECK_THROWS_AS(resolve_matches(a, bogus), std::runtime_error);
        auto too_wide = it.masks;
        too_wide[0][0] = 1u << 16;
        CHECK_THROWS_AS(resolve_matches(a, too_wide), std::runtime_error);
    }
}

// Dynamic T: each party keeps only the levels its data fills. Levels a party does not
// have could only ever have held its sentinel, which matches nothing - so comparing
// T_A x T_B pairs must give exactly what padding both sides to the larger T gives.
TEST_CASE("unequal level counts count exactly what equal ones do", "[psi][reference]") {
    std::mt19937_64 rng(20260917);
    for (unsigned trial = 0; trial < 40; ++trial) {
        const std::uint64_t cells = std::uint64_t{1} << (4 + trial % 5);
        const std::uint64_t shared = rng() % (cells * 2), only_a = rng() % (cells * 3), only_b = rng() % cells;
        auto rows_a = hashed("s" + std::to_string(trial) + "-", 0, shared);
        auto rows_b = rows_a;
        const auto extra_a = hashed("a" + std::to_string(trial) + "-", 0, only_a);
        const auto extra_b = hashed("b" + std::to_string(trial) + "-", 0, only_b);
        rows_a.insert(rows_a.end(), extra_a.begin(), extra_a.end());
        rows_b.insert(rows_b.end(), extra_b.begin(), extra_b.end());

        const auto ta = static_cast<unsigned>(std::max<std::uint64_t>(1, fullest_cell(rows_a, cells)));
        const auto tb = static_cast<unsigned>(std::max<std::uint64_t>(1, fullest_cell(rows_b, cells)));
        const unsigned tmax = std::max(ta, tb);
        CAPTURE(trial, cells, shared, ta, tb);
        const auto a = build(rows_a, { .cells = cells, .levels = ta, .limbs = 3 }, Role::A);
        const auto b = build(rows_b, { .cells = cells, .levels = tb, .limbs = 3 }, Role::B);
        const auto a_full = build(rows_a, { .cells = cells, .levels = tmax, .limbs = 3 }, Role::A);
        const auto b_full = build(rows_b, { .cells = cells, .levels = tmax, .limbs = 3 }, Role::B);

        const auto asym = reference_count(a, b, 2);
        const auto sym = reference_count(a_full, b_full, 2);
        REQUIRE(asym.per_cell == sym.per_cell);
        REQUIRE(asym.group_sums == sym.group_sums);
        REQUIRE(asym.matches == shared);  // no drops: each side has exactly the levels it needs

        // Itemized, in each viewer's own layout: its own T, masks for its own levels.
        const auto it_a = reference_itemized(a, b), it_a_full = reference_itemized(a, b_full);
        REQUIRE(it_a.masks == it_a_full.masks);
        REQUIRE(it_a.masks.size() == (ta + 15) / 16);
        REQUIRE(resolve_matches(b, reference_itemized(b, a).masks).size() == shared);
    }
}
