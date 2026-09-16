#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/matchers/catch_matchers_floating_point.hpp>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <map>
#include <random>
#include <set>
#include <string>
#include <vector>

#include "psi/digest.h"
#include "psi/table.h"

using namespace fhe_toolkit::psi;
using Catch::Matchers::WithinRel;

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

// A digest whose address the test chooses, with an otherwise pseudo-random body:
// puts a record in exactly the cell a test wants.
Digest at_address(std::uint32_t address, std::uint64_t id) {
    Digest d = sha256("synthetic-" + std::to_string(id));
    for (unsigned b = 0; b < address_bytes; ++b) {
        d[b] = static_cast<std::uint8_t>(address >> (8 * b));
    }
    return d;
}

// A real record whose first `limbs` limbs spell exactly `value` in limb 0 and
// zero elsewhere - i.e. whose signature lands on a sentinel.
Digest on_value(std::uint32_t address, std::uint16_t value, unsigned limbs, std::uint64_t id) {
    Digest d = at_address(address, id);
    for (std::size_t b = signature_offset; b < signature_offset + 2 * limbs; ++b) d[b] = 0;
    d[signature_offset] = static_cast<std::uint8_t>(value & 0xFF);
    d[signature_offset + 1] = static_cast<std::uint8_t>(value >> 8);
    return d;
}

bool same_value(const Table& a, unsigned ja, const Table& b, unsigned jb, std::uint64_t cell) {
    for (unsigned l = 0; l < a.params().limbs; ++l) {
        if (a.limb_at(ja, l, cell) != b.limb_at(jb, l, cell)) return false;
    }
    return true;
}

struct Match {
    unsigned      level_a;
    unsigned      level_b;
    std::uint64_t cell;
};

// Every slot-aligned (A level, B level) comparison the circuit performs, done in
// the clear on the stored values.
std::vector<Match> all_pairs_matches(const Table& a, const Table& b) {
    std::vector<Match> out;
    for (std::uint64_t cell = 0; cell < a.params().cells; ++cell) {
        for (unsigned ja = 0; ja < a.params().levels; ++ja) {
            for (unsigned jb = 0; jb < b.params().levels; ++jb) {
                if (same_value(a, ja, b, jb, cell)) out.push_back({ ja, jb, cell });
            }
        }
    }
    return out;
}

// build_table under the drop policy, keeping the report even when the table is
// refused (the refusal carries it).
PlacementReport placement_report(std::vector<Digest> digests, const TableParams& p) {
    try {
        return build_table(std::move(digests), p, Role::A, OverflowPolicy::drop).report();
    } catch (const TableOverflow& e) {
        return e.report();
    }
}

// Independent of the production model: plain pmf summation. Per-cell
// P(X > T), E[Y] and E[Y^2] for Y = (X - T)+, X ~ Poisson(lambda).
struct Moments {
    double overflow  = 0.0;
    double excess    = 0.0;
    double excess_sq = 0.0;
};
Moments poisson_moments(double lambda, unsigned levels) {
    Moments m;
    for (unsigned x = levels + 1; x < levels + 200; ++x) {
        const double dx = static_cast<double>(x);
        const double p = std::exp(-lambda + dx * std::log(lambda) - std::lgamma(dx + 1.0));
        const double y = dx - static_cast<double>(levels);
        m.overflow += p;
        m.excess += y * p;
        m.excess_sq += y * y * p;
    }
    return m;
}

}  // namespace

// ---------------------------------------------------------------------------
// Placement
// ---------------------------------------------------------------------------

TEST_CASE("a record lands at its position, in the first free level", "[psi][table]") {
    SECTION("hand-placed cells") {
        const TableParams p{ .cells = 16, .levels = 4, .limbs = 8 };
        // Four records for cell 5 - one of them via address 5 + 16*1000, since only
        // the low 4 bits pick the cell - and one for cell 9.
        const std::vector<Digest> in{ at_address(5, 1), at_address(9, 2), at_address(5, 3),
                                      at_address(5, 4), at_address(5 + 16 * 1000, 5) };
        const auto t = build_table(in, p, Role::A, OverflowPolicy::fail);

        std::vector<Digest> five{ in[0], in[2], in[3], in[4] };
        std::sort(five.begin(), five.end());
        for (unsigned level = 0; level < 4; ++level) {
            CAPTURE(level);
            REQUIRE(t.occupant(level, 5) != Table::empty);
            REQUIRE(t.records()[t.occupant(level, 5)] == five[level]);  // digest order
        }
        REQUIRE(t.records()[t.occupant(0, 9)] == in[1]);
        for (unsigned level = 1; level < 4; ++level) REQUIRE(t.occupant(level, 9) == Table::empty);
        for (std::uint64_t cell = 0; cell < 16; ++cell) {
            if (cell == 5 || cell == 9) continue;
            for (unsigned level = 0; level < 4; ++level) REQUIRE(t.occupant(level, cell) == Table::empty);
        }
        REQUIRE(t.report().cell_max_load == 4);
        REQUIRE(t.report().dropped == 0);
    }

    SECTION("random records: each cell's occupants are its first min(load, T) records, "
            "in digest order, on levels 0 upward") {
        // lambda = 1, T = 4: the model expects ~4 drops (0.43 %), under the ceiling.
        const TableParams p{ .cells = 1 << 10, .levels = 4, .limbs = 8 };
        const auto in = hashed("place-", 0, 1 << 10);
        const auto t = build_table(in, p, Role::A, OverflowPolicy::drop);

        std::map<std::uint64_t, std::vector<Digest>> by_cell;  // independent grouping
        for (const auto& d : std::set<Digest>(in.begin(), in.end())) by_cell[position(d, p.cells)].push_back(d);

        std::uint64_t dropped = 0;
        for (std::uint64_t cell = 0; cell < p.cells; ++cell) {
            const auto& want = by_cell[cell];  // ascending: std::set order
            CAPTURE(cell, want.size());
            for (unsigned level = 0; level < p.levels; ++level) {
                const auto occ = t.occupant(level, cell);
                if (level < want.size()) {
                    REQUIRE(occ != Table::empty);
                    REQUIRE(t.records()[occ] == want[level]);
                } else {
                    REQUIRE(occ == Table::empty);
                }
            }
            for (std::size_t i = p.levels; i < want.size(); ++i) {
                REQUIRE(std::binary_search(t.dropped().begin(), t.dropped().end(), want[i]));
                ++dropped;
            }
        }
        REQUIRE(t.dropped().size() == dropped);
        REQUIRE(dropped > 0);  // this set does overflow, so the dropped path is exercised
    }
}

TEST_CASE("T+1 records contending for one cell overflow, and it is never silent", "[psi][table]") {
    const TableParams p{ .cells = 1024, .levels = 3, .limbs = 8 };
    // `crowd` records in cell 7, then one record in each other cell up to 1000 total.
    auto input = [](unsigned crowd) {
        std::vector<Digest> v;
        std::uint64_t id = 0;
        for (unsigned i = 0; i < crowd; ++i) v.push_back(at_address(7, id++));
        for (std::uint32_t cell = 0; v.size() < 1000; ++cell) {
            if (cell != 7) v.push_back(at_address(cell, id++));
        }
        return v;
    };

    SECTION("exactly T fit") {
        const auto t = build_table(input(3), p, Role::A, OverflowPolicy::fail);
        REQUIRE(t.report().dropped == 0);
        REQUIRE(t.report().cell_max_load == 3);
        REQUIRE(t.report().placed == 1000);
    }

    SECTION("T+1 under the fail policy is refused, and the refusal carries the numbers") {
        REQUIRE_THROWS_AS(build_table(input(4), p, Role::A, OverflowPolicy::fail), TableOverflow);
        try {
            (void)build_table(input(4), p, Role::A, OverflowPolicy::fail);
        } catch (const TableOverflow& e) {
            REQUIRE(e.report().dropped == 1);
            REQUIRE(e.report().overflowed_cells == 1);
            REQUIRE(e.report().cell_max_load == 4);
            REQUIRE(e.report().placed == 999);
            REQUIRE(std::string(e.what()).find("1 of 1000 records did not fit") != std::string::npos);
        }
    }

    SECTION("T+1 under the drop policy drops the largest digest in the cell, and says so") {
        const auto in = input(4);
        const auto t = build_table(in, p, Role::A, OverflowPolicy::drop);
        const auto largest = *std::max_element(in.begin(), in.begin() + 4);
        REQUIRE(t.dropped() == std::vector<Digest>{ largest });
        REQUIRE(t.report().dropped == 1);
        REQUIRE(t.report().overflowed_cells == 1);
        REQUIRE(t.report().placed == 999);
        REQUIRE(t.report().drop_rate() == 0.001);
    }
}

TEST_CASE("the placement report agrees with an independent count", "[psi][table]") {
    const TableParams p{ .cells = 1 << 8, .levels = 2, .limbs = 8 };
    auto in = hashed("report-", 0, 512);                   // lambda = 2, T = 2: heavy overflow
    for (std::size_t i = 0; i < 50; ++i) in.push_back(in[i * 3]);  // 50 repeated rows

    std::map<std::uint64_t, std::uint64_t> load;
    for (const auto& d : std::set<Digest>(in.begin(), in.end())) ++load[position(d, p.cells)];
    std::uint64_t dropped = 0, overflowed = 0, max_load = 0;
    for (const auto& [cell, l] : load) {
        if (l > p.levels) { dropped += l - p.levels; ++overflowed; }
        max_load = std::max(max_load, l);
    }

    for (const auto policy : { OverflowPolicy::fail, OverflowPolicy::drop }) {
        CAPTURE(policy == OverflowPolicy::fail);
        PlacementReport r;
        try {
            r = build_table(in, p, Role::A, policy).report();
            FAIL("a table with a drop rate of " << dropped * 100.0 / 512 << " % was not refused");
        } catch (const TableOverflow& e) {
            r = e.report();
        }
        REQUIRE(r.rows == 562);
        REQUIRE(r.duplicates == 50);
        REQUIRE(r.records == 512);
        REQUIRE(r.dropped == dropped);
        REQUIRE(r.overflowed_cells == overflowed);
        REQUIRE(r.cell_max_load == max_load);
        REQUIRE(r.placed + r.dropped == r.records);
    }
}

TEST_CASE("the drop policy is capped at 1 % of distinct records", "[psi][table]") {
    const TableParams p{ .cells = 1024, .levels = 1, .limbs = 8 };
    // 1000 records: `colliding` cells hold two each (one drops), the rest one each.
    auto input = [](unsigned colliding) {
        std::vector<Digest> v;
        std::uint64_t id = 0;
        for (std::uint32_t c = 0; c < colliding; ++c) {
            v.push_back(at_address(c, id++));
            v.push_back(at_address(c, id++));
        }
        for (std::uint32_t c = colliding; v.size() < 1000; ++c) v.push_back(at_address(c, id++));
        return v;
    };

    SECTION("10 of 1000 dropped (exactly 1.00 %) is allowed under drop, refused under fail") {
        const auto t = build_table(input(10), p, Role::A, OverflowPolicy::drop);
        REQUIRE(t.report().records == 1000);
        REQUIRE(t.report().dropped == 10);
        REQUIRE_THROWS_AS(build_table(input(10), p, Role::A, OverflowPolicy::fail), TableOverflow);
    }

    SECTION("11 of 1000 dropped (1.10 %) is refused even under drop") {
        try {
            (void)build_table(input(11), p, Role::A, OverflowPolicy::drop);
            FAIL("an 1.1 % drop rate was accepted");
        } catch (const TableOverflow& e) {
            REQUIRE(e.report().dropped == 11);
            REQUIRE(std::string(e.what()).find("1.10 %") != std::string::npos);
        }
    }
}

// ---------------------------------------------------------------------------
// Sentinels
// ---------------------------------------------------------------------------

TEST_CASE("empty cells hold the role's sentinel, occupied cells never do", "[psi][table]") {
    const Role role = GENERATE(Role::A, Role::B);
    const TableParams p{ .cells = 1 << 10, .levels = 4, .limbs = 8 };
    // lambda = 1, T = 4 expects ~4 overflowing cells, so drop (~0.45 %) rather than fail.
    const auto t = build_table(hashed("sentinel-", 0, 1 << 10), p, role, OverflowPolicy::drop);

    REQUIRE(sentinel(Role::A, 8) == std::vector<std::uint16_t>{ 0, 0, 0, 0, 0, 0, 0, 0 });
    REQUIRE(sentinel(Role::B, 8) == std::vector<std::uint16_t>{ 1, 0, 0, 0, 0, 0, 0, 0 });

    std::uint64_t empties = 0;
    std::vector<std::uint16_t> row(p.cells);
    for (unsigned level = 0; level < p.levels; ++level) {
        for (std::uint64_t cell = 0; cell < p.cells; ++cell) {
            const auto occ = t.occupant(level, cell);
            const auto v = t.signature_at(level, cell);
            if (occ == Table::empty) {
                ++empties;
                REQUIRE(v == sentinel(role, p.limbs));
            } else {
                REQUIRE(v == stored_signature(t.records()[occ], p.limbs));
                REQUIRE(v != sentinel(Role::A, p.limbs));
                REQUIRE(v != sentinel(Role::B, p.limbs));
            }
        }
        // The bulk path the encoder uses agrees with the per-cell accessor.
        for (unsigned j = 0; j < p.limbs; ++j) {
            t.fill_limb_row(level, j, row);
            for (std::uint64_t cell = 0; cell < p.cells; ++cell) REQUIRE(row[cell] == t.limb_at(level, j, cell));
        }
    }
    REQUIRE(empties > 2 * p.cells);  // lambda = 1 over 4 levels: most slots are empty
}

TEST_CASE("a real signature on a sentinel value is remapped, identically on both sides",
          "[psi][table]") {
    const unsigned k = GENERATE(1u, 2u, 8u);
    CAPTURE(k);
    const TableParams p{ .cells = 16, .levels = 2, .limbs = k };
    const Digest z0 = on_value(3, 0, k, 1);  // a real record whose signature is 0
    const Digest z1 = on_value(4, 1, k, 2);  // ...and one whose signature is 1
    REQUIRE(signature(z0, k) == sentinel(Role::A, k));  // the setup really does hit them
    REQUIRE(signature(z1, k) == sentinel(Role::B, k));

    auto expect = [k](std::uint16_t limb0) {
        std::vector<std::uint16_t> v(k, 0);
        v[0] = limb0;
        return v;
    };
    REQUIRE(stored_signature(z0, k) == expect(2));
    REQUIRE(stored_signature(z1, k) == expect(3));

    SECTION("both parties hold them: each matches exactly once") {
        const auto a = build_table({ z0, z1 }, p, Role::A, OverflowPolicy::fail);
        const auto b = build_table({ z0, z1 }, p, Role::B, OverflowPolicy::fail);
        REQUIRE(a.report().remapped == 2);
        REQUIRE(b.report().remapped == 2);
        const auto m = all_pairs_matches(a, b);
        REQUIRE(m.size() == 2);
        for (const auto& x : m) {
            const auto oa = a.occupant(x.level_a, x.cell);
            const auto ob = b.occupant(x.level_b, x.cell);
            REQUIRE(oa != Table::empty);  // an empty slot matched something
            REQUIRE(ob != Table::empty);
            REQUIRE(a.records()[oa] == b.records()[ob]);
        }
    }

    SECTION("only one party holds them: they match nothing, not the other side's empty cells") {
        const auto a_empty = build_table({}, p, Role::A, OverflowPolicy::fail);
        const auto b_empty = build_table({}, p, Role::B, OverflowPolicy::fail);
        const auto a_full = build_table({ z0, z1 }, p, Role::A, OverflowPolicy::fail);
        const auto b_full = build_table({ z0, z1 }, p, Role::B, OverflowPolicy::fail);
        REQUIRE(all_pairs_matches(a_empty, b_full).empty());
        REQUIRE(all_pairs_matches(a_full, b_empty).empty());
    }
}

TEST_CASE("no empty cell ever matches", "[psi][table]") {
    SECTION("disjoint sets in mostly-empty tables: zero matches") {
        const TableParams p{ .cells = 1 << 10, .levels = 4, .limbs = 8 };
        const auto a = build_table(hashed("a-", 0, 300), p, Role::A, OverflowPolicy::fail);
        const auto b = build_table(hashed("b-", 0, 300), p, Role::B, OverflowPolicy::fail);
        REQUIRE(all_pairs_matches(a, b).empty());

        // What a shared fill value would have counted instead: every aligned pair
        // of empty slots.
        std::uint64_t empty_pairs = 0;
        for (std::uint64_t cell = 0; cell < p.cells; ++cell) {
            std::uint64_t ea = 0, eb = 0;
            for (unsigned j = 0; j < p.levels; ++j) {
                ea += a.occupant(j, cell) == Table::empty;
                eb += b.occupant(j, cell) == Table::empty;
            }
            empty_pairs += ea * eb;
        }
        CAPTURE(empty_pairs);
        REQUIRE(empty_pairs > 10 * p.cells);
    }

    SECTION("two empty tables: zero matches over every slot") {
        const TableParams p{ .cells = 64, .levels = 3, .limbs = 8 };
        const auto a = build_table({}, p, Role::A, OverflowPolicy::fail);
        const auto b = build_table({}, p, Role::B, OverflowPolicy::fail);
        REQUIRE(all_pairs_matches(a, b).empty());
        REQUIRE(a.report().records == 0);
        REQUIRE(a.report().drop_rate() == 0.0);
    }
}

// ---------------------------------------------------------------------------
// The counting invariant, and what first-free placement is actually for
// ---------------------------------------------------------------------------

// Design §2.2: a record occupies exactly one (level, cell) on each side, so a
// shared record matches in exactly one (A level, B level) pair and nothing else
// matches. The two sides generally put it on DIFFERENT levels - the other records
// contending for that cell differ - which is why all T^2 pairs are compared.
TEST_CASE("a shared record matches in exactly one level pair, and nothing else matches",
          "[psi][table]") {
    const TableParams p{ .cells = 1 << 11, .levels = 9, .limbs = 8 };
    auto a_in = hashed("record-", 0, 2000);
    auto b_in = hashed("record-", 1000, 2000);  // shares records 1000..1999
    std::mt19937_64 rng(20260911);
    std::shuffle(b_in.begin(), b_in.end(), rng);
    for (std::size_t i = 0; i < 100; ++i) b_in.push_back(b_in[i]);  // and repeats rows

    const auto a = build_table(a_in, p, Role::A, OverflowPolicy::fail);
    const auto b = build_table(b_in, p, Role::B, OverflowPolicy::fail);
    const auto matches = all_pairs_matches(a, b);

    std::set<Digest> matched;
    std::uint64_t different_levels = 0;
    for (const auto& m : matches) {
        const auto oa = a.occupant(m.level_a, m.cell);
        const auto ob = b.occupant(m.level_b, m.cell);
        REQUIRE(oa != Table::empty);  // an empty slot matched something
        REQUIRE(ob != Table::empty);
        const auto& da = a.records()[oa];
        const auto& db = b.records()[ob];
        REQUIRE(da == db);
        REQUIRE(matched.insert(da).second);  // no record matches twice
        different_levels += m.level_a != m.level_b;
    }
    const auto shared = hashed("record-", 1000, 1000);
    REQUIRE(matched == std::set<Digest>(shared.begin(), shared.end()));
    CAPTURE(different_levels);
    REQUIRE(different_levels > 0);  // cross-level matches do occur: all T^2 pairs are needed
}

// First-free placement over digest order makes the table a function of the
// record SET. It is not needed for the count (above), but it is what lets a party
// rebuild its own layout from its CSV at resolve time instead of storing it.
TEST_CASE("the table is a function of the set, not of row order or repeats", "[psi][table]") {
    const TableParams p{ .cells = 1 << 10, .levels = 5, .limbs = 8 };
    const auto in = hashed("set-", 0, 1500);  // lambda ~1.46, T = 5: ~5 drops, under the 1 % ceiling
    auto shuffled = in;
    std::mt19937_64 rng(7);
    std::shuffle(shuffled.begin(), shuffled.end(), rng);
    for (std::size_t i = 0; i < 300; ++i) shuffled.push_back(shuffled[i * 5]);

    const auto t1 = build_table(in, p, Role::A, OverflowPolicy::drop);
    const auto t2 = build_table(shuffled, p, Role::A, OverflowPolicy::drop);
    const auto t3 = build_table(in, p, Role::A, OverflowPolicy::drop);
    REQUIRE(t1.report().dropped > 0);
    for (const Table* other : { &t2, &t3 }) {
        for (unsigned level = 0; level < p.levels; ++level) {
            for (std::uint64_t cell = 0; cell < p.cells; ++cell) {
                const auto o1 = t1.occupant(level, cell);
                const auto o2 = other->occupant(level, cell);
                REQUIRE((o1 == Table::empty) == (o2 == Table::empty));
                if (o1 != Table::empty) REQUIRE(t1.records()[o1] == other->records()[o2]);
            }
        }
        REQUIRE(t1.dropped() == other->dropped());
    }
}

// ---------------------------------------------------------------------------
// The occupancy model, and that it predicts the code
// ---------------------------------------------------------------------------

TEST_CASE("the occupancy model matches independently computed values", "[psi][table]") {
    // From Python, direct pmf summation (not this code's recurrence):
    //   m * sum(p(x) for x > T), m * sum((x - T) * p(x) for x > T), lambda = records / cells
    SECTION("known answers, including the far tails the solver sizes against") {
        CHECK_THAT(expected_overflowed_cells(1 << 20, 1 << 20, 12), WithinRel(6.668709870577021e-05, 1e-9));
        CHECK_THAT(expected_dropped_records(1 << 20, 1 << 20, 12), WithinRel(7.176188165581592e-05, 1e-9));
        CHECK_THAT(expected_overflowed_cells(1 << 21, 1 << 20, 16), WithinRel(5.8783704932486796e-05, 1e-9));
        CHECK_THAT(expected_dropped_records(1 << 21, 1 << 20, 16), WithinRel(6.602715045666515e-05, 1e-9));
        CHECK_THAT(expected_overflowed_cells(1 << 18, 1 << 20, 6), WithinRel(0.010207385945670043, 1e-9));
        CHECK_THAT(expected_dropped_records(1 << 18, 1 << 20, 6), WithinRel(0.010534267085411147, 1e-9));
        CHECK_THAT(expected_overflowed_cells(1 << 14, 1 << 14, 3), WithinRel(311.10196225890405, 1e-9));
        CHECK_THAT(expected_dropped_records(1 << 14, 1 << 14, 3), WithinRel(382.35220284101047, 1e-9));
    }

    SECTION("closed forms at the edges") {
        // T = 0: every record beyond the first in a cell drops... and with T = 0,
        // every record drops: m(1 - e^-lambda) cells overflow, m*lambda records drop.
        CHECK_THAT(expected_overflowed_cells(1 << 15, 1 << 14, 0), WithinRel((1 << 14) * (1 - std::exp(-2.0)), 1e-12));
        CHECK_THAT(expected_dropped_records(1 << 15, 1 << 14, 0), WithinRel(double(1 << 15), 1e-12));
        // lambda far above T: every cell overflows, and all but T per cell drop.
        CHECK_THAT(expected_overflowed_cells(1 << 24, 1 << 10, 4), WithinRel(1024.0, 1e-12));
        CHECK_THAT(expected_dropped_records(1 << 24, 1 << 10, 4), WithinRel(1024.0 * (16384 - 4), 1e-12));
        CHECK(expected_overflowed_cells(0, 1 << 10, 4) == 0.0);
        CHECK(expected_dropped_records(0, 1 << 10, 4) == 0.0);
    }
}

// The model the solver will size (m, T) with has to predict what build_table
// actually does - otherwise the solver's promises are about a different program.
TEST_CASE("measured overflow matches the Poisson model, lambda 0.25 to 2", "[psi][table]") {
    struct Point { std::uint64_t records; unsigned levels; };
    constexpr std::uint64_t m = 1 << 14;
    const Point pt = GENERATE(Point{ m / 4, 1 }, Point{ m / 4, 2 }, Point{ m / 2, 2 }, Point{ m / 2, 3 },
                              Point{ m, 3 }, Point{ m, 4 }, Point{ 2 * m, 5 }, Point{ 2 * m, 6 });
    constexpr unsigned seeds = 8;
    const TableParams p{ .cells = m, .levels = pt.levels, .limbs = 8 };

    std::uint64_t overflowed = 0, dropped = 0;
    for (unsigned s = 1; s <= seeds; ++s) {
        // Fresh records per lambda: one shared prefix would nest the smaller sets
        // inside the larger, and the points would stop being independent evidence.
        const auto r = placement_report(
            hashed("mc-" + std::to_string(pt.records) + "-" + std::to_string(s) + "-", 0, pt.records), p);
        overflowed += r.overflowed_cells;
        dropped += r.dropped;
    }

    const double lambda = static_cast<double>(pt.records) / m;
    const auto mom = poisson_moments(lambda, pt.levels);
    // The production model agrees with the independent computation...
    REQUIRE_THAT(expected_overflowed_cells(pt.records, m, pt.levels), WithinRel(m * mom.overflow, 1e-12));
    REQUIRE_THAT(expected_dropped_records(pt.records, m, pt.levels), WithinRel(m * mom.excess, 1e-12));

    // ...and predicts the code. Cells are sampled as independent here; the true
    // multinomial loads are slightly negatively correlated, so this sigma is a
    // little conservative. At this m the Poisson-vs-binomial bias is ~0.01 sigma.
    const double pred_cells = seeds * expected_overflowed_cells(pt.records, m, pt.levels);
    const double pred_drops = seeds * expected_dropped_records(pt.records, m, pt.levels);
    const double sd_cells = std::sqrt(seeds * m * mom.overflow * (1 - mom.overflow));
    const double sd_drops = std::sqrt(seeds * m * (mom.excess_sq - mom.excess * mom.excess));
    const double z_cells = (static_cast<double>(overflowed) - pred_cells) / sd_cells;
    const double z_drops = (static_cast<double>(dropped) - pred_drops) / sd_drops;
    CAPTURE(lambda, pt.levels, overflowed, pred_cells, z_cells, dropped, pred_drops, z_drops);
    REQUIRE(std::abs(z_cells) < 5.0);
    REQUIRE(std::abs(z_drops) < 5.0);
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

TEST_CASE("table parameters are validated", "[psi][table]") {
    const std::vector<Digest> none;
    auto build = [&](TableParams p) { return build_table(none, p, Role::A, OverflowPolicy::fail); };
    CHECK_THROWS_AS(build({ .cells = 0, .levels = 2, .limbs = 8 }), std::invalid_argument);
    CHECK_THROWS_AS(build({ .cells = 3, .levels = 2, .limbs = 8 }), std::invalid_argument);
    CHECK_THROWS_AS(build({ .cells = max_cells << 1, .levels = 2, .limbs = 8 }), std::invalid_argument);
    CHECK_THROWS_AS(build({ .cells = 16, .levels = 0, .limbs = 8 }), std::invalid_argument);
    CHECK_THROWS_AS(build({ .cells = 16, .levels = 2, .limbs = 0 }), std::invalid_argument);
    CHECK_THROWS_AS(build({ .cells = 16, .levels = 2, .limbs = max_limbs + 1 }), std::invalid_argument);

    const auto t = build({ .cells = 16, .levels = 2, .limbs = 8 });
    CHECK_THROWS_AS(t.occupant(2, 0), std::out_of_range);
    CHECK_THROWS_AS(t.occupant(0, 16), std::out_of_range);
    CHECK_THROWS_AS(t.limb_at(0, 8, 0), std::out_of_range);
    std::vector<std::uint16_t> short_row(15);
    CHECK_THROWS_AS(t.fill_limb_row(0, 0, short_row), std::invalid_argument);
    CHECK_THROWS_AS(sentinel(Role::A, 0), std::invalid_argument);
}
