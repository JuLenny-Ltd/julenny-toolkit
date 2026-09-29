// Client-side sharding (platform plans/exact-psi-implementation.md step F1; design §2.7 item 1).
//
// The claim F1 exists to establish is that sharding is a change of STORAGE, not of meaning: the
// same records at the same cells_total give the same count whether they are encoded as one table
// or as P. Everything here is built around that equality, plus the two ways it can silently fail -
// spending the same digest bits twice, and comparing one party's shard p against the other's
// shard q.
#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <numeric>
#include <set>
#include <string>
#include <vector>

#include "psi/bundle.h"
#include "psi/digest.h"
#include "psi/reference.h"
#include "psi/table.h"

using namespace fhe_toolkit::psi;

namespace {

constexpr const char* domain = "f1-shard-test";

std::vector<Digest> records(const std::string& prefix, int n, int from = 0) {
    std::vector<Digest> out;
    out.reserve(static_cast<std::size_t>(n));
    for (int i = from; i < from + n; ++i) out.push_back(record_digest(domain, prefix + std::to_string(i)));
    return out;
}

// Build every shard of one party, from the whole record set.
std::vector<Table> shard_tables(const std::vector<Digest>& all, std::uint64_t cells_total,
                                unsigned levels, unsigned limbs, std::uint64_t shards, Role role,
                                OverflowPolicy policy = OverflowPolicy::drop) {
    const auto buckets = partition_by_shard(all, shards);
    std::vector<Table> out;
    for (std::uint64_t p = 0; p < shards; ++p) {
        TableParams params{ .cells = cells_total / shards, .levels = levels, .limbs = limbs,
                            .shards = shards, .shard = p };
        out.push_back(build_table(buckets[p], params, role, policy));
    }
    return out;
}

}  // namespace

TEST_CASE("the shard index and the in-shard cell are disjoint halves of one position", "[psi][shard]") {
    // The whole scheme rests on this. If the shard were taken from bits the cell also uses, every
    // record in a shard would agree on them and the shard's effective cell count would collapse
    // from m/P to m/P^2 - with no symptom but a silently worse collision rate.
    const std::uint64_t cells_total = 4096;
    for (const std::uint64_t P : { 1ull, 2ull, 8ull, 64ull, 512ull }) {
        for (int i = 0; i < 4000; ++i) {
            const auto d = record_digest(domain, "rec" + std::to_string(i));
            const std::uint32_t pos = position(d, cells_total);
            const std::uint32_t sh = shard_of(d, P);
            const std::uint32_t cell = position_in_shard(d, cells_total, P);
            REQUIRE(sh < P);
            REQUIRE(cell < cells_total / P);
            REQUIRE(pos == cell * P + sh);
        }
    }
}

TEST_CASE("sharding uses every cell of the key space", "[psi][shard]") {
    // A stronger form of the same claim: over many records, the (shard, cell) pairs actually seen
    // cover as many distinct positions as the unsharded table does. A construction that stole the
    // cell's bits would cover P times fewer.
    const std::uint64_t cells_total = 256;
    const auto rs = records("cover", 20000);
    std::set<std::uint32_t> flat, split;
    for (const auto& d : rs) {
        flat.insert(position(d, cells_total));
        split.insert(static_cast<std::uint32_t>(position_in_shard(d, cells_total, 16) * 16 + shard_of(d, 16)));
    }
    CHECK(flat.size() == cells_total);
    CHECK(split == flat);
}

TEST_CASE("partition_by_shard is a partition, and agrees with shard_of", "[psi][shard]") {
    const auto rs = records("part", 5000);
    for (const std::uint64_t P : { 1ull, 4ull, 32ull }) {
        const auto buckets = partition_by_shard(rs, P);
        REQUIRE(buckets.size() == P);
        std::size_t total = 0;
        for (std::uint64_t p = 0; p < P; ++p) {
            total += buckets[p].size();
            for (const auto& d : buckets[p]) CHECK(shard_of(d, P) == p);
        }
        CHECK(total == rs.size());
    }
    // Duplicates land together, which is what lets each bucket be deduped on its own.
    auto dup = records("dup", 10);
    dup.insert(dup.end(), dup.begin(), dup.end());
    const auto buckets = partition_by_shard(dup, 8);
    for (const auto& bucket : buckets) CHECK(bucket.size() % 2 == 0);
}

TEST_CASE("a sharded count equals the unsharded count of the same records", "[psi][shard]") {
    // The convince-me of step F1, in the clear.
    const std::uint64_t cells_total = 2048;
    const unsigned levels = 8, limbs = 8;
    auto a = records("a", 3000);
    auto b = records("b", 3000);
    const auto shared = records("a", 900);                 // 900 records both parties hold
    b.insert(b.end(), shared.begin(), shared.end());

    const TableParams flat{ .cells = cells_total, .levels = levels, .limbs = limbs };
    const auto ta = build_table(a, flat, Role::A, OverflowPolicy::drop);
    const auto tb = build_table(b, flat, Role::B, OverflowPolicy::drop);
    const auto expected = reference_count(ta, tb, 1);
    REQUIRE(expected.matches > 0);

    for (const std::uint64_t P : { 1ull, 2ull, 4ull, 16ull, 128ull }) {
        const auto sa = shard_tables(a, cells_total, levels, limbs, P, Role::A);
        const auto sb = shard_tables(b, cells_total, levels, limbs, P, Role::B);
        const auto got = reference_count_sharded(sa, sb, 1);
        INFO("P = " << P);
        CHECK(got.matches == expected.matches);
        CHECK(got.count_mod_t == expected.count_mod_t);
        // ... and not merely the total: the same records are placed and the same ones dropped.
        std::uint64_t placed = 0, dropped = 0;
        for (const auto& t : sa) { placed += t.report().records; dropped += t.report().dropped; }
        CHECK(placed == ta.report().records);
        CHECK(dropped == ta.report().dropped);
    }
}

TEST_CASE("the grouped count survives sharding", "[psi][shard]") {
    const std::uint64_t cells_total = 1024;
    auto a = records("ga", 2000);
    auto b = records("ga", 2000);  // identical sets: every record matches
    const TableParams flat{ .cells = cells_total, .levels = 10, .limbs = 8 };
    const auto expected = reference_count(build_table(a, flat, Role::A, OverflowPolicy::drop),
                                          build_table(b, flat, Role::B, OverflowPolicy::drop), 8);
    for (const std::uint64_t P : { 2ull, 8ull }) {
        const auto sa = shard_tables(a, cells_total, 10, 8, P, Role::A);
        const auto sb = shard_tables(b, cells_total, 10, 8, P, Role::B);
        const auto got = reference_count_sharded(sa, sb, 8);
        INFO("P = " << P);
        CHECK(count_from_groups(got.group_sums) == count_from_groups(expected.group_sums));
        CHECK(got.matches == expected.matches);
        CHECK(got.group_wrapped == expected.group_wrapped);
    }
}

TEST_CASE("P = 1 is not merely equivalent to unsharded, it is identical", "[psi][shard]") {
    const auto rs = records("id", 900);
    const TableParams implicit{ .cells = 512, .levels = 6, .limbs = 8 };
    const TableParams explicit_one{ .cells = 512, .levels = 6, .limbs = 8, .shards = 1, .shard = 0 };
    const auto x = build_table(rs, implicit, Role::A, OverflowPolicy::drop);
    const auto y = build_table(rs, explicit_one, Role::A, OverflowPolicy::drop);
    REQUIRE(x.records() == y.records());
    for (unsigned level = 0; level < 6; ++level)
        for (std::uint64_t cell = 0; cell < 512; ++cell)
            REQUIRE(x.occupant(level, cell) == y.occupant(level, cell));

    // And the header it produces is byte-identical to the pre-sharding one: no SHARDS line.
    const auto layout = bundle_layout(explicit_one, 1, 32768);
    const auto header = bundle_header(layout, Role::A);
    CHECK(header.find("SHARDS") == std::string::npos);
    CHECK(header.find("SHARD ") == std::string::npos);
}

TEST_CASE("a sharded bundle declares its shard, so a mispairing cannot be silent", "[psi][shard]") {
    const TableParams params{ .cells = 512, .levels = 6, .limbs = 8, .shards = 8, .shard = 3 };
    const auto layout = bundle_layout(params, 1, 32768);
    CHECK(layout.shards == 8);
    CHECK(layout.shard == 3);
    const auto header = bundle_header(layout, Role::B);
    CHECK(header.find("\nSHARDS 8\n") != std::string::npos);
    CHECK(header.find("\nSHARD 3\n") != std::string::npos);
    // The shard lines sit before the payload marker, like every other field.
    CHECK(header.find("SHARDS") < header.find("PAYLOAD"));

    CHECK_THROWS_AS(bundle_layout(TableParams{ .cells = 512, .levels = 6, .limbs = 8, .shards = 3 }, 1, 32768),
                    std::invalid_argument);
    CHECK_THROWS_AS(bundle_layout(TableParams{ .cells = 512, .levels = 6, .limbs = 8, .shards = 4, .shard = 4 }, 1, 32768),
                    std::invalid_argument);
}

TEST_CASE("comparing different shards is refused", "[psi][shard]") {
    const auto a = records("xa", 400);
    const auto b = records("xb", 400);
    const auto sa = shard_tables(a, 512, 6, 8, 4, Role::A);
    const auto sb = shard_tables(b, 512, 6, 8, 4, Role::B);
    CHECK_NOTHROW(reference_count(sa[2], sb[2], 1));
    CHECK_THROWS_AS(reference_count(sa[2], sb[3], 1), std::invalid_argument);
    // A sharded table against an unsharded one is the same mistake wearing a different hat. Its
    // cells must MATCH a shard's (512 / 4) or the cell check would fire first and prove nothing;
    // 16 levels so 400 records in 128 cells are all placed and the ceiling is not what throws.
    const auto flat = build_table(b, TableParams{ .cells = 128, .levels = 16, .limbs = 8 }, Role::B, OverflowPolicy::drop);
    CHECK_THROWS_AS(reference_count(sa[0], flat, 1), std::invalid_argument);
    // Out-of-order shard vectors are refused rather than quietly mispaired.
    auto reversed = sb;
    std::reverse(reversed.begin(), reversed.end());
    CHECK_THROWS_AS(reference_count_sharded(sa, reversed, 1), std::invalid_argument);
    CHECK_THROWS_AS(reference_count_sharded(sa, std::vector<Table>{ sb[0] }, 1), std::invalid_argument);
}

TEST_CASE("an aggregate is laid out in shard order, not merely summed", "[psi][shard]") {
    // The COUNT is order-independent - permute both sides the same way and the total is unchanged -
    // so a test that only checks the total cannot tell whether shards were aggregated in order.
    // What the ordering guards is per_cell: cell c of shard p sits at p * cells_per_shard + c, and a
    // caller locating a match reads it that way. Assert the layout, not just the sum.
    const std::uint64_t cells_total = 512, shards = 4, per_shard = cells_total / shards;
    const auto both = records("ord", 60);   // identical sets: every record matches, at its own cell
    const auto sa = shard_tables(both, cells_total, 8, 8, shards, Role::A);
    const auto sb = shard_tables(both, cells_total, 8, 8, shards, Role::B);
    const auto got = reference_count_sharded(sa, sb, 1);
    REQUIRE(got.per_cell.size() == cells_total);

    for (const auto& d : both) {
        const std::uint64_t p = shard_of(d, shards);
        const std::uint64_t cell = position_in_shard(d, cells_total, shards);
        INFO("record in shard " << p << " cell " << cell);
        CHECK(got.per_cell[p * per_shard + cell] > 0);
        // And it is at the position the UNSHARDED table would have put it, read back through the
        // same split - which is the whole claim of this step, stated per cell rather than per count.
        CHECK(p * per_shard + cell < cells_total);
        CHECK(position(d, cells_total) == cell * shards + p);
    }

    // Rotating BOTH sides identically keeps every pair same-shard, so the pairing check passes and
    // the total is unchanged: only the ordering check stands between this and a scrambled layout.
    auto ra = sa, rb = sb;
    std::rotate(ra.begin(), ra.begin() + 1, ra.end());
    std::rotate(rb.begin(), rb.begin() + 1, rb.end());
    CHECK_THROWS_AS(reference_count_sharded(ra, rb, 1), std::invalid_argument);
}

TEST_CASE("build_table ignores records of other shards", "[psi][shard]") {
    // The whole dataset may be handed to every shard: correct, if wasteful. What must not happen is
    // a record of shard 1 being placed in shard 0's table.
    const auto all = records("mix", 1500);
    const TableParams params{ .cells = 256, .levels = 8, .limbs = 8, .shards = 4, .shard = 1 };
    const auto whole = build_table(all, params, Role::A, OverflowPolicy::drop);
    const auto bucket = build_table(partition_by_shard(all, 4)[1], params, Role::A, OverflowPolicy::drop);
    CHECK(whole.records() == bucket.records());
    CHECK(whole.report().records == bucket.report().records);
    for (const auto& d : whole.records()) CHECK(shard_of(d, 4) == 1);
    // The report describes this shard, not the dataset, and its own invariant still holds.
    CHECK(whole.report().records == whole.report().rows - whole.report().duplicates);
    CHECK(whole.report().records < all.size());
}

TEST_CASE("the 1 % drop ceiling is a promise about the dataset, not about a shard", "[psi][shard]") {
    // A shard holds n/P records in m/P cells: the same mean drop rate as the whole, with far more
    // variance. build_table therefore applies the ceiling only when unsharded, and exposes it so
    // the caller can apply it to the sum - which the CLI does.
    CHECK(drop_floor_exceeded(100, 2));
    CHECK_FALSE(drop_floor_exceeded(100, 1));
    CHECK_FALSE(drop_floor_exceeded(1000, 10));
    CHECK(drop_floor_message(100, 2).find("2 of 100") != std::string::npos);

    // Cells deliberately far too few, so drops are certain: unsharded refuses, sharded does not.
    const auto rs = records("tight", 2000);
    const TableParams flat{ .cells = 64, .levels = 2, .limbs = 8 };
    CHECK_THROWS_AS(build_table(rs, flat, Role::A, OverflowPolicy::drop), TableOverflow);
    const TableParams sharded{ .cells = 16, .levels = 2, .limbs = 8, .shards = 4, .shard = 0 };
    CHECK_NOTHROW(build_table(partition_by_shard(rs, 4)[0], sharded, Role::A, OverflowPolicy::drop));
    // ... but the sum is what the caller must judge, and it is over the ceiling.
    std::uint64_t records_total = 0, dropped_total = 0;
    for (std::uint64_t p = 0; p < 4; ++p) {
        const auto t = build_table(partition_by_shard(rs, 4)[p],
                                   TableParams{ .cells = 16, .levels = 2, .limbs = 8, .shards = 4, .shard = p },
                                   Role::A, OverflowPolicy::drop);
        records_total += t.report().records;
        dropped_total += t.report().dropped;
    }
    CHECK(drop_floor_exceeded(records_total, dropped_total));
}

TEST_CASE("OverflowPolicy::fail still fails per shard", "[psi][shard]") {
    // Deferring the RATE ceiling must not defer "no record may be dropped".
    const auto rs = records("strict", 2000);
    CHECK_THROWS_AS(build_table(partition_by_shard(rs, 4)[0],
                                TableParams{ .cells = 16, .levels = 2, .limbs = 8, .shards = 4, .shard = 0 },
                                Role::A, OverflowPolicy::fail),
                    TableOverflow);
}

TEST_CASE("sharding never invents or loses a match", "[psi][shard]") {
    // Disjoint sets must count zero at every P, and identical sets must count every record.
    const auto a = records("zz", 800);
    const auto b = records("yy", 800);
    for (const std::uint64_t P : { 1ull, 4ull, 32ull }) {
        const auto none = reference_count_sharded(shard_tables(a, 512, 8, 8, P, Role::A),
                                                  shard_tables(b, 512, 8, 8, P, Role::B), 1);
        INFO("P = " << P);
        CHECK(none.matches == 0);
        const auto all = reference_count_sharded(shard_tables(a, 512, 8, 8, P, Role::A),
                                                 shard_tables(a, 512, 8, 8, P, Role::B), 1);
        std::uint64_t placed = 0;
        for (const auto& t : shard_tables(a, 512, 8, 8, P, Role::A)) placed += t.report().placed;
        CHECK(all.matches == placed);
    }
}
