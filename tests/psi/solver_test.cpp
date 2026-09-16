#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/matchers/catch_matchers_floating_point.hpp>

#include <algorithm>
#include <bit>
#include <cmath>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

#include "psi/digest.h"
#include "psi/solver.h"
#include "psi/table.h"

using namespace fhe_toolkit::psi;
using Catch::Matchers::WithinRel;

namespace {

constexpr std::string_view kDomain = "julenny/joint-record-overlap/exact/v1";

std::uint64_t ceil_div(std::uint64_t a, std::uint64_t b) { return (a + b - 1) / b; }

Request request_for(std::uint64_t records, double target = 1e-6, unsigned signature_bits = 128) {
    Request r;
    r.records = records;
    r.target_drop_rate = target;
    r.signature_bits = signature_bits;
    return r;
}

}  // namespace

// ---------------------------------------------------------------------------
// The cost model against A1's measurements
// ---------------------------------------------------------------------------

// A1-RESULTS.md §1-§2: every serialized ciphertext size the probe measured, at
// t = 65537 / HEStd_128_classic. The model is 2 * N * towers * 8.
TEST_CASE("the ciphertext-size model reproduces every size A1 measured", "[psi][solver]") {
    struct Row { std::uint64_t slots; unsigned towers; std::uint64_t measured; };
    const Row rows[] = {
        { 16384, 5, 1'311'953 },  { 16384, 6, 1'574'219 },  { 16384, 4, 1'049'687 },
        { 16384, 3, 787'421 },    { 32768, 13, 6'817'953 }, { 32768, 14, 7'342'363 },
        { 65536, 13, 13'633'697 }, { 65536, 14, 14'682'395 },
        { 65536, 15, 15'731'093 }, { 65536, 16, 16'779'783 },
    };
    for (const auto& row : rows) {
        ContextCost c;
        c.slots = row.slots;
        c.towers = row.towers;
        const auto predicted = c.ciphertext_bytes();
        const double error = std::abs(static_cast<double>(predicted) - static_cast<double>(row.measured))
                           / static_cast<double>(row.measured);
        const std::int64_t header = static_cast<std::int64_t>(row.measured)
                                  - static_cast<std::int64_t>(predicted);
        CAPTURE(row.slots, row.towers, row.measured, predicted, error, header);
        // What the model omits is a fixed serialization header, so the gap is a
        // number of bytes rather than a percentage - which is why it looks
        // largest (0.11 %) on the smallest ciphertext measured.
        REQUIRE(header >= 0);
        REQUIRE(header <= 4096);
        REQUIRE(error < 0.002);
    }
    // The default context is A1's recommendation: depth 19, BV, N = 32768.
    REQUIRE(ContextCost{}.ciphertext_bytes() == 7'340'032);
    REQUIRE(ContextCost{}.slots == 32768);
    REQUIRE(ContextCost{}.max_limbs == 8);
}

// A1-RESULTS.md §5: the design's cost table, recomputed on A1's measured
// per-multiply cost and ciphertext size. Those rows are (m = n, T from design
// §2.5), so they are fed in as plans rather than solved for.
TEST_CASE("the cost model reproduces A1's measured cost table", "[psi][solver]") {
    struct Row {
        std::uint64_t records; unsigned levels; std::uint64_t mults; double core_hours;
    };
    const Row rows[] = {
        { 1'000, 10, 540, 196.56 / 3600 },
        { 10'000, 11, 4'995, 1818.18 / 3600 },
        { 100'000, 11, 49'950, 5.05 },
        { 1'000'000, 12, 593'325, 59.99 },
        { 10'000'000, 13, 6'962'625, 704.0 },  // A1 §5 quotes 708 h from a rounded 7.0 M mults
    };
    for (const auto& row : rows) {
        const auto r = request_for(row.records);
        const std::uint64_t cells = row.records;  // A1's table and design §2.5 cost m = n
        const Plan p{ cells, 1, row.levels, 8 };
        const auto e = estimate(r, p);
        CAPTURE(row.records, row.levels, e.multiplications, e.chunks, e.ciphertexts_self);

        // Chunks and multiplications are exact arithmetic, not a measurement:
        // ceil(T^2 * m / N) * (16k + k - 1).
        REQUIRE(e.chunks == ceil_div(std::uint64_t{row.levels} * row.levels * cells, 32768));
        REQUIRE(e.multiplications == e.chunks * 135);

        // Core time from A1's measured 0.364 s per single-core multiply.
        REQUIRE_THAT(e.core_seconds / 3600, WithinRel(row.core_hours, 0.02));

        // Ciphertexts: this model rounds up per limb, ceil(T*m/N)*k, which is
        // design §2.5's stated formula and matches A1's n = 1000 row. A1's other
        // rows pack limbs across ciphertext boundaries, ceil(T*m*k/N). The two
        // differ by at most k-1 ciphertexts, and never the other way.
        const std::uint64_t dense = ceil_div(std::uint64_t{row.levels} * cells * 8, 32768);
        REQUIRE(e.ciphertexts_self >= dense);
        REQUIRE(e.ciphertexts_self - dense <= 7);
    }
}

TEST_CASE("A1's headline sizes come back out of the model", "[psi][solver]") {
    // n = 10^7, associative T = 13, k = 8: A1 §5 measured 233 GB per party.
    const auto e = estimate(request_for(10'000'000), Plan{ 10'000'000, 1, 13, 8 });
    CAPTURE(e.input_bytes_self, e.ciphertexts_self, e.core_seconds / 3600);
    REQUIRE_THAT(static_cast<double>(e.input_bytes_self) / 1e9, WithinRel(233.0, 0.02));
    REQUIRE_THAT(e.core_seconds / 3600, WithinRel(708.0, 0.02));
}

// ---------------------------------------------------------------------------
// The limb rule (design §2.1)
// ---------------------------------------------------------------------------

TEST_CASE("limbs come from the guarantee minus the address entropy", "[psi][solver]") {
    // ceil((S - log2 m) / 16), and the address is free entropy.
    CHECK(limbs_for(128, 1, 8) == 8);
    CHECK(limbs_for(128, 1 << 16, 8) == 7);   // design §2.1: 7 limbs, not 8, from n ~ 10^5 up
    CHECK(limbs_for(128, 1 << 23, 8) == 7);
    CHECK(limbs_for(128, std::uint64_t{1} << 32, 8) == 6);
    CHECK(limbs_for(64, 1 << 10, 8) == 4);
    CHECK(limbs_for(32, 1 << 16, 8) == 1);
    CHECK(limbs_for(8, 1 << 16, 8) == 1);     // never fewer than one limb

    SECTION("the delivered guarantee is never below the request") {
        for (unsigned bits : { 16u, 32u, 64u, 96u, 128u }) {
            for (unsigned e = 0; e <= 32; ++e) {
                const std::uint64_t cells = std::uint64_t{1} << e;
                const auto k = limbs_for(bits, cells, 8);
                CAPTURE(bits, e, k);
                REQUIRE(16 * k + e >= bits);
                // ...and never more limbs than needed, once past the one-limb floor
                // (at k = 1 the address alone can already cover the guarantee).
                if (k > 1) REQUIRE(16 * (k - 1) + e < bits);
            }
        }
    }

    SECTION("a guarantee this context cannot carry is refused, not silently cut") {
        // A1 §6: k <= 8 at t = 65537, so 256 bits needs more limbs than exist.
        CHECK_THROWS_AS(limbs_for(256, 1 << 10, 8), std::invalid_argument);
        CHECK_THROWS_AS(limbs_for(512, std::uint64_t{1} << 32, 8), std::invalid_argument);
        CHECK_THROWS_AS(solve(request_for(1000, 1e-6, 256)), std::invalid_argument);
        // ...but a wide-enough address makes 160 bits reachable at k = 8.
        CHECK(limbs_for(160, std::uint64_t{1} << 32, 8) == 8);
    }
}

// ---------------------------------------------------------------------------
// The solver's promise, measured against B2
// ---------------------------------------------------------------------------

// The plan the solver hands out, fed to build_table over several seeds: the
// drop rate it promised has to be what the encoder actually does.
TEST_CASE("a solved plan drops at or below its target, measured", "[psi][solver]") {
    struct Point { std::uint64_t records; double target; };
    const Point pt = GENERATE(Point{ 2'000, 1e-3 }, Point{ 2'000, 1e-5 },
                              Point{ 20'000, 1e-3 }, Point{ 20'000, 1e-5 });
    constexpr unsigned seeds = 8;
    const auto e = solve(request_for(pt.records, pt.target));
    CAPTURE(pt.records, pt.target, e.plan.cells_total, e.plan.levels, e.plan.limbs, e.expected_drop_rate);

    REQUIRE(e.expected_drop_rate <= pt.target);  // the model's own promise
    REQUIRE(e.plan.shards == 1);                 // these fit in one shard

    std::uint64_t dropped = 0;
    for (unsigned s = 0; s < seeds; ++s) {
        std::vector<Digest> rows;
        rows.reserve(pt.records);
        const std::string prefix = "solve-" + std::to_string(pt.records) + "-" + std::to_string(s) + "-";
        for (std::uint64_t i = 0; i < pt.records; ++i) rows.push_back(record_digest(kDomain, prefix + std::to_string(i)));
        try {
            dropped += build_table(rows, e.plan.table_params(), Role::A, OverflowPolicy::drop).report().dropped;
        } catch (const TableOverflow& over) {
            dropped += over.report().dropped;
        }
    }
    // Poisson upper bound around the model's own expectation: a measurement
    // above this would mean the model the solver sized with is wrong.
    const double expected = seeds * e.expected_drop_rate * static_cast<double>(pt.records);
    const double bound = expected + 5.0 * std::sqrt(expected) + 5.0;
    CAPTURE(dropped, expected, bound);
    REQUIRE(static_cast<double>(dropped) <= bound);
}

TEST_CASE("the solver minimises the compute it claims to minimise", "[psi][solver]") {
    const std::uint64_t records = GENERATE(std::uint64_t{100}, 10'000, 1'000'000);
    const auto e = solve(request_for(records));
    const std::uint64_t chosen = std::uint64_t{e.plan.levels} * e.plan.levels * e.plan.cells_total;
    CAPTURE(records, e.plan.cells_total, e.plan.levels, chosen);

    // Brute force the same grid the solver searched.
    for (unsigned bit = 0; bit <= 32; ++bit) {
        const std::uint64_t cells = std::uint64_t{1} << bit;
        unsigned levels = 0;
        for (unsigned t = 1; t <= 256; ++t) {
            if (expected_dropped_records(records, cells, t) <= 1e-6 * static_cast<double>(records)) {
                levels = t;
                break;
            }
        }
        if (levels == 0) continue;
        unsigned k = 0;
        try {
            k = limbs_for(128, cells, 8);
        } catch (const std::invalid_argument&) {
            continue;
        }
        (void)k;
        CAPTURE(bit, levels);
        REQUIRE(std::uint64_t{levels} * levels * cells >= chosen);
    }
}

// ---------------------------------------------------------------------------
// Sharding, degenerate inputs, and the fields a quote is made of
// ---------------------------------------------------------------------------

TEST_CASE("sharding splits until a shard fits, and no further", "[psi][solver]") {
    const auto e = solve(request_for(10'000'000));
    CAPTURE(e.plan.cells_total, e.plan.shards, e.plan.levels, e.plan.limbs,
            e.input_bytes_self, e.itemized_output_bytes);

    REQUIRE(std::has_single_bit(e.plan.shards));
    REQUIRE(e.plan.cells_total % e.plan.shards == 0);
    REQUIRE(e.plan.cells_per_shard() >= 32768);  // never smaller than one ciphertext of cells
    // Either the shard fits the budget, or splitting stopped at one ciphertext of
    // cells per shard - past that, sharding only wastes slots. Splitting a large
    // shard's UPLOAD into objects is transport's job (F3), not the table's.
    const std::uint64_t shard_bytes = e.input_bytes_self / e.plan.shards;
    CAPTURE(shard_bytes);
    REQUIRE((shard_bytes <= (std::uint64_t{128} << 20) || e.plan.cells_per_shard() == 32768));

    SECTION("a smaller shard budget never makes fewer shards") {
        Request r = request_for(10'000'000);
        r.max_shard_bytes = std::uint64_t{16} << 20;
        const auto smaller = solve(r);
        REQUIRE(smaller.plan.shards >= e.plan.shards);
        REQUIRE(smaller.plan.cells_total == e.plan.cells_total);  // sharding does not change the table
        REQUIRE(smaller.multiplications >= e.multiplications);    // only rounding differs
    }
}

TEST_CASE("degenerate sizes produce a usable plan", "[psi][solver]") {
    SECTION("no records at all") {
        const auto e = solve(request_for(0));
        REQUIRE(e.plan.cells_total >= 1);
        REQUIRE(e.plan.levels >= 1);
        REQUIRE(e.plan.shards == 1);
        REQUIRE(e.expected_drop_rate == 0.0);
        REQUIRE(e.expected_false_matches == 0.0);
        REQUIRE(e.multiplications > 0);  // one chunk is still compared
        REQUIRE_NOTHROW(build_table({}, e.plan.table_params(), Role::A, OverflowPolicy::fail));
    }
    SECTION("a single record") {
        const auto e = solve(request_for(1));
        REQUIRE(e.plan.levels >= 1);
        REQUIRE(e.expected_drop_rate <= 1e-6);
        const auto d = record_digest(kDomain, "only-one");
        REQUIRE_NOTHROW(build_table({ d }, e.plan.table_params(), Role::A, OverflowPolicy::fail));
    }
    SECTION("more records than any one ciphertext can hold") {
        const auto e = solve(request_for(1'000'000'000));
        CAPTURE(e.plan.cells_total, e.plan.shards, e.plan.levels, e.plan.limbs);
        REQUIRE(e.plan.shards > 1);
        REQUIRE(e.plan.cells_total <= max_cells);
        REQUIRE(e.plan.limbs <= 8);
        REQUIRE(e.signature_bits_delivered >= 128);
        REQUIRE(e.input_bytes_self > 0);
    }
}

TEST_CASE("the estimate's fields hold together", "[psi][solver]") {
    const std::uint64_t records = GENERATE(std::uint64_t{1'000}, 100'000, 10'000'000);
    const auto e = solve(request_for(records));
    CAPTURE(records, e.plan.cells_total, e.plan.shards, e.plan.levels, e.plan.limbs);

    REQUIRE(std::has_single_bit(e.plan.cells_total));
    REQUIRE(e.multiplications == e.chunks * (16 * e.plan.limbs + e.plan.limbs - 1));
    REQUIRE_THAT(e.core_seconds, WithinRel(static_cast<double>(e.multiplications) * 0.364, 1e-12));
    REQUIRE(e.input_bytes_self == e.ciphertexts_self * ContextCost{}.ciphertext_bytes());
    REQUIRE(e.input_bytes_total == e.input_bytes_self + e.input_bytes_peer);
    REQUIRE(e.peer_decrypt_bytes == e.itemized_output_bytes);
    REQUIRE(e.count_output_bytes == ContextCost{}.ciphertext_bytes());
    // The itemized result is far smaller than the input it describes (design §2.3).
    REQUIRE(e.itemized_output_bytes < e.input_bytes_self);
    REQUIRE(e.signature_bits_delivered >= 128);
    REQUIRE(e.expected_drop_rate <= 1e-6);

    // Expected false matches are same-cell cross pairs x 2^-16k, which is
    // n_A * n_B * 2^-(delivered bits): the address the cell alignment already
    // verified counts towards the guarantee (design §2.1, §2.3).
    const double by_delivered = static_cast<double>(records) * static_cast<double>(records)
                              * std::ldexp(1.0, -static_cast<int>(e.signature_bits_delivered));
    REQUIRE_THAT(e.expected_false_matches, WithinRel(by_delivered, 1e-9));
    REQUIRE(e.expected_false_matches < 1e-9);  // 128 bits at these sizes: nowhere near one

    SECTION("limb sensitivity costs the same job at k = 4 and 6 (design §3.8)") {
        const auto rows = limb_sensitivity(request_for(records), e.plan, { 4, 6, 8 });
        REQUIRE(rows.size() == 3);
        for (std::size_t i = 1; i < rows.size(); ++i) {
            REQUIRE(rows[i].input_bytes_self > rows[i - 1].input_bytes_self);
            REQUIRE(rows[i].multiplications > rows[i - 1].multiplications);
            REQUIRE(rows[i].expected_false_matches < rows[i - 1].expected_false_matches);
        }
    }
}

// A single slot sum cannot exceed t - 1, so the count comes back as partial sums
// once a set could pass it (B3-RESULTS.md §1). |A n B| <= min(n_A, n_B), so the
// smaller side decides.
TEST_CASE("the count is grouped only when one sum could overflow, and it is disclosed",
          "[psi][solver]") {
    SECTION("a set within the modulus needs no grouping, and gets no warning") {
        const auto e = solve(request_for(65'536));
        REQUIRE(e.count_groups == 1);
        REQUIRE(e.warnings.empty());
        REQUIRE_FALSE(e.count_exceeds_modulus);
    }

    SECTION("past it, the count is split and the split is warned about in numbers") {
        const auto e = solve(request_for(10'000'000));
        CAPTURE(e.count_groups, e.count_records_per_group, e.count_group_headroom);
        REQUIRE(e.count_groups > 1);
        REQUIRE(std::has_single_bit(e.count_groups));
        REQUIRE(e.count_records_per_group <= 65536.0 / 4);  // 4x headroom under the ceiling
        REQUIRE(e.count_group_headroom >= 4.0);
        REQUIRE_FALSE(e.count_exceeds_modulus);

        // Grouping is free: the partial sums share one ciphertext.
        REQUIRE(e.count_output_bytes == ContextCost{}.ciphertext_bytes());

        REQUIRE(e.warnings.size() == 1);
        REQUIRE(e.warnings[0].code == WarningCode::count_group_leak);
        const auto& text = e.warnings[0].message;
        REQUIRE(text.find(std::to_string(e.count_groups)) != std::string::npos);
        REQUIRE(text.find("65536") != std::string::npos);
    }

    SECTION("the smaller side decides") {
        Request lopsided = request_for(10'000'000);
        lopsided.peer_records = 1'000;
        const auto e = solve(lopsided);
        REQUIRE(e.count_groups == 1);
        REQUIRE(e.warnings.empty());
    }

    SECTION("a count too large for any grouping is refused a quiet answer") {
        const auto e = solve(request_for(3'000'000'000));
        CAPTURE(e.count_groups, e.count_records_per_group);
        REQUIRE(e.count_exceeds_modulus);
        bool flagged = false;
        for (const auto& w : e.warnings) flagged = flagged || w.code == WarningCode::count_not_representable;
        REQUIRE(flagged);
    }
}

TEST_CASE("malformed requests and plans are refused", "[psi][solver]") {
    const auto r = request_for(1000);
    CHECK_THROWS_AS(estimate(r, Plan{ 0, 1, 4, 8 }), std::invalid_argument);
    CHECK_THROWS_AS(estimate(r, Plan{ 1024, 3, 4, 8 }), std::invalid_argument);        // shards not a power of two
    CHECK_THROWS_AS(estimate(r, Plan{ 1000, 16, 4, 8 }), std::invalid_argument);       // shards do not divide the cells

    // A non-power-of-two cell count can be costed - that is what design §2.5 and
    // A1 did - but it cannot be encoded, and the encoder is where that is caught.
    CHECK_NOTHROW(estimate(r, Plan{ 1000, 1, 4, 8 }));
    CHECK_THROWS_AS(build_table({}, Plan{ 1000, 1, 4, 8 }.table_params(), Role::A, OverflowPolicy::fail),
                    std::invalid_argument);
    CHECK_THROWS_AS(estimate(r, Plan{ 1024, 2048, 4, 8 }), std::invalid_argument);     // more shards than cells
    CHECK_THROWS_AS(estimate(r, Plan{ 1024, 1, 0, 8 }), std::invalid_argument);        // no levels
    CHECK_THROWS_AS(estimate(r, Plan{ 1024, 1, 4, 0 }), std::invalid_argument);        // no limbs
    CHECK_THROWS_AS(estimate(r, Plan{ 1024, 1, 4, 9 }), std::invalid_argument);        // beyond the context

    Request bad = r;
    bad.target_drop_rate = 0.0;
    CHECK_THROWS_AS(solve(bad), std::invalid_argument);
    bad = r;
    bad.signature_bits = 0;
    CHECK_THROWS_AS(solve(bad), std::invalid_argument);
    bad = r;
    bad.context.slots = 1000;  // not a power of two
    CHECK_THROWS_AS(solve(bad), std::invalid_argument);
}
