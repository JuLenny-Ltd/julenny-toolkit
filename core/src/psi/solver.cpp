#include "psi/solver.h"

#include "psi/bundle.h"     // bundle_header: the input files begin with it
#include "psi/reference.h"  // plaintext_modulus: the ceiling on a single-slot count

#include <algorithm>
#include <bit>
#include <cmath>
#include <sstream>
#include <stdexcept>
#include <string>
#include <tuple>

namespace fhe_toolkit::psi {

namespace {

constexpr unsigned max_levels_searched = 256;  // T beyond this is never the cheap answer
constexpr unsigned max_levels_tied = 4096;     // the bundle header's TABLES ceiling (psi/bundle)
constexpr double   drop_rate_floor = 0x1p-40;   // drop rates below this tie (decided 2026-09-17)

std::uint64_t ceil_div(std::uint64_t a, std::uint64_t b) { return (a + b - 1) / b; }

// Three significant digits: a group of 0.122 records must not read as "~0".
std::string three_digits(double v) {
    std::ostringstream out;
    out.precision(3);
    out << v;
    return out.str();
}

unsigned floor_log2(std::uint64_t power_of_two) {
    return static_cast<unsigned>(std::bit_width(power_of_two) - 1);
}

void validate_context(const ContextCost& c) {
    if (c.slots == 0 || !std::has_single_bit(c.slots)) {
        throw std::invalid_argument("PSI context slot count must be a power of two, got "
                                    + std::to_string(c.slots));
    }
    if (c.towers == 0) throw std::invalid_argument("PSI context needs at least one tower");
    if (c.max_limbs == 0 || c.max_limbs > max_limbs) {
        throw std::invalid_argument("PSI context supports 1.." + std::to_string(max_limbs)
                                    + " limbs, got " + std::to_string(c.max_limbs));
    }
    if (!(c.seconds_per_mult > 0.0)) {
        throw std::invalid_argument("PSI context needs a positive per-multiplication cost");
    }
}

void validate_request(const Request& r) {
    validate_context(r.context);
    if (r.signature_bits == 0) throw std::invalid_argument("PSI signature must be at least 1 bit");
    if (!(r.target_drop_rate > 0.0) || r.target_drop_rate > 1.0) {
        throw std::invalid_argument("PSI target drop rate must be in (0, 1]");
    }
    if (r.max_shard_bytes == 0) throw std::invalid_argument("PSI max shard bytes must be positive");
}

// Ciphertexts one shard's bundle holds, in the wire form psi/bundle emits:
// per-level from one ciphertext of cells up, prealigned below it.
std::uint64_t bundle_ciphertexts(std::uint64_t levels, std::uint64_t cells, std::uint64_t slots,
                                 std::uint64_t limbs) {
    const std::uint64_t positions = cells < slots ? levels * levels * cells : levels * cells;
    return ceil_div(positions, slots) * limbs;
}

}  // namespace

std::uint64_t ContextCost::ciphertext_bytes() const {
    return 2 * slots * towers * 8;
}

std::uint64_t ContextCost::archive_bytes(std::uint64_t ciphertexts, std::uint64_t header_bytes) const {
    return header_bytes + archive_fixed_bytes + ciphertexts * (ciphertext_bytes() + archived_ciphertext_extra);
}

std::uint64_t ContextCost::single_ciphertext_file_bytes() const {
    return ciphertext_bytes() + single_ciphertext_extra;
}

// Partial sums the count must be split into so no group can reach t. A group
// holds at most the records the smaller side placed in it, so the bound is per
// group on that side; 4x headroom absorbs the spread around the mean, and each
// encoder can verify its own worst group exactly before uploading.
std::uint64_t count_groups_for(std::uint64_t smaller_side, std::uint64_t cells_per_shard,
                               std::uint64_t slots) {
    constexpr std::uint64_t ceiling = plaintext_modulus - 1;
    if (smaller_side <= ceiling) return 1;  // the total itself cannot wrap
    const std::uint64_t cap = std::min(slots, cells_per_shard);
    std::uint64_t groups = 1;
    while (groups < cap && smaller_side > ceiling / 4 * groups) groups *= 2;
    return groups;
}

// Smallest T whose expected drop rate meets the target, or 0 if none does
// within the search cap.
unsigned smallest_levels(std::uint64_t records, std::uint64_t cells_total, double target) {
    if (records == 0) return 1;
    const double budget = target * static_cast<double>(records);
    for (unsigned levels = 1; levels <= max_levels_searched; ++levels) {
        if (expected_dropped_records(records, cells_total, levels) <= budget) return levels;
    }
    return 0;
}

TableParams Plan::table_params() const { return table_params(0); }

TableParams Plan::table_params(std::uint64_t which_shard) const {
    TableParams p;
    p.cells = cells_per_shard();
    p.levels = levels;
    p.limbs = limbs;
    p.shards = shards;
    p.shard = which_shard;
    return p;
}

unsigned limbs_for(unsigned signature_bits, std::uint64_t cells_total, unsigned context_max_limbs) {
    if (cells_total == 0 || cells_total > max_cells || !std::has_single_bit(cells_total)) {
        throw std::invalid_argument("PSI cell count must be a power of two in [1, 2^32], got "
                                    + std::to_string(cells_total));
    }
    if (signature_bits == 0) throw std::invalid_argument("PSI signature must be at least 1 bit");
    // The cell alignment has already verified the address, so only the rest has
    // to be stored (design §2.1).
    const unsigned address_bits = floor_log2(cells_total);
    const unsigned stored = signature_bits > address_bits ? signature_bits - address_bits : 0;
    const unsigned needed = std::max(1u, (stored + limb_bits - 1) / limb_bits);
    if (needed > context_max_limbs) {
        throw std::invalid_argument(
            "a " + std::to_string(signature_bits) + "-bit signature over "
            + std::to_string(cells_total) + " cells needs " + std::to_string(needed)
            + " limbs, but this context carries at most " + std::to_string(context_max_limbs)
            + " (A1: depth 19 is the last depth with packed slots at t = 65537)");
    }
    return needed;
}

Estimate estimate(const Request& r, const Plan& p) {
    validate_request(r);
    // Any cell count can be COSTED: design §2.5's table and A1's measurements
    // both cost m = n, which is rarely a power of two. The power-of-two rule
    // belongs to the encoding - position() and build_table enforce it, and
    // solve() only ever returns one.
    if (p.cells_total == 0 || p.cells_total > max_cells) {
        throw std::invalid_argument("PSI plan cell count must be in [1, 2^32], got "
                                    + std::to_string(p.cells_total));
    }
    if (p.shards == 0 || !std::has_single_bit(p.shards) || p.shards > p.cells_total
        || p.cells_total % p.shards != 0) {
        throw std::invalid_argument("PSI plan shard count must be a power of two dividing the cell "
                                    "count, got " + std::to_string(p.shards));
    }
    if (p.levels == 0) throw std::invalid_argument("PSI plan needs at least one level");
    if (p.peer_levels != 0 && p.peer_levels != p.levels && p.cells_per_shard() < r.context.slots) {
        throw std::invalid_argument("PSI tables below one ciphertext of cells are stored prealigned, whose "
                                    "layout depends on both parties' T; they must use the same T, not "
                                    + std::to_string(p.levels) + " and " + std::to_string(p.peer_levels));
    }
    if (p.limbs == 0 || p.limbs > r.context.max_limbs) {
        throw std::invalid_argument("PSI plan needs 1.." + std::to_string(r.context.max_limbs)
                                    + " limbs, got " + std::to_string(p.limbs));
    }
    if (p.count_groups == 0 || !std::has_single_bit(p.count_groups)
        || p.count_groups > p.cells_per_shard() || p.count_groups > r.context.slots) {
        throw std::invalid_argument("PSI count grouping must be a power of two, no larger than the "
                                    "slot count or the cells in one shard, got "
                                    + std::to_string(p.count_groups));
    }

    const std::uint64_t peer = r.peer_records != 0 ? r.peer_records : r.records;
    const std::uint64_t n = r.context.slots;
    const std::uint64_t m = p.cells_per_shard();
    const std::uint64_t levels = p.levels;

    Estimate e;
    e.plan = p;
    e.records = r.records;
    e.peer_records = peer;

    const std::uint64_t peer_levels = p.peer_levels != 0 ? p.peer_levels : levels;
    e.chunks = p.shards * ceil_div(levels * peer_levels * m, n);
    e.multiplications = e.chunks * (16 * p.limbs + p.limbs - 1);
    e.core_seconds = static_cast<double>(e.multiplications) * r.context.seconds_per_mult;

    // Each shard is one bundle file: its header, then one archive of its ciphertexts.
    // The header is the encoder's own; both roles give it the same length.
    const std::uint64_t shard_ciphertexts = bundle_ciphertexts(levels, m, n, p.limbs);
    BundleLayout header_layout;
    header_layout.cells = m;
    header_layout.tables = levels;
    header_layout.limbs = p.limbs;
    header_layout.groups = p.count_groups;
    header_layout.slots = n;
    header_layout.per_level = m >= n;
    header_layout.ciphertexts = shard_ciphertexts;
    header_layout.shards = p.shards;
    // The last shard's index is the longest one to print, so its header is the largest; quoting the
    // largest keeps the estimate an upper bound on every shard rather than a figure only shard 0
    // meets. The difference is single digits of bytes, but "predicted <= written" is the property
    // step D3's evidence rests on.
    header_layout.shard = p.shards - 1;
    const std::uint64_t header_bytes = bundle_header(header_layout, Role::A).size();

    e.prealigned = m < n;
    e.ciphertexts_self = p.shards * shard_ciphertexts;
    e.input_bytes_self = p.shards * r.context.archive_bytes(shard_ciphertexts, header_bytes);
    e.input_bytes_peer = e.input_bytes_self;  // same pinned (m, T, k) on both sides
    e.input_bytes_total = e.input_bytes_self + e.input_bytes_peer;
    e.input_objects = p.shards;

    // One ciphertext, after homomorphic shard aggregation, written as a result file.
    e.count_output_bytes = r.context.single_ciphertext_file_bytes();
    e.itemized_output_ciphertexts = p.shards * ceil_div(levels, levels_per_mask) * ceil_div(m, n);
    e.itemized_output_bytes = e.itemized_output_ciphertexts * r.context.single_ciphertext_file_bytes();
    e.peer_decrypt_bytes = e.itemized_output_bytes;

    e.expected_overflowed_cells = expected_overflowed_cells(r.records, p.cells_total, p.levels);
    e.expected_drop_rate = r.records == 0
        ? 0.0
        : expected_dropped_records(r.records, p.cells_total, p.levels) / static_cast<double>(r.records);
    // Same-cell cross pairs x the chance a pair agrees on every stored limb.
    // Equivalently n_A * n_B * 2^-(16k + log2 m_total): the address pays too.
    e.expected_false_matches = static_cast<double>(r.records) * static_cast<double>(peer)
                             / static_cast<double>(p.cells_total)
                             * std::ldexp(1.0, -static_cast<int>(16 * p.limbs));
    e.signature_bits_delivered = 16 * p.limbs + floor_log2(p.cells_total);

    // The count comes back as count_groups partial sums in one ciphertext.
    const std::uint64_t smaller = std::min(r.records, peer);
    e.count_groups = p.count_groups;
    e.count_records_per_group = static_cast<double>(smaller) / static_cast<double>(p.count_groups);
    e.count_group_headroom = e.count_records_per_group > 0.0
        ? static_cast<double>(plaintext_modulus - 1) / e.count_records_per_group
        : 0.0;
    // Strictly greater: a group holding exactly t - 1 = 65536 records still fits
    // in a slot, which is why count_groups_for treats that size as ungrouped.
    e.count_exceeds_modulus = e.count_records_per_group > static_cast<double>(plaintext_modulus - 1);

    if (e.count_groups > 1) {
        e.warnings.push_back({ WarningCode::count_group_leak,
            "the count comes back as " + std::to_string(e.count_groups)
            + " partial sums rather than one number, because a single sum cannot exceed 65536. "
              "Each partial sum says how many matches fell among the ~"
            + three_digits(e.count_records_per_group)
            + " records you placed in that group of cells, so the other party learns the "
              "intersection's spread across " + std::to_string(e.count_groups)
            + " groups, not only its size." });
    }
    if (e.count_exceeds_modulus) {
        e.warnings.push_back({ WarningCode::count_not_representable,
            "even at " + std::to_string(e.count_groups) + " partial sums, a group can hold ~"
            + three_digits(e.count_records_per_group)
            + " records against a per-sum ceiling of 65536, so the count can overflow and be "
              "reported wrongly. Use fewer records per execution, or shard the job further." });
    }
    return e;
}

Estimate solve(const Request& r) {
    validate_request(r);

    // Cells and tables (D3-RESULTS.md §2a, rule 3). Every power-of-two m is searched, and
    // ciphertexts are counted in the form the encoder writes: T^2 * m below N (prealigned),
    // T * m from N (per-level). Among plans meeting the drop-rate target:
    //   1. fewest ciphertexts per party - the upload;
    //   then, between plans that tie on it (decided 2026-09-17):
    //   2. the smaller expected drop rate - but every rate below 2^-40 counts as equal, or
    //      the budget fills with ever more tables for no practical gain (8 x 64 at 120 records),
    //   3. less communication - bundle plus itemized-result ciphertexts (the result grows
    //      with T); counted in ciphertexts, so a header digit never decides,
    //   4. less compute - chunks,
    //   5. fewer tables.
    // Adding tables at a fixed m never lowers the ciphertext count and never raises the
    // drop rate, so for each m only its largest T within the winning ciphertext count
    // can win the tie-break.
    struct Candidate {
        std::uint64_t cells;
        unsigned      levels;
        unsigned      limbs;
    };
    std::vector<Candidate> minimal;  // for each m, its smallest adequate T
    std::uint64_t fewest = 0;
    for (unsigned e = r.per_level_only ? floor_log2(r.context.slots) : 0; e <= floor_log2(max_cells); ++e) {
        const std::uint64_t cells_total = std::uint64_t{1} << e;
        unsigned limbs = 0;
        try {
            limbs = limbs_for(r.signature_bits, cells_total, r.context.max_limbs);
        } catch (const std::invalid_argument&) {
            continue;  // this cell count cannot carry the requested guarantee
        }
        const unsigned levels = smallest_levels(r.records, cells_total, r.target_drop_rate);
        if (levels == 0) continue;  // no level count meets the target here
        const std::uint64_t cts = bundle_ciphertexts(levels, cells_total, r.context.slots, limbs);
        if (minimal.empty() || cts < fewest) fewest = cts;
        minimal.push_back({ cells_total, levels, limbs });
    }
    if (minimal.empty()) {
        throw std::invalid_argument("no PSI plan meets a " + std::to_string(r.signature_bits)
                                    + "-bit signature at a drop rate of "
                                    + std::to_string(r.target_drop_rate) + " for "
                                    + std::to_string(r.records) + " records");
    }

    const std::uint64_t smaller = r.peer_records != 0 ? std::min(r.records, r.peer_records) : r.records;
    bool found = false;
    Plan best;
    Estimate best_estimate;
    for (const auto& c : minimal) {
        if (bundle_ciphertexts(c.levels, c.cells, r.context.slots, c.limbs) != fewest) continue;
        unsigned levels = c.levels;
        while (levels < max_levels_tied
               && bundle_ciphertexts(levels + 1, c.cells, r.context.slots, c.limbs) == fewest) {
            ++levels;
        }
        Plan plan{ c.cells, 1, levels, c.limbs };
        plan.count_groups = count_groups_for(smaller, plan.cells_per_shard(), r.context.slots);
        const Estimate e = estimate(r, plan);
        const auto floored = [](double rate) { return rate < drop_rate_floor ? 0.0 : rate; };
        const auto communication = [](const Estimate& x) { return x.ciphertexts_self + x.itemized_output_ciphertexts; };
        const double drop = floored(e.expected_drop_rate), best_drop = floored(best_estimate.expected_drop_rate);
        const auto key = [&](const Estimate& x, double d) {
            return std::make_tuple(d, communication(x), x.chunks, x.plan.levels);
        };
        const bool better = !found || key(e, drop) < key(best_estimate, best_drop);
        if (better) {
            found = true;
            best = plan;
            best_estimate = e;
        }
    }

    // Split until one shard's upload fits, but never past one ciphertext of
    // cells per shard - below that, sharding only wastes slots.
    const std::uint64_t ct_bytes = r.context.ciphertext_bytes();
    while (best.shards * 2 <= best.cells_total) {
        const std::uint64_t m = best.cells_per_shard();
        const std::uint64_t shard_bytes =
            bundle_ciphertexts(best.levels, m, r.context.slots, best.limbs) * ct_bytes;
        if (shard_bytes <= r.max_shard_bytes) break;
        if (m <= r.context.slots) break;
        best.shards *= 2;
    }

    best.count_groups = count_groups_for(smaller, best.cells_per_shard(), r.context.slots);
    return estimate(r, best);
}

unsigned likely_fullest_cell(std::uint64_t records, std::uint64_t cells, double probability) {
    if (cells == 0) throw std::invalid_argument("PSI cell count must be positive");
    if (!(probability > 0.0) || !(probability < 1.0)) {
        throw std::invalid_argument("PSI fullest-cell probability must be in (0, 1)");
    }
    if (records == 0) return 0;
    // P(max <= T) = F(T)^m for independent Poisson(lambda) loads: the smallest T with
    // m * log F(T) >= log p. The pmf is walked in log space so a large lambda does not underflow.
    const double lambda = static_cast<double>(records) / static_cast<double>(cells);
    const double target = std::log(probability) / static_cast<double>(cells);
    double log_pmf = -lambda;  // log P(X = 0)
    double cdf = std::exp(log_pmf);
    for (unsigned t = 0; t < 1u << 20; ++t) {
        if (cdf > 0.0 && std::log(std::min(cdf, 1.0)) >= target) return t;
        log_pmf += std::log(lambda) - std::log(static_cast<double>(t + 1));
        cdf += std::exp(log_pmf);
    }
    return 1u << 20;
}

std::vector<Estimate> limb_sensitivity(const Request& r, const Plan& p,
                                       const std::vector<unsigned>& limbs) {
    std::vector<Estimate> out;
    out.reserve(limbs.size());
    for (const auto k : limbs) {
        Plan variant = p;
        variant.limbs = k;
        out.push_back(estimate(r, variant));
    }
    return out;
}

}  // namespace fhe_toolkit::psi
