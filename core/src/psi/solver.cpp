#include "psi/solver.h"

#include "psi/reference.h"  // plaintext_modulus: the ceiling on a single-slot count

#include <algorithm>
#include <bit>
#include <cmath>
#include <stdexcept>
#include <string>

namespace fhe_toolkit::psi {

namespace {

constexpr unsigned max_levels_searched = 256;  // T beyond this is never the cheap answer

std::uint64_t ceil_div(std::uint64_t a, std::uint64_t b) { return (a + b - 1) / b; }

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

}  // namespace

std::uint64_t ContextCost::ciphertext_bytes() const {
    return 2 * slots * towers * 8;
}

TableParams Plan::table_params() const {
    TableParams p;
    p.cells = cells_per_shard();
    p.levels = levels;
    p.limbs = limbs;
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
    const std::uint64_t ct_bytes = r.context.ciphertext_bytes();

    Estimate e;
    e.plan = p;
    e.records = r.records;
    e.peer_records = peer;

    e.chunks = p.shards * ceil_div(levels * levels * m, n);
    e.multiplications = e.chunks * (16 * p.limbs + p.limbs - 1);
    e.core_seconds = static_cast<double>(e.multiplications) * r.context.seconds_per_mult;

    e.ciphertexts_self = p.shards * ceil_div(levels * m, n) * p.limbs;
    e.input_bytes_self = e.ciphertexts_self * ct_bytes;
    e.input_bytes_peer = e.input_bytes_self;  // same pinned (m, T, k) on both sides
    e.input_bytes_total = e.input_bytes_self + e.input_bytes_peer;

    e.count_output_bytes = ct_bytes;  // one ciphertext, after homomorphic shard aggregation
    e.itemized_output_bytes = p.shards * ceil_div(levels, levels_per_mask) * ceil_div(m, n) * ct_bytes;
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
            + std::to_string(std::llround(e.count_records_per_group))
            + " records you placed in that group of cells, so the other party learns the "
              "intersection's spread across " + std::to_string(e.count_groups)
            + " groups, not only its size." });
    }
    if (e.count_exceeds_modulus) {
        e.warnings.push_back({ WarningCode::count_not_representable,
            "even at " + std::to_string(e.count_groups) + " partial sums, a group can hold ~"
            + std::to_string(std::llround(e.count_records_per_group))
            + " records against a per-sum ceiling of 65536, so the count can overflow and be "
              "reported wrongly. Use fewer records per execution, or shard the job further." });
    }
    return e;
}

Estimate solve(const Request& r) {
    validate_request(r);

    bool found = false;
    Plan best;
    std::uint64_t best_compute = 0;  // T^2 * m_total
    std::uint64_t best_bytes = 0;    // T * m_total, the tie-break
    for (unsigned e = 0; e <= floor_log2(max_cells); ++e) {
        const std::uint64_t cells_total = std::uint64_t{1} << e;
        unsigned limbs = 0;
        try {
            limbs = limbs_for(r.signature_bits, cells_total, r.context.max_limbs);
        } catch (const std::invalid_argument&) {
            continue;  // this cell count cannot carry the requested guarantee
        }
        const unsigned levels = smallest_levels(r.records, cells_total, r.target_drop_rate);
        if (levels == 0) continue;  // no level count meets the target here

        const std::uint64_t compute = std::uint64_t{levels} * levels * cells_total;
        const std::uint64_t bytes = std::uint64_t{levels} * cells_total;
        if (!found || compute < best_compute || (compute == best_compute && bytes < best_bytes)) {
            found = true;
            best_compute = compute;
            best_bytes = bytes;
            best = Plan{ cells_total, 1, levels, limbs };
        }
    }
    if (!found) {
        throw std::invalid_argument("no PSI plan meets a " + std::to_string(r.signature_bits)
                                    + "-bit signature at a drop rate of "
                                    + std::to_string(r.target_drop_rate) + " for "
                                    + std::to_string(r.records) + " records");
    }

    // Split until one shard's upload fits, but never past one ciphertext of
    // cells per shard - below that, sharding only wastes slots.
    const std::uint64_t ct_bytes = r.context.ciphertext_bytes();
    while (best.shards * 2 <= best.cells_total) {
        const std::uint64_t m = best.cells_per_shard();
        const std::uint64_t shard_bytes =
            ceil_div(std::uint64_t{best.levels} * m, r.context.slots) * best.limbs * ct_bytes;
        if (shard_bytes <= r.max_shard_bytes) break;
        if (m <= r.context.slots) break;
        best.shards *= 2;
    }

    const std::uint64_t smaller = r.peer_records != 0 ? std::min(r.records, r.peer_records) : r.records;
    best.count_groups = count_groups_for(smaller, best.cells_per_shard(), r.context.slots);
    return estimate(r, best);
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
