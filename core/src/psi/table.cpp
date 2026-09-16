#include "psi/table.h"

#include <algorithm>
#include <bit>
#include <cmath>
#include <cstdio>
#include <utility>

namespace fhe_toolkit::psi {

namespace {

void validate(const TableParams& p) {
    if (p.cells == 0 || p.cells > max_cells || !std::has_single_bit(p.cells)) {
        throw std::invalid_argument("PSI table cell count must be a power of two in [1, 2^32], got "
                                    + std::to_string(p.cells));
    }
    if (p.levels == 0) {
        throw std::invalid_argument("PSI table needs at least one level");
    }
    if (p.limbs == 0 || p.limbs > max_limbs) {
        throw std::invalid_argument("PSI table needs 1.." + std::to_string(max_limbs)
                                    + " limbs, got " + std::to_string(p.limbs));
    }
    if (p.cells > std::numeric_limits<std::size_t>::max() / p.levels) {
        throw std::invalid_argument("PSI table of " + std::to_string(p.levels) + " levels x "
                                    + std::to_string(p.cells) + " cells is not addressable");
    }
}

// True when the first `limbs` limbs of d spell a sentinel: 0 (all zero) or 1
// (limb 0 = 1, the rest zero). High limbs are checked first, so a real record
// costs one limb read on all but ~2^-16 of digests.
bool on_sentinel(const Digest& d, unsigned limbs) {
    for (unsigned j = limbs; j-- > 1;) {
        if (limb(d, j) != 0) return false;
    }
    return limb(d, 0) <= 1;
}

std::string percent(std::uint64_t num, std::uint64_t den) {
    char buf[32];
    std::snprintf(buf, sizeof buf, "%.2f %%",
                  100.0 * static_cast<double>(num) / static_cast<double>(den));
    return buf;
}

// Per-cell P(X > T) and E[(X - T)+] for X ~ Poisson(lambda).
struct Tail {
    double overflow = 0.0;
    double excess   = 0.0;
};

double poisson_pmf(double lambda, unsigned x) {
    const double dx = static_cast<double>(x);
    return std::exp(-lambda + dx * std::log(lambda) - std::lgamma(dx + 1.0));
}

Tail poisson_tail(double lambda, unsigned levels) {
    if (lambda <= 0.0) return {};
    const double t = static_cast<double>(levels);
    Tail out;
    if (t + 1.0 <= lambda) {
        // T at or below the mean: the tail is most of the mass, so 1 - CDF is
        // accurate - and summing upward from T+1 could start in underflow.
        double cdf = 0.0;
        double short_by = 0.0;  // E[(T - X)+]
        for (unsigned x = 0; x <= levels; ++x) {
            const double p = poisson_pmf(lambda, x);
            cdf += p;
            short_by += (t - static_cast<double>(x)) * p;
        }
        out.overflow = std::max(0.0, 1.0 - cdf);
        out.excess = lambda - t + short_by;
        return out;
    }
    // T above the mean: sum the tail directly, from its largest term down. The
    // tails the solver sizes against are ~1e-10, far below where 1 - CDF would
    // cancel to rounding noise.
    double p = poisson_pmf(lambda, levels + 1);
    for (unsigned x = levels + 1; p > 0.0 && x - levels < 100000; ++x) {
        out.overflow += p;
        out.excess += static_cast<double>(x - levels) * p;
        if (p <= out.overflow * 1e-18) break;
        p *= lambda / (static_cast<double>(x) + 1.0);
    }
    return out;
}

Tail model(std::uint64_t records, std::uint64_t cells, unsigned levels) {
    if (cells == 0) throw std::invalid_argument("PSI occupancy model needs at least one cell");
    return poisson_tail(static_cast<double>(records) / static_cast<double>(cells), levels);
}

}  // namespace

double PlacementReport::drop_rate() const noexcept {
    return records == 0 ? 0.0 : static_cast<double>(dropped) / static_cast<double>(records);
}

TableOverflow::TableOverflow(const std::string& what, PlacementReport report)
    : std::runtime_error(what), report_(report) {}

std::vector<std::uint16_t> stored_signature(const Digest& d, unsigned limbs) {
    auto s = signature(d, limbs);
    if (on_sentinel(d, limbs)) s[0] = static_cast<std::uint16_t>(s[0] + 2);
    return s;
}

std::vector<std::uint16_t> sentinel(Role role, unsigned limbs) {
    if (limbs == 0 || limbs > max_limbs) {
        throw std::invalid_argument("PSI sentinel needs 1.." + std::to_string(max_limbs)
                                    + " limbs, got " + std::to_string(limbs));
    }
    std::vector<std::uint16_t> s(limbs, 0);
    if (role == Role::B) s[0] = 1;
    return s;
}

Table build_table(std::vector<Digest> digests, const TableParams& params, Role role,
                  OverflowPolicy policy) {
    validate(params);
    Table t;
    t.params_ = params;
    t.role_ = role;
    PlacementReport& r = t.report_;
    r.rows = digests.size();
    r.duplicates = dedupe(digests);  // also sorts: placement order is digest order
    r.records = digests.size();
    if (r.records >= Table::empty) {
        throw std::invalid_argument("PSI table holds at most 2^32 - 2 distinct records");
    }

    const std::uint64_t cells = params.cells;
    t.occupant_.assign(static_cast<std::size_t>(params.levels * cells), Table::empty);
    std::vector<std::uint32_t> load(static_cast<std::size_t>(cells), 0);
    for (std::size_t i = 0; i < digests.size(); ++i) {
        const std::uint32_t cell = position(digests[i], cells);
        const std::uint32_t level = load[cell]++;
        if (level < params.levels) {
            t.occupant_[level * cells + cell] = static_cast<std::uint32_t>(i);
            ++r.placed;
            if (on_sentinel(digests[i], params.limbs)) ++r.remapped;
        } else {
            t.dropped_.push_back(digests[i]);
        }
    }
    r.dropped = t.dropped_.size();
    for (const auto l : load) {
        if (l > params.levels) ++r.overflowed_cells;
        r.cell_max_load = std::max<std::uint64_t>(r.cell_max_load, l);
    }
    t.records_ = std::move(digests);

    if (r.dropped > 0 && policy == OverflowPolicy::fail) {
        throw TableOverflow("PSI table overflow: " + std::to_string(r.dropped) + " of "
                                + std::to_string(r.records) + " records did not fit ("
                                + std::to_string(r.overflowed_cells) + " cells had more than "
                                + std::to_string(params.levels) + " records, at most "
                                + std::to_string(r.cell_max_load)
                                + "). Re-encode with more cells or tables.",
                            r);
    }
    if (r.dropped * 100 > r.records * max_drop_percent) {
        throw TableOverflow("PSI table drop rate " + percent(r.dropped, r.records) + " ("
                                + std::to_string(r.dropped) + " of " + std::to_string(r.records)
                                + " records) exceeds the " + std::to_string(max_drop_percent)
                                + " % ceiling. Re-encode with more cells or tables.",
                            r);
    }
    return t;
}

std::uint32_t Table::occupant(unsigned level, std::uint64_t cell) const {
    if (level >= params_.levels || cell >= params_.cells) {
        throw std::out_of_range("PSI table position (level " + std::to_string(level) + ", cell "
                                + std::to_string(cell) + ") out of range");
    }
    return occupant_[level * params_.cells + cell];
}

std::uint16_t Table::value_limb(std::uint32_t occ, unsigned j) const {
    if (occ == empty) return (j == 0 && role_ == Role::B) ? 1 : 0;
    const Digest& d = records_[occ];
    const std::uint16_t v = limb(d, j);
    return (j == 0 && on_sentinel(d, params_.limbs)) ? static_cast<std::uint16_t>(v + 2) : v;
}

std::uint16_t Table::limb_at(unsigned level, unsigned j, std::uint64_t cell) const {
    if (j >= params_.limbs) {
        throw std::out_of_range("PSI limb " + std::to_string(j) + " out of range");
    }
    return value_limb(occupant(level, cell), j);
}

std::vector<std::uint16_t> Table::signature_at(unsigned level, std::uint64_t cell) const {
    const auto occ = occupant(level, cell);
    std::vector<std::uint16_t> out(params_.limbs);
    for (unsigned j = 0; j < params_.limbs; ++j) out[j] = value_limb(occ, j);
    return out;
}

void Table::fill_limb_row(unsigned level, unsigned j, std::span<std::uint16_t> out) const {
    if (level >= params_.levels || j >= params_.limbs) {
        throw std::out_of_range("PSI table row (level " + std::to_string(level) + ", limb "
                                + std::to_string(j) + ") out of range");
    }
    if (out.size() != params_.cells) {
        throw std::invalid_argument("PSI limb row needs " + std::to_string(params_.cells)
                                    + " slots, got " + std::to_string(out.size()));
    }
    const std::uint32_t* row = occupant_.data() + level * params_.cells;
    for (std::size_t c = 0; c < out.size(); ++c) out[c] = value_limb(row[c], j);
}

double expected_overflowed_cells(std::uint64_t records, std::uint64_t cells, unsigned levels) {
    return static_cast<double>(cells) * model(records, cells, levels).overflow;
}

double expected_dropped_records(std::uint64_t records, std::uint64_t cells, unsigned levels) {
    return static_cast<double>(cells) * model(records, cells, levels).excess;
}

}  // namespace fhe_toolkit::psi
