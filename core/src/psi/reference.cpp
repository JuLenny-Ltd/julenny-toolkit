#include "psi/reference.h"

#include <algorithm>
#include <bit>
#include <stdexcept>
#include <string>

namespace fhe_toolkit::psi {

namespace {

constexpr std::uint64_t t = plaintext_modulus;

// fermat[d] = 1 - d^(t-1) mod t for every residue d, by fermat_indicator's own
// squarings. The reference's comparisons all go through this table.
const std::vector<std::uint32_t>& fermat_table() {
    static const std::vector<std::uint32_t> table = [] {
        std::vector<std::uint32_t> out(plaintext_modulus);
        for (std::uint32_t d = 0; d < plaintext_modulus; ++d) out[d] = fermat_indicator(d);
        return out;
    }();
    return table;
}

std::uint32_t sub_mod(std::uint16_t a, std::uint16_t b) {
    return static_cast<std::uint32_t>((a + t - b) % t);
}

void check_compatible(const Table& x, const Table& y) {
    const auto& p = x.params();
    const auto& q = y.params();
    if (p.cells != q.cells || p.levels != q.levels || p.limbs != q.limbs) {
        throw std::invalid_argument(
            "PSI tables disagree on (cells, levels, limbs): (" + std::to_string(p.cells) + ", "
            + std::to_string(p.levels) + ", " + std::to_string(p.limbs) + ") vs ("
            + std::to_string(q.cells) + ", " + std::to_string(q.levels) + ", "
            + std::to_string(q.limbs) + "); comparing them would give a meaningless count");
    }
    if (x.role() == y.role()) {
        throw std::invalid_argument(
            "PSI tables are both the same party's: their empty cells share a sentinel and "
            "would all match each other");
    }
}

// Limb 0 of every level, row by row: the comparison loop streams these, and
// only fetches limbs 1.. when limb 0 already agrees.
std::vector<std::vector<std::uint16_t>> limb0_rows(const Table& x) {
    const auto& p = x.params();
    std::vector<std::vector<std::uint16_t>> rows(p.levels, std::vector<std::uint16_t>(p.cells));
    for (unsigned level = 0; level < p.levels; ++level) x.fill_limb_row(level, 0, rows[level]);
    return rows;
}

// Runs fn(level_x, level_y, cell, eq) for every compared pair whose eq is
// nonzero. eq is the product over limbs of the Fermat indicators, mod t, taken
// limb by limb; once it is 0 it stays 0 in Z_t, so stopping there is exact.
template <class Fn>
void for_each_equal_pair(const Table& x, const Table& y, Fn fn) {
    const auto& p = x.params();
    const auto& fermat = fermat_table();
    const auto rx = limb0_rows(x);
    const auto ry = limb0_rows(y);
    for (unsigned jx = 0; jx < p.levels; ++jx) {
        for (unsigned jy = 0; jy < p.levels; ++jy) {
            const auto& ax = rx[jx];
            const auto& ay = ry[jy];
            for (std::uint64_t cell = 0; cell < p.cells; ++cell) {
                std::uint64_t eq = fermat[sub_mod(ax[cell], ay[cell])];
                for (unsigned j = 1; j < p.limbs && eq != 0; ++j) {
                    eq = eq * fermat[sub_mod(x.limb_at(jx, j, cell), y.limb_at(jy, j, cell))] % t;
                }
                if (eq != 0) fn(jx, jy, cell, static_cast<std::uint32_t>(eq));
            }
        }
    }
}

}  // namespace

std::uint32_t fermat_indicator(std::uint32_t d) {
    if (d >= plaintext_modulus) {
        throw std::out_of_range("Fermat indicator needs a residue below t, got " + std::to_string(d));
    }
    std::uint64_t x = d;
    for (int i = 0; i < 16; ++i) x = x * x % t;  // d^(2^16) = d^(t-1)
    return static_cast<std::uint32_t>((1 + t - x) % t);
}

std::int64_t centered(std::uint32_t r) {
    if (r >= plaintext_modulus) {
        throw std::out_of_range("not a residue mod t: " + std::to_string(r));
    }
    return r <= (plaintext_modulus - 1) / 2 ? std::int64_t{r} : std::int64_t{r} - std::int64_t{t};
}

std::uint32_t residue(std::int64_t decoded) {
    const auto m = static_cast<std::int64_t>(t);
    return static_cast<std::uint32_t>(((decoded % m) + m) % m);
}

CountResult reference_count(const Table& a, const Table& b, unsigned groups) {
    check_compatible(a, b);
    const auto& p = a.params();
    if (groups == 0 || !std::has_single_bit(groups) || groups > p.cells) {
        throw std::invalid_argument("PSI count grouping must be a power of two no larger than the "
                                    + std::to_string(p.cells) + " cells, got "
                                    + std::to_string(groups));
    }

    CountResult r;
    r.groups = groups;
    r.per_cell.assign(static_cast<std::size_t>(p.cells), 0);
    for_each_equal_pair(a, b, [&](unsigned, unsigned, std::uint64_t cell, std::uint32_t eq) {
        r.per_cell[cell] = static_cast<std::uint32_t>((r.per_cell[cell] + eq) % t);
    });
    for (const auto v : r.per_cell) r.matches += v;
    r.count_mod_t = static_cast<std::uint32_t>(r.matches % t);

    // group(cell) = cell mod L: what rotating by strides L, 2L, ... N/2 leaves
    // in slot i. Summed as integers first, so a group that would wrap is visible
    // rather than silently reduced.
    std::vector<std::uint64_t> totals(groups, 0);
    for (std::uint64_t cell = 0; cell < p.cells; ++cell) totals[cell % groups] += r.per_cell[cell];
    r.group_sums.resize(groups);
    for (unsigned g = 0; g < groups; ++g) {
        r.group_wrapped = r.group_wrapped || totals[g] >= t;
        r.group_sums[g] = static_cast<std::uint32_t>(totals[g] % t);
    }
    return r;
}

std::uint64_t count_from_groups(const std::vector<std::uint32_t>& group_sums) {
    std::uint64_t total = 0;
    for (const auto v : group_sums) {
        if (v >= plaintext_modulus) {
            throw std::invalid_argument("PSI partial sum " + std::to_string(v)
                                        + " is not a residue mod t; decode with residue() first");
        }
        total += v;
    }
    return total;
}

ItemizedResult reference_itemized(const Table& viewer, const Table& other) {
    check_compatible(viewer, other);
    const auto& p = viewer.params();
    ItemizedResult r;
    r.indicators.assign(static_cast<std::size_t>(p.levels * p.cells), 0);
    for_each_equal_pair(viewer, other, [&](unsigned jv, unsigned, std::uint64_t cell, std::uint32_t eq) {
        auto& ind = r.indicators[jv * p.cells + cell];
        ind = static_cast<std::uint32_t>((ind + eq) % t);
    });

    const unsigned masks = (p.levels + levels_per_mask - 1) / levels_per_mask;
    r.masks.assign(masks, std::vector<std::uint32_t>(static_cast<std::size_t>(p.cells), 0));
    for (unsigned level = 0; level < p.levels; ++level) {
        const unsigned q = level / levels_per_mask;
        const std::uint64_t weight = std::uint64_t{1} << (level % levels_per_mask);
        for (std::uint64_t cell = 0; cell < p.cells; ++cell) {
            auto& v = r.masks[q][cell];
            v = static_cast<std::uint32_t>((v + weight * r.indicators[level * p.cells + cell]) % t);
        }
    }
    return r;
}

std::vector<Digest> resolve_matches(const Table& viewer,
                                    const std::vector<std::vector<std::uint32_t>>& masks) {
    const auto& p = viewer.params();
    const unsigned expected = (p.levels + levels_per_mask - 1) / levels_per_mask;
    if (masks.size() != expected) {
        throw std::invalid_argument("PSI itemized result needs " + std::to_string(expected)
                                    + " masks for " + std::to_string(p.levels) + " levels, got "
                                    + std::to_string(masks.size()));
    }
    std::vector<Digest> out;
    for (unsigned q = 0; q < masks.size(); ++q) {
        if (masks[q].size() != p.cells) {
            throw std::invalid_argument("PSI itemized mask " + std::to_string(q) + " has "
                                        + std::to_string(masks[q].size()) + " slots, expected "
                                        + std::to_string(p.cells));
        }
        for (std::uint64_t cell = 0; cell < p.cells; ++cell) {
            const std::uint32_t v = masks[q][cell];
            if (v >> levels_per_mask) {
                throw std::runtime_error("PSI itemized mask value " + std::to_string(v)
                                         + " at cell " + std::to_string(cell)
                                         + " is not a 16-bit mask");
            }
            for (unsigned bit = 0; bit < levels_per_mask; ++bit) {
                if (((v >> bit) & 1u) == 0) continue;
                const unsigned level = q * levels_per_mask + bit;
                const auto occ = level < p.levels ? viewer.occupant(level, cell) : Table::empty;
                if (occ == Table::empty) {
                    throw std::runtime_error("PSI itemized mask marks level " + std::to_string(level)
                                             + " of cell " + std::to_string(cell)
                                             + ", which holds no record");
                }
                out.push_back(viewer.records()[occ]);
            }
        }
    }
    std::sort(out.begin(), out.end());
    return out;
}

}  // namespace fhe_toolkit::psi
