#include "psi/bundle.h"

#include <sstream>
#include <stdexcept>
#include <string>

namespace fhe_toolkit::psi {

namespace {

bool power_of_two(std::uint64_t v) noexcept { return v != 0 && (v & (v - 1)) == 0; }

[[noreturn]] void refuse(const std::string& what) { throw std::invalid_argument("psi bundle: " + what); }

}  // namespace

BundleLayout bundle_layout(const TableParams& params, std::uint64_t groups, std::uint64_t slots) {
    // The same conditions the server checks, so a bundle this builds is never one it refuses.
    if (!power_of_two(params.cells) || params.cells > max_cells)
        refuse("CELLS " + std::to_string(params.cells) + " must be a power of two no larger than 2^32");
    if (params.levels == 0 || params.levels > 4096)
        refuse("TABLES must be between 1 and 4096, not " + std::to_string(params.levels));
    if (params.limbs == 0 || params.limbs > max_limbs)
        refuse("LIMBS must be between 1 and " + std::to_string(max_limbs) + ", not " + std::to_string(params.limbs));
    if (!power_of_two(slots)) refuse("SLOTS " + std::to_string(slots) + " must be a power of two");
    if (!power_of_two(groups) || groups > params.cells || groups > slots)
        refuse("GROUPS " + std::to_string(groups) + " must be a power of two no larger than CELLS "
               + std::to_string(params.cells) + " or SLOTS " + std::to_string(slots));

    BundleLayout l;
    l.cells = params.cells;
    l.tables = params.levels;
    l.limbs = params.limbs;
    l.groups = groups;
    l.slots = slots;
    l.per_level = l.cells >= l.slots;
    if (l.per_level) {
        l.blocks = l.cells / l.slots;
        l.chunks = l.tables * l.tables * l.blocks;
        l.ciphertexts = l.tables * l.blocks * l.limbs;
    } else {
        l.blocks = 1;
        l.chunks = (l.tables * l.tables * l.cells + l.slots - 1) / l.slots;
        l.ciphertexts = l.chunks * l.limbs;
    }
    return l;
}

std::string bundle_header(const BundleLayout& layout, Role role) {
    std::ostringstream out;
    out << "PSI-TABLE v1\n"
        << "ROLE " << (role == Role::A ? 'A' : 'B') << "\n"
        << "CELLS " << layout.cells << "\n"
        << "TABLES " << layout.tables << "\n"
        << "LIMBS " << layout.limbs << "\n"
        << "GROUPS " << layout.groups << "\n"
        << "SLOTS " << layout.slots << "\n"
        << "LAYOUT " << layout.layout_name() << "\n"
        << "CIPHERTEXTS " << layout.ciphertexts << "\n"
        << "PAYLOAD\n";
    return out.str();
}

void bundle_slots(const Table& table, const BundleLayout& layout, std::uint64_t index,
                  std::span<std::int64_t> out) {
    if (index >= layout.ciphertexts)
        refuse("ciphertext " + std::to_string(index) + " of " + std::to_string(layout.ciphertexts));
    if (out.size() != layout.slots)
        refuse("a slot vector holds " + std::to_string(layout.slots) + " values, not "
               + std::to_string(out.size()));
    const TableParams& p = table.params();
    if (p.cells != layout.cells || p.levels != layout.tables || p.limbs != layout.limbs)
        refuse("the table is (cells " + std::to_string(p.cells) + ", tables " + std::to_string(p.levels)
               + ", limbs " + std::to_string(p.limbs) + ") but the layout is (cells "
               + std::to_string(layout.cells) + ", tables " + std::to_string(layout.tables) + ", limbs "
               + std::to_string(layout.limbs) + ")");

    const unsigned j = static_cast<unsigned>(index % layout.limbs);
    const std::uint64_t which = index / layout.limbs;
    if (layout.per_level) {
        const unsigned      level = static_cast<unsigned>(which / layout.blocks);
        const std::uint64_t block = which % layout.blocks;
        for (std::uint64_t s = 0; s < layout.slots; ++s)
            out[s] = table.limb_at(level, j, block * layout.slots + s);
        return;
    }
    // Prealigned: this party's own level varies with the pair, A taking the outer index and B the inner.
    const std::uint64_t positions = layout.tables * layout.tables * layout.cells;
    const std::int64_t  pad = sentinel(table.role(), static_cast<unsigned>(layout.limbs))[j];
    for (std::uint64_t s = 0; s < layout.slots; ++s) {
        const std::uint64_t pos = which * layout.slots + s;
        if (pos >= positions) {
            out[s] = pad;
            continue;
        }
        const std::uint64_t pair = pos / layout.cells, cell = pos % layout.cells;
        const unsigned level = static_cast<unsigned>(table.role() == Role::A ? pair / layout.tables
                                                                            : pair % layout.tables);
        out[s] = table.limb_at(level, j, cell);
    }
}

}  // namespace fhe_toolkit::psi
