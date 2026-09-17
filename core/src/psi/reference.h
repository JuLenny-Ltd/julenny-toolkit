#ifndef FHE_TOOLKIT_PSI_REFERENCE_H
#define FHE_TOOLKIT_PSI_REFERENCE_H

// Plaintext reference for the exact-PSI circuit (platform
// plans/exact-psi-signature-tables.md §2.3): the same comparisons, in the same
// arithmetic, in the clear. Every later FHE step is checked against this.
//
// Per compared pair of slot-aligned values a (party A, level ja) and b (party B,
// level jb) at one cell, exactly as the circuit does it, mod t = 65537:
//
//   d_j   = a_j - b_j                      j = 0 .. k-1
//   z_j   = 1 - d_j^(t-1)                  Fermat, by 16 squarings: 1 iff d_j = 0
//   eq    = z_0 · z_1 · … · z_{k-1}        the AND over limbs, as a product
//   acc   = Σ eq over all T^2 level pairs, per cell
//   count = Σ acc over all cells, mod t    what EvalSum leaves in the slot
//
// The Fermat step is not restated as `a == b`: every indicator comes from a table
// of 1 - d^(t-1) computed by the circuit's own 16 squarings over all t residues,
// so a wrong exponent here shows up in the counts, not only in a unit test.
//
// Every slot is compared, empty ones included - the circuit cannot skip them, so
// neither does the reference. The sentinels (psi/table) are what keep them out
// of the count.
//
// The itemized variant sums away only the OTHER party's levels - its level
// assignment is its own business - and keeps the viewer's T levels apart, since
// a level is where a collision on the viewer's own side put the record. The T
// levels are then bit-packed, 16 per slot: bit j is level j, so the packing is
// lossless as long as each indicator is 0/1. It is 0/1 unless two of the other
// party's records in one cell share a stored signature, which needs a 2^-16k
// coincidence (2^-128 at the default k = 8).
//
// The final sum is mod t, so folding every slot into one caps the count at
// t - 1 = 65536 (B3-RESULTS.md §1). The count is therefore returned as `groups`
// partial sums instead of one number:
//
//   the circuit stops the slot-sum early and rotates by STRIDES - L, 2L, 4L,
//   ... N/2 - after which slot i holds the sum over every slot congruent to
//   i mod L. That is a clean partition into L groups, with every slot of a
//   group carrying its group's total, and every rotation index a power of two,
//   so the existing EvalSum keys already cover it.
//
// (Stopping the ordinary EvalSum partway would instead leave sliding windows,
// whose differences expose individual slots - much more than the total.)
//
// The L values sit in one ciphertext, so the result does not grow, and the
// client adds them in the clear. A group wraps only if it gathers t matches,
// and a group's matches cannot exceed the records that party placed in it, so
// each side can verify its own maximum group load before uploading. L = 1 is
// the old single-slot form and is all a set of at most 65 536 records needs.
//
// What this costs is disclosure: L partial sums say how many matches fell in
// each group of cells, not only the total. psi/solver warns about it.

#include <cstdint>
#include <vector>

#include "psi/digest.h"
#include "psi/table.h"

namespace fhe_toolkit::psi {

// t: the BFV plaintext modulus of the exact-PSI context. t - 1 = 2^16.
constexpr std::uint32_t plaintext_modulus = 65537;

// Levels one itemized mask carries: 2^16 - 1 < t, so 16 bits never wrap.
constexpr unsigned levels_per_mask = 16;

// 1 - d^(t-1) mod t, by the circuit's 16 squarings. d must be in [0, t).
std::uint32_t fermat_indicator(std::uint32_t d);

// What OpenFHE's packed BFV decode reports for a residue r in [0, t): r itself
// up to (t-1)/2 = 32768, r - t above it (measured, OpenFHE 1.5).
std::int64_t centered(std::uint32_t residue);

// The inverse: a decoded slot value back to its residue in [0, t).
std::uint32_t residue(std::int64_t decoded);

struct CountResult {
    // Σ_{ja, jb} eq at each cell: the circuit's accumulator before the slot sum.
    // Layout-independent (one entry per cell); C2 folds it into its slot layout.
    std::vector<std::uint32_t> per_cell;
    // Σ per_cell as an integer: the count the circuit is meant to deliver.
    std::uint64_t matches = 0;
    // matches mod t: what a single-slot EvalSum would leave. Equal to `matches`
    // only while matches < t - which is why the count is grouped.
    std::uint32_t count_mod_t = 0;

    // The grouped result: one partial sum per group, group(cell) = cell mod L,
    // each a residue mod t. Summing them recovers the count exactly.
    unsigned                   groups = 1;
    std::vector<std::uint32_t> group_sums;
    // True if some group's true total reached t, so its partial sum wrapped and
    // the count is not recoverable. The grouping is sized to prevent this.
    bool group_wrapped = false;
};

// Compare party A's table with party B's, all T_A * T_B level pairs at every cell, and
// return the count as `groups` partial sums (a power of two, at most the cell
// count; 1 is the single-slot form). Throws std::invalid_argument unless the two
// tables have identical (m, k) and different roles - T may differ (dynamic T) - two tables of the same
// role share a sentinel, so every aligned pair of empty cells would match - or
// if `groups` is not a valid grouping.
CountResult reference_count(const Table& a, const Table& b, unsigned groups = 1);

// What the client does with the grouped result: add the partial sums. Decoded
// slots must be put back in [0, t) with residue() first.
std::uint64_t count_from_groups(const std::vector<std::uint32_t>& group_sums);

struct ItemizedResult {
    // ind[level * cells + cell] = Σ_k eq(viewer level, other level k) at that cell,
    // mod t: one indicator per viewer (level, cell). 0/1 unless two of the other
    // party's records in that cell share a stored signature.
    std::vector<std::uint32_t> indicators;
    // masks[q][cell] = Σ_{j < 16} 2^j · ind[16q + j][cell] mod t, q = 0 .. ceil(T/16)-1:
    // the viewer's T levels bit-packed, 16 per slot (design §2.3).
    std::vector<std::vector<std::uint32_t>> masks;
};

// The itemized variant, in the viewer's layout: the other party's comparison axis
// is summed away, then the viewer's levels are bit-packed. Same validation as
// reference_count.
ItemizedResult reference_itemized(const Table& viewer, const Table& other);

// Decode masks back to the viewer's own records: bit j of masks[q][cell] set means
// the record at (level 16q + j, cell) matched. Returns them ascending. Throws
// std::invalid_argument on a wrongly shaped mask, and std::runtime_error if a mask
// marks an empty slot or a level beyond T - which only a broken circuit produces.
std::vector<Digest> resolve_matches(const Table& viewer,
                                    const std::vector<std::vector<std::uint32_t>>& masks);

}  // namespace fhe_toolkit::psi

#endif
