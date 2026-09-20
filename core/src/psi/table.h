#ifndef FHE_TOOLKIT_PSI_TABLE_H
#define FHE_TOOLKIT_PSI_TABLE_H

// Associative placement of record digests into T slot-aligned tables
// (platform plans/exact-psi-signature-tables.md §2.1-2.2).
//
// ONE position hash, shared by every table: a record goes to cell position(d) of
// level 0; if that cell is taken, to the same cell of level 1; and so on up to
// level T-1. The T levels are a bucket of depth T laid out as T parallel arrays,
// so the circuit can compare every (A level j, B level k) pair slot-aligned, and
// a record both parties hold matches in exactly one of those T^2 pairs.
//
// build_table dedupes (full-digest key, psi/digest) and places records in
// ascending digest order, so a table is a function of the SET of records: any
// row order, with or without repeated rows, gives an identical table. That lets
// a party recompute its own placement later (resolve-indicator) rather than
// store it. Which level a record takes does not affect the count - all T^2 pairs
// are compared - so this is about reproducibility, not correctness.
//
// Empty cells hold a public sentinel that can never match: party A fills with
// signature 0 (every limb 0), party B with signature 1 (limb 0 = 1, the rest 0).
// A real signature that lands on either value is remapped by adding 2 to limb 0
// (0 -> 2, 1 -> 3). The rule depends only on the digest, so a shared record
// still stores the same value on both sides. Then sentinel-vs-sentinel differs
// in limb 0 and sentinel-vs-real always differs: no empty cell can ever match.
//
// Overflow - more than T records for one cell - is never silent. Under
// OverflowPolicy::fail any overflow throws TableOverflow. Under ::drop the
// surplus (the largest digests in the cell) is dropped and counted, but a drop
// rate above 1 % of the distinct records still throws: drop raises the ceiling
// from 0 to 1 %, not to infinity (design §2.2 point 3, Q1).

#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

#include "psi/digest.h"

namespace fhe_toolkit::psi {

enum class Role { A, B };                // which sentinel fills this party's empty cells
enum class OverflowPolicy { fail, drop };

// Hard ceiling under OverflowPolicy::drop: dropped * 100 <= records * max_drop_percent.
constexpr std::uint64_t max_drop_percent = 1;

// The ceiling, as a test and as its message. Exposed because a SHARDED encoding has to apply it to
// the dataset - the sum over shards - rather than to any one shard: a shard's drop rate has the
// same mean as the whole dataset's but far more variance, so one unlucky shard passing 1 % is not
// an encoding anyone should be asked to fix. build_table applies it itself only when shards == 1.
bool        drop_floor_exceeded(std::uint64_t records, std::uint64_t dropped) noexcept;
std::string drop_floor_message(std::uint64_t records, std::uint64_t dropped);

struct TableParams {
    std::uint64_t cells  = 0;  // m: cells in THIS shard, a power of two in [1, 2^32]
    unsigned      levels = 0;  // T >= 1   (number of tables - to deal with collision at the client)
    unsigned      limbs  = 0;  // k in [1, max_limbs]  (number of limbs to allow large id at each hash cell)
    // Sharding (design §2.7, step F1). `cells` is this shard's cell count, so the whole key space is
    // cells * shards cells and a record's place in it is split as psi/digest describes: the low
    // log2(shards) bits of its position pick the shard, the rest pick the cell. P = 1 is the
    // unsharded table, bit for bit.
    std::uint64_t shards = 1;  // P: a power of two
    std::uint64_t shard  = 0;  // p in [0, P): which shard this table is
};

struct PlacementReport {
    std::uint64_t rows             = 0;  // digests handed to build_table
    std::uint64_t duplicates       = 0;  // rows that repeated an earlier record
    std::uint64_t records          = 0;  // distinct records: rows - duplicates
    std::uint64_t placed           = 0;
    std::uint64_t dropped          = 0;  // records with no free level left in their cell
    std::uint64_t overflowed_cells = 0;  // cells that more than T records contended for
    std::uint64_t cell_max_load    = 0;  // most records contending for any one cell
    std::uint64_t remapped         = 0;  // placed records whose signature hit a sentinel

    double drop_rate() const noexcept;   // dropped / records; 0 for an empty set
};

// Thrown when a table is refused. Carries the full report, so the caller can
// say how far off the configuration is rather than just that it failed.
class TableOverflow : public std::runtime_error {
  public:
    TableOverflow(const std::string& what, PlacementReport report);
    const PlacementReport& report() const noexcept { return report_; }

  private:
    PlacementReport report_;
};

// The value a real record stores: signature(d, limbs), moved off the sentinels.
std::vector<std::uint16_t> stored_signature(const Digest& d, unsigned limbs);

// The value an empty cell of `role`'s table holds.
std::vector<std::uint16_t> sentinel(Role role, unsigned limbs);

// The most distinct records any one of `cells` cells receives: the smallest T
// that places every record. Dynamic T (--dynamic-tables) builds with exactly
// this many levels - more when the data collides more than expected, fewer
// when the levels above it would be empty. 0 for an empty set.
//
// `cells` is the WHOLE key space, not one shard's: sharding splits the same
// positions, so the fullest cell of the union is the fullest cell of any shard,
// and one pass over every record answers it for every shard at once.
std::uint64_t fullest_cell(std::vector<Digest> digests, std::uint64_t cells);

class Table;
// Builds ONE shard's table. `digests` may be the whole dataset or just this
// shard's bucket (psi::partition_by_shard); records belonging to another shard
// are ignored either way, and the report counts only this shard's. Passing the
// whole set to each of P shards is correct but O(P*n); partition once instead.
Table build_table(std::vector<Digest> digests, const TableParams& params, Role role,
                  OverflowPolicy policy);

class Table {
  public:
    static constexpr std::uint32_t empty = std::numeric_limits<std::uint32_t>::max();

    const TableParams&     params() const noexcept { return params_; }
    Role                   role()   const noexcept { return role_; }
    const PlacementReport& report() const noexcept { return report_; }

    // The distinct records, ascending; occupant() indexes into this.
    const std::vector<Digest>& records() const noexcept { return records_; }
    // Records that did not fit (OverflowPolicy::drop only), ascending.
    const std::vector<Digest>& dropped() const noexcept { return dropped_; }

    // Index into records() of the record at (level, cell), or `empty`.
    std::uint32_t occupant(unsigned level, std::uint64_t cell) const;

    // Limb j of the value at (level, cell): the occupant's stored signature, or
    // this role's sentinel.
    std::uint16_t              limb_at(unsigned level, unsigned j, std::uint64_t cell) const;
    std::vector<std::uint16_t> signature_at(unsigned level, std::uint64_t cell) const;

    // Limb j of every cell of one level, in cell order: the slot vector a single
    // (level, limb) ciphertext is encoded from. out.size() must equal cells.
    void fill_limb_row(unsigned level, unsigned j, std::span<std::uint16_t> out) const;

  private:
    friend Table build_table(std::vector<Digest>, const TableParams&, Role, OverflowPolicy);
    Table() = default;

    std::uint16_t value_limb(std::uint32_t occupant, unsigned j) const;

    TableParams                params_;
    Role                       role_ = Role::A;
    PlacementReport            report_;
    std::vector<Digest>        records_;
    std::vector<Digest>        dropped_;
    std::vector<std::uint32_t> occupant_;  // [level * cells + cell]
};

// ---------------------------------------------------------------------------
// Occupancy model: each cell's load is Poisson(λ = records / cells). This is
// what the solver sizes (m, T) against; the tests check it predicts what
// build_table actually does.
// ---------------------------------------------------------------------------

// m · P(X > T): expected number of cells that overflow.
double expected_overflowed_cells(std::uint64_t records, std::uint64_t cells, unsigned levels);

// m · E[(X - T)+]: expected number of records dropped.
double expected_dropped_records(std::uint64_t records, std::uint64_t cells, unsigned levels);

}  // namespace fhe_toolkit::psi

#endif
