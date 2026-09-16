#ifndef FHE_TOOLKIT_PSI_SOLVER_H
#define FHE_TOOLKIT_PSI_SOLVER_H

// Picks (cells, levels, limbs, shards) for an exact-PSI encoding and predicts
// what it costs - from MEASURED numbers, not assumed ones. Every constant in
// ContextCost comes from scratch/psi-spike/A1-RESULTS.md, and the tests check
// the predictions against A1's own measurements rather than against this model.
//
// This is the function that will quote a price (design §3.8, Q6 "price at
// cost"), so it reports work and bytes, not just a time.
//
// The shape of the job (design §2.2, §2.5, §2.7), per shard:
//
//   chunks       = ceil(T^2 * m / N)              slot-aligned comparisons
//   mults        = chunks * (16k + k - 1)         ct x ct multiplications
//   ciphertexts  = ceil(T * m / N) * k            stored per party
//
// and the parameters it solves for:
//
//   T   smallest level count whose expected drop rate meets the target, under
//       the Poisson occupancy model of psi/table (the same model B2's tests
//       showed predicts what build_table actually does)
//   m   the power-of-two cell count minimising compute, T^2 * m
//   k   ceil((signature_bits - log2 m_total) / 16) - the address the cell
//       alignment already verified pays for part of the signature (design §2.1)
//   P   fewest shards whose per-shard upload fits max_shard_bytes, never
//       splitting so far that a shard holds fewer cells than one ciphertext

#include <cstdint>
#include <string>
#include <vector>

#include "psi/table.h"

namespace fhe_toolkit::psi {

// The measured cost of one crypto context. The defaults are A1's recommendation:
// BFV t = 65537, BV key switching, depth 19, N = 32768, logQ 840, 14 towers,
// HEStd_128_classic, NOISE_FLOODING_MULTIPARTY.
struct ContextCost {
    std::uint64_t slots            = 32768;  // N: BFV batches N slots
    unsigned      towers           = 14;     // ceil(logQ / 60) at depth 19
    double        seconds_per_mult = 0.364;  // one ct x ct EvalMult, single core (A1 §2)
    unsigned      max_limbs        = 8;      // depth 19 is the last depth at N = 32768 (A1 §6)

    // 2 * N * towers * 8 - the word-aligned model A1 calibrated against the
    // committed fixture, within 0.1 % on every measured row. (Design §2.5's
    // 2*N*logQ/8 is 6.3 % low on every row, by the 60/64 packing ratio.)
    std::uint64_t ciphertext_bytes() const;
};

struct Plan {
    std::uint64_t cells_total  = 0;  // m_total: cells across all shards, a power of two
    std::uint64_t shards       = 1;  // P, a power of two dividing cells_total
    unsigned      levels       = 0;  // T
    unsigned      limbs        = 0;  // k
    // L: partial sums the count is returned as, group(cell) = cell mod L
    // (psi/reference). 1 is the single-slot form; more only when a single sum
    // could pass t - 1 = 65536.
    std::uint64_t count_groups = 1;

    std::uint64_t cells_per_shard() const { return cells_total / shards; }
    TableParams   table_params() const;  // what build_table takes, for one shard
};

struct Request {
    std::uint64_t records      = 0;     // this party's distinct records
    std::uint64_t peer_records = 0;     // 0 = assume the same as `records`
    unsigned      signature_bits = 128; // the guarantee, not the storage (design Q2c)
    double        target_drop_rate = 1e-6;  // expected dropped records / records
    std::uint64_t max_shard_bytes = std::uint64_t{128} << 20;
    ContextCost   context;
};

enum class WarningCode {
    count_group_leak,         // the grouped count discloses more than the total
    count_not_representable,  // no grouping can carry a count this large
};

// A warning stated in numbers, as design §3.9 requires. D4 renders these and
// takes the acknowledgement.
struct Warning {
    WarningCode code;
    std::string message;
};

struct Estimate {
    Plan          plan;
    std::uint64_t records = 0;
    std::uint64_t peer_records = 0;

    // Work
    std::uint64_t chunks = 0;           // slot-aligned comparisons, all shards
    std::uint64_t multiplications = 0;  // ct x ct
    double        core_seconds = 0.0;   // multiplications x measured per-mult cost

    // Bytes
    std::uint64_t ciphertexts_self = 0;
    std::uint64_t input_bytes_self = 0;
    std::uint64_t input_bytes_peer = 0;   // equal to self under the associative layout
    std::uint64_t input_bytes_total = 0;
    std::uint64_t count_output_bytes = 0;     // one ciphertext, after homomorphic shard aggregation
    std::uint64_t itemized_output_bytes = 0;  // ceil(T/16) masks x m cells, per shard
    std::uint64_t peer_decrypt_bytes = 0;     // the counterparty's burden for an itemized run

    // Accuracy
    double   expected_drop_rate = 0.0;
    double   expected_overflowed_cells = 0.0;
    double   expected_false_matches = 0.0;
    unsigned signature_bits_delivered = 0;  // 16k + log2(cells_total)

    // How the count comes back (psi/reference): count_groups partial sums inside
    // one ciphertext, which the client adds in the clear. The result does not
    // grow; what it costs is disclosure, hence the warning.
    std::uint64_t count_groups = 1;
    double        count_records_per_group = 0.0;  // on the smaller side
    double        count_group_headroom = 0.0;     // (t - 1) / records per group
    // True when even the finest grouping this context allows could still let a
    // partial sum reach t.
    bool count_exceeds_modulus = false;

    // Client-facing warnings, in numbers rather than adjectives (design §3.9).
    std::vector<Warning> warnings;
};

// Limbs from the guarantee and the address entropy (design §2.1):
// ceil((signature_bits - log2 cells_total) / 16), at least 1. Throws
// std::invalid_argument if that needs more than max_limbs.
unsigned limbs_for(unsigned signature_bits, std::uint64_t cells_total, unsigned max_limbs);

// Cost of a given plan. Throws std::invalid_argument on a malformed plan.
Estimate estimate(const Request& r, const Plan& p);

// Solve for a plan and cost it. Throws std::invalid_argument if no cell count
// can meet the request (e.g. a signature wider than max_limbs can carry).
Estimate solve(const Request& r);

// The same job at other limb counts (design §3.8's limbSensitivity line).
std::vector<Estimate> limb_sensitivity(const Request& r, const Plan& p,
                                       const std::vector<unsigned>& limbs);

}  // namespace fhe_toolkit::psi

#endif
