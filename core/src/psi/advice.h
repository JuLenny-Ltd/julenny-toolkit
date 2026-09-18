#ifndef FHE_TOOLKIT_PSI_ADVICE_H
#define FHE_TOOLKIT_PSI_ADVICE_H

// Unsafe parameters: warn, recommend, acknowledge (platform design §3.9, step D4).
//
// Two mechanisms, deliberately kept apart:
//
//   refuse       a drop rate above 1 % - the toolkit will not emit the bundle,
//                whatever the user acknowledges (§2.2 point 3, Q1)
//   acknowledge  every accuracy problem short of that floor - stated in numbers,
//                with a concrete fix, and the encoder will not proceed without
//                --accept-degraded-accuracy
//
// plus `notice`, for what is disclosed rather than degraded (the count groups),
// which is reported and never blocks.
//
// Every recommendation here has been checked by the same rules before it is
// returned: its plan is re-advised, and a recommendation that still raises the
// problem it claims to fix is discarded rather than shown (the D4 convince-me:
// "a recommendation nobody verified is worse than none").
//
// What counts as material. One per-record error budget is used for both kinds
// of error: `Request::target_drop_rate` (--target-overflow, default 1e-6), the
// knob the solver already sizes drops against. Drops are material above it;
// expected false matches are material above target x min(records, peer records).
//
// Two sources of truth, by stage:
//
//   dry run      the occupancy model (expected drop rate, Poisson), because no
//                record has been read
//   encoder      what build_table measured (Observed), because the model's
//                expectation is beside the point once the table exists - a
//                bundle that dropped nothing is exact, whatever was expected.
//                The expected-rate refusal still applies before the table is
//                built, as the design requires.

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "psi/solver.h"
#include "psi/table.h"

namespace fhe_toolkit::psi {

enum class Severity { notice, acknowledge, refuse };

enum class Issue {
    drop_rate_over_floor,    // expected or measured drop rate above 1 %: refused
    records_do_not_fit,      // records did not fit under --on-overflow fail: refused
    drop_rate_above_target,  // dry run: expected drop rate above the target
    records_dropped,         // encoder: records dropped under --on-overflow drop, at most 1 %
    false_matches_material,  // expected false matches above the error budget
    count_may_wrap,          // a count group can hold more than t - 1 = 65536 matches
    count_group_disclosure,  // the count comes back as L > 1 partial sums
    approximate_collisions,  // the approximate variant's expected false matches
};

// Stable, kebab-case names for JSON.
const char* issue_code(Issue issue) noexcept;
const char* severity_name(Severity severity) noexcept;

// What the encoder measured when it built (or failed to build) its table.
struct Observed {
    std::uint64_t records = 0;  // distinct records
    std::uint64_t dropped = 0;  // at the plan being advised
    // This data's fullest cell at any power-of-two cell count (psi::fullest_cell).
    // Because position() is the address's low bits, it is also the fullest count
    // group at L = cells, whatever the table's own cell count: group(cell) =
    // cell mod L = position(d, L). An upper bound on placed records when some
    // were dropped, exact otherwise.
    std::function<std::uint64_t(std::uint64_t cells)> fullest_cell_at;
};

struct AdviceOptions {
    OverflowPolicy  policy = OverflowPolicy::fail;
    bool            dynamic_tables = false;  // T is the data's fullest cell: nothing drops
    const Observed* observed = nullptr;      // null: the dry run, or the encoder before its table exists
};

// A concrete, costed parameter set, as flags the user can copy.
struct Recommendation {
    Plan     plan;
    unsigned signature_bits = 0;  // the bits plan.limbs deliver at plan.cells_total, so it derives exactly those limbs
    bool     dynamic_tables = false;
    Estimate estimate;            // what it costs, under the same context

    // "--cells 256 --tables 11 --limbs 8 --count-groups 1 --signature-bits 128"
    // (--dynamic-tables in place of --tables when it applies). Complete: every
    // sizing flag is pinned, so the other party can pass the same line.
    std::string flags() const;
    // "8 ciphertexts (58.7 MB) per party, 1 chunk, expected drop rate ..., ..."
    std::string cost() const;
};

struct Finding {
    Issue       issue = Issue::count_group_disclosure;
    Severity    severity = Severity::notice;
    std::string message;                          // numbers, not adjectives
    std::vector<Recommendation> recommendations;  // each verified to clear `issue`
};

enum class Verdict {
    ok,                     // nothing to acknowledge
    accepted,               // acknowledgements were needed and given
    needs_acknowledgement,  // --accept-degraded-accuracy required
    refused,                // cannot be acknowledged away
};
const char* verdict_name(Verdict verdict) noexcept;

struct Advice {
    std::vector<Finding> findings;
    // One parameter set that clears every refusal and acknowledgement, verified
    // the same way; empty when none was found (or none is needed).
    std::vector<Recommendation> fix;

    bool refused() const noexcept;
    bool needs_acknowledgement() const noexcept;
    Verdict verdict(bool acknowledged) const noexcept;
};

// Assess the plan `e` was costed for. `r` is the request the plan was sized with
// (the encoder's own: records as read, peer_records only for accuracy).
Advice advise(const Request& r, const Estimate& e, const AdviceOptions& options);

// The approximate variant (bfv-default-v1, FNV-1a mod 16384; design §3.7) at the
// same record counts: n_A * n_B / 16384 expected false matches, against the same
// budget. Its recommendation is `exact`, the exact variant's plan.
Finding advise_approximate(const Request& r, const Estimate& exact);

}  // namespace fhe_toolkit::psi

#endif
