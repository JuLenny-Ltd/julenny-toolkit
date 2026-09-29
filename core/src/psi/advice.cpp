#include "psi/advice.h"

#include "psi/reference.h"  // plaintext_modulus: what one partial sum can carry

#include <algorithm>
#include <bit>
#include <cmath>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <tuple>

namespace fhe_toolkit::psi {

namespace {

constexpr double        drop_floor = static_cast<double>(max_drop_percent) / 100.0;
constexpr std::uint64_t group_ceiling = plaintext_modulus - 1;  // a partial sum of 65536 still fits
constexpr unsigned      max_levels = 4096;                      // the bundle header's TABLES ceiling
constexpr int           max_fix_steps = 6;                      // drops, then groups, then limbs, with room

std::string num(double v) {
    std::ostringstream out;
    out.precision(3);
    out << v;
    return out.str();
}

std::string percent(double rate) { return num(rate * 100.0) + " %"; }

std::string bytes(std::uint64_t b) {
    const char* units[] = { "B", "KB", "MB", "GB", "TB" };
    double v = static_cast<double>(b);
    int u = 0;
    while (v >= 1000.0 && u < 4) { v /= 1000.0; ++u; }
    std::ostringstream out;
    out.setf(std::ios::fixed);
    out.precision(u == 0 ? 0 : 1);
    out << v << " " << units[u];
    return out.str();
}

unsigned floor_log2(std::uint64_t v) { return static_cast<unsigned>(std::bit_width(v) - 1); }

std::uint64_t peer_of(const Request& r) { return r.peer_records != 0 ? r.peer_records : r.records; }
std::uint64_t smaller_of(const Request& r) { return std::min(r.records, peer_of(r)); }

// Expected false matches above this are material: the same per-record budget drops are held to.
double false_match_budget(const Request& r) {
    return r.target_drop_rate * static_cast<double>(std::max<std::uint64_t>(1, smaller_of(r)));
}

enum class Family { drops, false_matches, count_wrap, disclosure, approximate };

Family family_of(Issue issue) {
    switch (issue) {
        case Issue::drop_rate_over_floor:
        case Issue::records_do_not_fit:
        case Issue::drop_rate_above_target:
        case Issue::records_dropped:        return Family::drops;
        case Issue::false_matches_material: return Family::false_matches;
        case Issue::count_may_wrap:         return Family::count_wrap;
        case Issue::count_group_disclosure: return Family::disclosure;
        case Issue::approximate_collisions: return Family::approximate;
    }
    return Family::disclosure;
}

// A plan in the state it is judged in: what was measured for it, if anything.
struct Subject {
    Plan     plan;
    bool     dynamic = false;
    Estimate estimate;
    std::uint64_t dropped = 0;  // measured drops at this plan (encoder only)
};

std::string table_words(const Plan& p) {
    return std::to_string(p.cells_total) + " cells x " + std::to_string(p.levels) + " tables";
}

std::vector<Finding> assess(const Request& r, const Subject& s, const AdviceOptions& o) {
    const Estimate& e = s.estimate;
    const Observed* seen = o.observed;
    std::vector<Finding> out;
    const auto add = [&](Issue issue, Severity severity, std::string message) {
        out.push_back({ issue, severity, std::move(message), {} });
    };

    // Drops. Dynamic tables size T to this data's fullest cell, so nothing can drop.
    if (!s.dynamic) {
        const double expected = e.expected_drop_rate;
        const double expected_records = expected * static_cast<double>(r.records);
        if (expected > drop_floor) {
            add(Issue::drop_rate_over_floor, Severity::refuse,
                "at " + std::to_string(r.records) + " records, " + table_words(s.plan) + " is expected to drop ~"
                + num(expected_records) + " records (" + percent(expected)
                + "), above the 1 % floor: the encoder will not emit it, and an acknowledgement does not change that.");
        } else if (seen != nullptr) {
            const double measured = seen->records == 0
                ? 0.0 : static_cast<double>(s.dropped) / static_cast<double>(seen->records);
            const std::uint64_t fullest = seen->fullest_cell_at(s.plan.cells_total);
            const std::string what = std::to_string(s.dropped) + " of " + std::to_string(seen->records)
                + " distinct records (" + percent(measured) + ") did not fit in " + table_words(s.plan)
                + "; the fullest cell holds " + std::to_string(fullest) + " records";
            if (measured > drop_floor) {
                add(Issue::drop_rate_over_floor, Severity::refuse,
                    what + ". That is above the 1 % floor: the bundle will not be emitted.");
            } else if (s.dropped > 0 && o.policy == OverflowPolicy::fail) {
                add(Issue::records_do_not_fit, Severity::refuse,
                    what + ". --on-overflow fail refuses any drop.");
            } else if (s.dropped > 0) {
                add(Issue::records_dropped, Severity::acknowledge,
                    what + ". They are left out of the bundle: every one the other party also holds is missing "
                    "from the count, which can be up to " + std::to_string(s.dropped)
                    + " low, and an itemized result cannot mark them.");
            }
        } else if (expected > r.target_drop_rate) {
            const double any_overflow = -std::expm1(-e.expected_overflowed_cells);
            const bool drop = o.policy == OverflowPolicy::drop;
            add(Issue::drop_rate_above_target, drop ? Severity::acknowledge : Severity::notice,
                "at " + std::to_string(r.records) + " records, " + table_words(s.plan) + " is expected to drop ~"
                + num(expected_records) + " records (rate " + num(expected) + ", above the target "
                + num(r.target_drop_rate) + "); some cell overflows with probability " + num(any_overflow) + ". "
                + (drop ? "Under --on-overflow drop those records are left out, and the count can be that many low."
                        : "Under --on-overflow fail the encoder then refuses, after reading the input and before "
                          "encrypting."));
        }
    }

    // False matches: same-cell cross pairs that agree on every stored limb.
    const double budget = false_match_budget(r);
    if (e.expected_false_matches > budget) {
        add(Issue::false_matches_material, Severity::acknowledge,
            "a " + std::to_string(s.plan.limbs) + "-limb signature over " + std::to_string(s.plan.cells_total)
            + " cells delivers " + std::to_string(e.signature_bits_delivered) + " bits: between "
            + std::to_string(e.records) + " and " + std::to_string(e.peer_records) + " records that is ~"
            + num(e.expected_false_matches) + " expected false matches, above the budget of " + num(budget)
            + " (target " + num(r.target_drop_rate) + " x the smaller side). Each false match adds one to the "
            "count and marks a record the other party does not hold.");
    }

    // Count groups: a partial sum wraps at t = 65537.
    const std::uint64_t groups = s.plan.count_groups;
    if (seen != nullptr) {
        const std::uint64_t fullest_group = seen->fullest_cell_at(groups);
        if (fullest_group > group_ceiling) {
            add(Issue::count_may_wrap, Severity::acknowledge,
                "the fullest of your " + std::to_string(groups) + " count groups holds "
                + std::to_string(fullest_group) + " records, over the 65536 one partial sum can carry: if more "
                "than 65536 of them are also the other party's, that sum wraps and the count comes back short by a "
                "multiple of 65537, with nothing to show it.");
        }
    } else if (e.count_exceeds_modulus) {
        add(Issue::count_may_wrap, Severity::acknowledge,
            "at " + std::to_string(groups) + " count groups a group holds ~"
            + num(e.count_records_per_group) + " of the smaller side's " + std::to_string(smaller_of(r))
            + " records, over the 65536 one partial sum can carry: if more than 65536 in a group match, that "
            "sum wraps and the count comes back short by a multiple of 65537, with nothing to show it.");
    }

    // Disclosure, not accuracy: reported, never blocking.
    for (const auto& w : e.warnings) {
        if (w.code == WarningCode::count_group_leak) add(Issue::count_group_disclosure, Severity::notice, w.message);
    }
    return out;
}

bool clears(const Request& r, const Subject& candidate, const AdviceOptions& o, Family family) {
    for (const auto& f : assess(r, candidate, o)) {
        if (family_of(f.issue) == family) return false;
    }
    return true;
}

std::optional<Subject> costed(const Request& r, Plan plan, bool dynamic, std::uint64_t dropped) {
    try {
        Subject s;
        s.plan = plan;
        s.dynamic = dynamic;
        s.dropped = dropped;
        s.estimate = estimate(r, plan);
        return s;
    } catch (const std::invalid_argument&) {
        return std::nullopt;  // not a plan the encoder could write
    }
}

Recommendation to_recommendation(const Subject& s) {
    Recommendation rec;
    rec.plan = s.plan;
    // The bits these limbs deliver, so --signature-bits derives exactly --limbs: the line
    // stays right if either flag is dropped from it.
    rec.signature_bits = limb_bits * s.plan.limbs + floor_log2(s.plan.cells_total);
    rec.dynamic_tables = s.dynamic;
    rec.estimate = s.estimate;
    return rec;
}

// Candidate fixes for one family, each verified to clear it; cheapest upload first.
std::vector<Subject> fixes(const Request& r, const Subject& s, const AdviceOptions& o, Family family) {
    const Observed* seen = o.observed;
    std::vector<Subject> out;
    const auto consider = [&](std::optional<Subject> c) {
        if (!c || !clears(r, *c, o, family)) return;
        for (const auto& have : out) {
            // The same table at another grouping is not a different fix; the first (the user's) grouping stays.
            if (have.plan.cells_total == c->plan.cells_total && have.plan.levels == c->plan.levels
                && have.plan.limbs == c->plan.limbs) return;
        }
        out.push_back(*c);
    };

    switch (family) {
        case Family::drops: {
            // T no lower than this data's fullest cell places every record: measured, not expected.
            const auto levels_for = [&](std::uint64_t cells, unsigned model) -> unsigned {
                std::uint64_t t = model;
                if (seen != nullptr) t = std::max<std::uint64_t>(t, seen->fullest_cell_at(cells));
                return t == 0 || t > max_levels ? 0u : static_cast<unsigned>(t);
            };
            // (a) keep the cells, add tables.
            {
                Plan p = s.plan;
                p.levels = levels_for(p.cells_total, smallest_levels(r.records, p.cells_total, r.target_drop_rate));
                if (p.levels != 0) consider(costed(r, p, false, 0));
            }
            // (b) the solver's plan for this count, sized as the encoder sizes it (one shard, no peer).
            try {
                Request solo = r;
                solo.peer_records = 0;
                solo.per_level_only = false;
                Plan p = solve(solo).plan;
                p.shards = 1;
                p.peer_levels = s.plan.peer_levels;
                p.limbs = limbs_for(r.signature_bits, p.cells_total, r.context.max_limbs);
                p.levels = levels_for(p.cells_total, p.levels);
                if (p.levels != 0) consider(costed(r, p, false, 0));
            } catch (const std::invalid_argument&) {
            }
            break;
        }
        case Family::false_matches: {
            // More limbs at the same cells, tables and groups: the smallest count inside the budget.
            for (unsigned k = s.plan.limbs + 1; k <= r.context.max_limbs; ++k) {
                Plan p = s.plan;
                p.limbs = k;
                auto c = costed(r, p, s.dynamic, s.dropped);
                if (c && clears(r, *c, o, family)) { consider(c); break; }
            }
            break;
        }
        case Family::count_wrap: {
            // Finer groups at the same table. Measured: the smallest L whose fullest group fits.
            // Modelled: the solver's grouping, with its 4x headroom.
            const std::uint64_t cap = std::min(s.plan.cells_per_shard(), r.context.slots);
            if (seen != nullptr) {
                for (std::uint64_t groups = s.plan.count_groups * 2; groups <= cap; groups *= 2) {
                    Plan p = s.plan;
                    p.count_groups = groups;
                    auto c = costed(r, p, s.dynamic, s.dropped);
                    if (c && clears(r, *c, o, family)) { consider(c); break; }
                }
            } else {
                Plan p = s.plan;
                p.count_groups = count_groups_for(smaller_of(r), p.cells_per_shard(), r.context.slots);
                if (p.count_groups > s.plan.count_groups) consider(costed(r, p, s.dynamic, s.dropped));
            }
            break;
        }
        case Family::disclosure:
        case Family::approximate:
            break;
    }
    std::sort(out.begin(), out.end(), [](const Subject& a, const Subject& b) {
        return std::make_tuple(a.estimate.ciphertexts_self, a.estimate.chunks, a.plan.levels)
             < std::make_tuple(b.estimate.ciphertexts_self, b.estimate.chunks, b.plan.levels);
    });
    return out;
}

}  // namespace

const char* issue_code(Issue issue) noexcept {
    switch (issue) {
        case Issue::drop_rate_over_floor:   return "drop-rate-over-floor";
        case Issue::records_do_not_fit:     return "records-do-not-fit";
        case Issue::drop_rate_above_target: return "drop-rate-above-target";
        case Issue::records_dropped:        return "records-dropped";
        case Issue::false_matches_material: return "false-matches-material";
        case Issue::count_may_wrap:         return "count-may-wrap";
        case Issue::count_group_disclosure: return "count-group-disclosure";
        case Issue::approximate_collisions: return "approximate-collisions";
    }
    return "unknown";
}

const char* severity_name(Severity severity) noexcept {
    switch (severity) {
        case Severity::notice:      return "notice";
        case Severity::acknowledge: return "acknowledge";
        case Severity::refuse:      return "refuse";
    }
    return "unknown";
}

const char* verdict_name(Verdict verdict) noexcept {
    switch (verdict) {
        case Verdict::ok:                    return "ok";
        case Verdict::accepted:              return "accepted";
        case Verdict::needs_acknowledgement: return "needs-acknowledgement";
        case Verdict::refused:               return "refused";
    }
    return "unknown";
}

std::string Recommendation::flags() const {
    std::ostringstream out;
    out << "--cells " << plan.cells_total;
    if (dynamic_tables) out << " --dynamic-tables";
    else out << " --tables " << plan.levels;
    out << " --limbs " << plan.limbs << " --count-groups " << plan.count_groups
        << " --signature-bits " << signature_bits;
    return out.str();
}

std::string Recommendation::cost() const {
    const Estimate& e = estimate;
    return std::to_string(e.ciphertexts_self) + " ciphertexts (" + bytes(e.input_bytes_self) + ") per party, "
         + std::to_string(e.chunks) + (e.chunks == 1 ? " chunk" : " chunks") + " (~" + num(e.core_seconds / 3600.0)
         + " core-hours), expected drop rate " + (dynamic_tables ? std::string("0 (tables set by the data)")
                                                                 : num(e.expected_drop_rate))
         + ", expected false matches " + num(e.expected_false_matches);
}

bool Advice::refused() const noexcept {
    return std::any_of(findings.begin(), findings.end(),
                       [](const Finding& f) { return f.severity == Severity::refuse; });
}

bool Advice::needs_acknowledgement() const noexcept {
    return std::any_of(findings.begin(), findings.end(),
                       [](const Finding& f) { return f.severity == Severity::acknowledge; });
}

Verdict Advice::verdict(bool acknowledged) const noexcept {
    if (refused()) return Verdict::refused;
    if (!needs_acknowledgement()) return Verdict::ok;
    return acknowledged ? Verdict::accepted : Verdict::needs_acknowledgement;
}

Advice advise(const Request& r, const Estimate& e, const AdviceOptions& o) {
    Subject start;
    start.plan = e.plan;
    start.dynamic = o.dynamic_tables;
    start.estimate = e;
    start.dropped = o.observed != nullptr ? o.observed->dropped : 0;

    Advice advice;
    advice.findings = assess(r, start, o);
    for (auto& f : advice.findings) {
        if (f.severity == Severity::notice && f.issue != Issue::drop_rate_above_target) continue;
        for (const auto& c : fixes(r, start, o, family_of(f.issue))) f.recommendations.push_back(to_recommendation(c));
    }

    // One command that clears everything: apply the cheapest verified fix for the
    // first blocking finding, re-assess, repeat.
    Subject current = start;
    for (int step = 0; step < max_fix_steps; ++step) {
        const auto found = assess(r, current, o);
        const auto blocking = std::find_if(found.begin(), found.end(),
                                           [](const Finding& f) { return f.severity != Severity::notice; });
        if (blocking == found.end()) {
            if (step > 0) advice.fix.push_back(to_recommendation(current));
            break;
        }
        const auto options = fixes(r, current, o, family_of(blocking->issue));
        if (options.empty()) break;
        current = options.front();
    }
    return advice;
}

Finding advise_approximate(const Request& r, const Estimate& exact) {
    const double expected = static_cast<double>(r.records) * static_cast<double>(peer_of(r)) / 16384.0;
    const double budget = false_match_budget(r);
    Finding f;
    f.issue = Issue::approximate_collisions;
    const std::string numbers = "the approximate variant (bfv-default-v1) hashes each record to one of 16384 slots: "
        "between " + std::to_string(r.records) + " and " + std::to_string(peer_of(r)) + " records it expects ~"
        + num(expected) + " false matches";
    if (expected <= budget) {
        f.severity = Severity::notice;
        f.message = numbers + ", within the budget of " + num(budget) + ".";
        return f;
    }
    f.severity = Severity::acknowledge;
    f.message = numbers + ", above the budget of " + num(budget) + " (target " + num(r.target_drop_rate)
              + " x the smaller side), and records of one party that share a slot can hide real matches. "
                "The exact variant (signature-table) expects " + num(exact.expected_false_matches) + ".";
    Recommendation rec;
    rec.plan = exact.plan;
    rec.signature_bits = limb_bits * exact.plan.limbs + floor_log2(exact.plan.cells_total);
    rec.estimate = exact;
    f.recommendations.push_back(rec);
    return f;
}

}  // namespace fhe_toolkit::psi
