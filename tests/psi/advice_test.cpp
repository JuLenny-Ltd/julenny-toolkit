#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "psi/advice.h"
#include "psi/digest.h"
#include "psi/solver.h"
#include "psi/table.h"

// Step D4 (design §3.9): warn in numbers, recommend a fix, require an acknowledgement - and refuse
// outright above the 1 % drop floor. The tests that matter here take each recommendation and check
// it WITHOUT psi::advise: rebuilt with build_table over the same records when the advice was measured,
// re-costed with psi::estimate when it was modelled. A recommendation checked only by the code that
// made it would prove nothing.

using namespace fhe_toolkit::psi;

namespace {

constexpr std::string_view kDomain = "julenny/joint-record-overlap/exact/v1";

std::vector<Digest> records(std::uint64_t count, const std::string& prefix = "acct-") {
    std::vector<Digest> out;
    out.reserve(count);
    for (std::uint64_t i = 0; i < count; ++i) out.push_back(record_digest(kDomain, prefix + std::to_string(i)));
    return out;
}

Request request_for(std::uint64_t n, double target = 1e-6, unsigned bits = 128) {
    Request r;
    r.records = n;
    r.target_drop_rate = target;
    r.signature_bits = bits;
    return r;
}

Plan plan_of(std::uint64_t cells, unsigned tables, unsigned limbs, std::uint64_t groups = 1) {
    Plan p;
    p.cells_total = cells;
    p.levels = tables;
    p.limbs = limbs;
    p.count_groups = groups;
    return p;
}

Observed observe(const std::vector<Digest>& digests, std::uint64_t dropped) {
    Observed o;
    std::vector<Digest> distinct = digests;
    std::sort(distinct.begin(), distinct.end());
    distinct.erase(std::unique(distinct.begin(), distinct.end()), distinct.end());
    o.records = distinct.size();
    o.dropped = dropped;
    o.fullest_cell_at = [digests](std::uint64_t cells) { return fullest_cell(digests, cells); };
    return o;
}

bool has(const Advice& a, Issue issue) {
    return std::any_of(a.findings.begin(), a.findings.end(), [&](const Finding& f) { return f.issue == issue; });
}

const Finding& finding(const Advice& a, Issue issue) {
    const auto it = std::find_if(a.findings.begin(), a.findings.end(), [&](const Finding& f) { return f.issue == issue; });
    REQUIRE(it != a.findings.end());
    return *it;
}

// The most records this table placed in any one count group, counted from the table itself.
std::uint64_t fullest_group_placed(const Table& t, std::uint64_t groups) {
    std::vector<std::uint64_t> load(groups, 0);
    for (unsigned level = 0; level < t.params().levels; ++level) {
        for (std::uint64_t cell = 0; cell < t.params().cells; ++cell) {
            if (t.occupant(level, cell) != Table::empty) ++load[cell % groups];
        }
    }
    return *std::max_element(load.begin(), load.end());
}

// A recommendation is honest for measured data if the encoder, given exactly its flags, would build a
// table that drops nothing and whose count groups cannot wrap - checked by building it.
void require_clean_on_data(const Request& r, const Recommendation& rec, const std::vector<Digest>& digests) {
    CAPTURE(rec.flags());
    const Table t = build_table(digests, rec.plan.table_params(), Role::A, OverflowPolicy::fail);  // throws on any drop
    REQUIRE(t.report().dropped == 0);
    REQUIRE(fullest_group_placed(t, rec.plan.count_groups) <= 65536);
    const Estimate again = estimate(r, rec.plan);
    REQUIRE(again.ciphertexts_self == rec.estimate.ciphertexts_self);
    REQUIRE(again.expected_false_matches <= r.target_drop_rate * static_cast<double>(r.records));
}

// ... and honest for a dry run if the model, re-costed from scratch, meets the budgets it was meant to.
// `drop_limit` is the target where drops degrade the answer (--on-overflow drop), and the 1 % floor
// where they only make the encoder refuse (fail), which is a notice rather than a block.
struct Checks {
    double drop_limit = -1.0;  // < 0: not checked
    bool   false_matches = true;
    bool   count = true;
};

void require_clean_in_model(const Request& r, const Recommendation& rec, const Checks& checks) {
    CAPTURE(rec.flags());
    const Estimate again = estimate(r, rec.plan);
    const std::uint64_t peer = r.peer_records != 0 ? r.peer_records : r.records;
    REQUIRE(again.ciphertexts_self == rec.estimate.ciphertexts_self);
    if (checks.drop_limit >= 0.0 && !rec.dynamic_tables) REQUIRE(again.expected_drop_rate <= checks.drop_limit);
    if (checks.false_matches) {
        REQUIRE(again.expected_false_matches
                <= r.target_drop_rate * static_cast<double>(std::min(r.records, peer)));
    }
    if (checks.count) REQUIRE_FALSE(again.count_exceeds_modulus);
}

Checks everything(const Request& r) { return Checks{ r.target_drop_rate, true, true }; }

void require_flags_name_the_plan(const Recommendation& rec) {
    const std::string flags = rec.flags();
    CAPTURE(flags);
    REQUIRE(flags.find("--cells " + std::to_string(rec.plan.cells_total)) != std::string::npos);
    REQUIRE(flags.find("--limbs " + std::to_string(rec.plan.limbs)) != std::string::npos);
    REQUIRE(flags.find("--count-groups " + std::to_string(rec.plan.count_groups)) != std::string::npos);
    REQUIRE(flags.find(rec.dynamic_tables ? std::string("--dynamic-tables")
                                          : "--tables " + std::to_string(rec.plan.levels)) != std::string::npos);
    // --signature-bits must derive the same limbs, or a user who drops --limbs gets a different bundle.
    REQUIRE(limbs_for(rec.signature_bits, rec.plan.cells_total, 8) == rec.plan.limbs);
}

}  // namespace

TEST_CASE("solved plans need no acknowledgement", "[psi][advice]") {
    for (const std::uint64_t n : { 1ull, 120ull, 1000ull, 3000ull, 20000ull, 1000000ull }) {
        const Request r = request_for(n);
        Plan p = solve(r).plan;
        p.shards = 1;  // as the CLI plans it (plan_signature_table)
        const Estimate e = estimate(r, p);
        for (const auto policy : { OverflowPolicy::fail, OverflowPolicy::drop }) {
            AdviceOptions o;
            o.policy = policy;
            const Advice a = advise(r, e, o);
            CAPTURE(n, a.findings.size());
            REQUIRE(a.verdict(false) == Verdict::ok);
            REQUIRE(a.fix.empty());
        }
    }
}

TEST_CASE("an expected drop rate above 1 % is refused, acknowledged or not", "[psi][advice]") {
    const Request r = request_for(1000);
    const Estimate e = estimate(r, plan_of(256, 2, 8));  // ~3.9 records per cell, 2 levels
    REQUIRE(e.expected_drop_rate > 0.01);
    for (const auto policy : { OverflowPolicy::fail, OverflowPolicy::drop }) {
        AdviceOptions o;
        o.policy = policy;
        const Advice a = advise(r, e, o);
        REQUIRE(a.verdict(false) == Verdict::refused);
        REQUIRE(a.verdict(true) == Verdict::refused);
        const auto& f = finding(a, Issue::drop_rate_over_floor);
        REQUIRE(f.severity == Severity::refuse);
        // Numbers, not adjectives: the records, the table, the floor.
        REQUIRE(f.message.find("1000 records") != std::string::npos);
        REQUIRE(f.message.find("256 cells x 2 tables") != std::string::npos);
        REQUIRE(f.message.find("1 %") != std::string::npos);
        REQUIRE_FALSE(f.recommendations.empty());
        for (const auto& rec : f.recommendations) require_clean_in_model(r, rec, everything(r));
        REQUIRE(a.fix.size() == 1);
        require_clean_in_model(r, a.fix.front(), everything(r));
    }
}

TEST_CASE("an expected drop rate above the target needs acknowledging only where records can drop",
          "[psi][advice]") {
    const Request r = request_for(1000);
    const Estimate e = estimate(r, plan_of(32768, 2, 8, 32768));
    REQUIRE(e.expected_drop_rate > r.target_drop_rate);
    REQUIRE(e.expected_drop_rate <= 0.01);

    SECTION("--on-overflow drop: acknowledge") {
        AdviceOptions o;
        o.policy = OverflowPolicy::drop;
        const Advice a = advise(r, e, o);
        REQUIRE(a.verdict(false) == Verdict::needs_acknowledgement);
        REQUIRE(a.verdict(true) == Verdict::accepted);
        const auto& f = finding(a, Issue::drop_rate_above_target);
        REQUIRE(f.severity == Severity::acknowledge);
        REQUIRE_FALSE(f.recommendations.empty());
        for (const auto& rec : f.recommendations) {
            require_clean_in_model(r, rec, everything(r));
            require_flags_name_the_plan(rec);
            // Re-advised, the problem is gone.
            AdviceOptions again = o;
            REQUIRE(advise(r, rec.estimate, again).verdict(false) == Verdict::ok);
        }
    }
    SECTION("--on-overflow fail: a notice, because the encoder refuses rather than degrades") {
        const Advice a = advise(r, e, AdviceOptions{});
        REQUIRE(a.verdict(false) == Verdict::ok);
        REQUIRE(finding(a, Issue::drop_rate_above_target).severity == Severity::notice);
        REQUIRE(finding(a, Issue::drop_rate_above_target).message.find("probability") != std::string::npos);
    }
    SECTION("dynamic tables drop nothing, so there is nothing to say") {
        AdviceOptions o;
        o.policy = OverflowPolicy::drop;
        o.dynamic_tables = true;
        REQUIRE_FALSE(has(advise(r, e, o), Issue::drop_rate_above_target));
    }
}

TEST_CASE("measured drops: acknowledged under drop, refused under fail, and the fix is checked on the data",
          "[psi][advice]") {
    const auto digests = records(4000);
    const Request r = request_for(4000);
    const Plan p = plan_of(32768, 2, 8, 32768);
    const Estimate e = estimate(r, p);

    SECTION("--on-overflow drop") {
        const Table t = build_table(digests, p.table_params(), Role::A, OverflowPolicy::drop);
        const std::uint64_t dropped = t.report().dropped;
        REQUIRE(dropped > 0);  // the case this exists for
        const Observed seen = observe(digests, dropped);
        AdviceOptions o;
        o.policy = OverflowPolicy::drop;
        o.observed = &seen;
        const Advice a = advise(r, e, o);
        REQUIRE(a.verdict(false) == Verdict::needs_acknowledgement);
        REQUIRE(a.verdict(true) == Verdict::accepted);
        const auto& f = finding(a, Issue::records_dropped);
        REQUIRE(f.message.find(std::to_string(dropped) + " of 4000") != std::string::npos);
        REQUIRE(f.message.find("fullest cell holds " + std::to_string(t.report().cell_max_load)) != std::string::npos);
        REQUIRE_FALSE(f.recommendations.empty());
        for (const auto& rec : f.recommendations) require_clean_on_data(r, rec, digests);
        REQUIRE(a.fix.size() == 1);
        require_clean_on_data(r, a.fix.front(), digests);
    }
    SECTION("--on-overflow fail") {
        std::uint64_t dropped = 0;
        try {
            (void)build_table(digests, p.table_params(), Role::A, OverflowPolicy::fail);
        } catch (const TableOverflow& ex) {
            dropped = ex.report().dropped;
        }
        REQUIRE(dropped > 0);
        const Observed seen = observe(digests, dropped);
        AdviceOptions o;
        o.observed = &seen;
        const Advice a = advise(r, e, o);
        REQUIRE(a.verdict(true) == Verdict::refused);
        const auto& f = finding(a, Issue::records_do_not_fit);
        for (const auto& rec : f.recommendations) require_clean_on_data(r, rec, digests);
        REQUIRE(a.fix.size() == 1);
        require_clean_on_data(r, a.fix.front(), digests);
    }
    SECTION("the fix covers this data's fullest cell, even where the model would settle for less") {
        // A loose target: the model's smallest adequate T at these cells is the T that just dropped.
        const Request loose = request_for(4000, 1e-2);
        REQUIRE(smallest_levels(4000, 32768, 1e-2) == p.levels);
        const Table t = build_table(digests, p.table_params(), Role::A, OverflowPolicy::drop);
        REQUIRE(t.report().dropped > 0);
        REQUIRE(t.report().cell_max_load > p.levels);
        const Observed seen = observe(digests, t.report().dropped);
        AdviceOptions o;
        o.policy = OverflowPolicy::drop;
        o.observed = &seen;
        const Advice a = advise(loose, estimate(loose, p), o);
        const auto& f = finding(a, Issue::records_dropped);
        REQUIRE_FALSE(f.recommendations.empty());
        for (const auto& rec : f.recommendations) require_clean_on_data(loose, rec, digests);
    }
    SECTION("an expected rate above the target is not held against a table that dropped nothing") {
        const Plan roomy = plan_of(32768, 2, 8, 32768);
        const auto few = records(300);
        const Request small = request_for(300);
        const Estimate est = estimate(small, roomy);
        REQUIRE(est.expected_drop_rate > small.target_drop_rate);
        const Table t = build_table(few, roomy.table_params(), Role::A, OverflowPolicy::drop);
        REQUIRE(t.report().dropped == 0);
        const Observed seen = observe(few, 0);
        AdviceOptions o;
        o.policy = OverflowPolicy::drop;
        o.observed = &seen;
        REQUIRE(advise(small, est, o).verdict(false) == Verdict::ok);
    }
}

TEST_CASE("a material false-match bound needs acknowledging, and more limbs fix it", "[psi][advice]") {
    SECTION("modelled") {
        const Request r = request_for(100000, 1e-6, 32);
        const Estimate e = estimate(r, plan_of(32768, 12, 1, 8));  // 31 bits delivered
        const Advice a = advise(r, e, AdviceOptions{});
        REQUIRE(a.verdict(false) == Verdict::needs_acknowledgement);
        const auto& f = finding(a, Issue::false_matches_material);
        REQUIRE(f.message.find("31 bits") != std::string::npos);
        REQUIRE(f.recommendations.size() == 1);
        const auto& rec = f.recommendations.front();
        REQUIRE(rec.plan.limbs == 2);
        REQUIRE(rec.signature_bits == 16 * rec.plan.limbs + 15);
        REQUIRE(limbs_for(rec.signature_bits, 32768, 8) == rec.plan.limbs);
        // The smallest limb count that fits: one fewer would not.
        Plan fewer = rec.plan;
        --fewer.limbs;
        REQUIRE(estimate(r, fewer).expected_false_matches > 1e-6 * 100000);
        require_flags_name_the_plan(rec);
        REQUIRE(estimate(r, rec.plan).expected_false_matches <= 1e-6 * 100000);
    }
    SECTION("the peer's count counts") {
        Request r = request_for(1000, 1e-6, 32);
        const Estimate alone = estimate(r, plan_of(256, 16, 2));
        REQUIRE_FALSE(has(advise(r, alone, AdviceOptions{}), Issue::false_matches_material));
        r.peer_records = 100000000;
        const Estimate lopsided = estimate(r, plan_of(256, 16, 2));
        REQUIRE(has(advise(r, lopsided, AdviceOptions{}), Issue::false_matches_material));
    }
    SECTION("beyond what the context can carry, no fix is invented") {
        // 7 limbs over one cell; even the context's 8 leave ~5e-20 against a budget of 4e-21.
        const Request r = request_for(4000000000ull, 1e-30);
        const Estimate e = estimate(r, plan_of(1, 64, 7));
        const Advice a = advise(r, e, AdviceOptions{});
        REQUIRE(has(a, Issue::false_matches_material));
        REQUIRE(finding(a, Issue::false_matches_material).recommendations.empty());
    }
}

TEST_CASE("a count that can wrap needs acknowledging, and finer groups fix it", "[psi][advice]") {
    SECTION("modelled: a pinned plan with one group, over 65536 records") {
        const Request r = request_for(100000);
        const Estimate e = estimate(r, plan_of(65536, 12, 8, 1));
        const Advice a = advise(r, e, AdviceOptions{});
        REQUIRE(a.verdict(false) == Verdict::needs_acknowledgement);
        const auto& f = finding(a, Issue::count_may_wrap);
        REQUIRE(f.message.find("65536") != std::string::npos);
        REQUIRE(f.recommendations.size() == 1);
        require_clean_in_model(r, f.recommendations.front(), everything(r));
        REQUIRE(f.recommendations.front().plan.count_groups == 8);  // 100000 / 8 <= 16384
    }
    SECTION("measured: the fix is the smallest grouping this data's fullest group fits") {
        const auto digests = records(70000);
        const Request r = request_for(70000);
        const Plan p = plan_of(32768, 12, 8, 1);
        const Estimate e = estimate(r, p);
        const Table t = build_table(digests, p.table_params(), Role::A, OverflowPolicy::fail);
        REQUIRE(fullest_group_placed(t, 1) == 70000);
        const Observed seen = observe(digests, 0);
        AdviceOptions o;
        o.observed = &seen;
        const Advice a = advise(r, e, o);
        REQUIRE(a.verdict(false) == Verdict::needs_acknowledgement);
        const auto& f = finding(a, Issue::count_may_wrap);
        REQUIRE(f.message.find("holds 70000 records") != std::string::npos);
        REQUIRE(f.recommendations.size() == 1);
        const auto& rec = f.recommendations.front();
        REQUIRE(rec.plan.count_groups == 2);
        REQUIRE(fullest_group_placed(t, 2) <= 65536);
        require_clean_on_data(r, rec, digests);
    }
}

TEST_CASE("the count-group disclosure is a notice and never blocks", "[psi][advice]") {
    const Request r = request_for(10000000);
    Plan p = solve(r).plan;
    p.shards = 1;
    const Advice a = advise(r, estimate(r, p), AdviceOptions{});
    REQUIRE(has(a, Issue::count_group_disclosure));
    REQUIRE(finding(a, Issue::count_group_disclosure).severity == Severity::notice);
    REQUIRE(a.verdict(false) == Verdict::ok);
}

TEST_CASE("the approximate variant is warned about in numbers, with the exact plan as the fix", "[psi][advice]") {
    Request r = request_for(120);
    Plan p = solve(r).plan;
    p.shards = 1;
    const Estimate exact = estimate(r, p);
    const Finding f = advise_approximate(r, exact);
    REQUIRE(f.severity == Severity::acknowledge);
    REQUIRE(f.message.find("0.879") != std::string::npos);  // 120 * 120 / 16384
    REQUIRE(f.recommendations.size() == 1);
    require_clean_in_model(r, f.recommendations.front(), everything(r));

    r.target_drop_rate = 1.0;  // a budget of one false match per record
    REQUIRE(advise_approximate(r, exact).severity == Severity::notice);
}

// The broad check: every unsafe configuration in a grid either has a fix that is clean when
// re-costed from scratch, or is one no parameter set in this context can clear.
TEST_CASE("every blocking configuration in a grid gets a fix that is clean when re-costed", "[psi][advice]") {
    std::uint64_t blocking = 0, fixed = 0;
    for (const std::uint64_t n : { 120ull, 1000ull, 5000ull, 100000ull }) {
        for (const unsigned bits : { 32u, 128u }) {
            const Request r = request_for(n, 1e-6, bits);
            for (const std::uint64_t cells : { 64ull, 1024ull, 16384ull, 65536ull }) {
                for (const unsigned tables : { 1u, 2u, 4u, 8u }) {
                    for (const unsigned limbs : { 1u, 3u, 8u }) {
                        for (const std::uint64_t groups : { 1ull, 64ull }) {
                            if (tables * tables * cells > 64 * 32768ull) continue;  // keep the grid quick
                            const Plan p = plan_of(cells, tables, limbs, groups);
                            const Estimate e = estimate(r, p);
                            for (const auto policy : { OverflowPolicy::fail, OverflowPolicy::drop }) {
                                AdviceOptions o;
                                o.policy = policy;
                                const Advice a = advise(r, e, o);
                                // Each per-problem fix, re-advised, no longer raises that problem.
                                for (const auto& f : a.findings) {
                                    for (const auto& rec : f.recommendations) {
                                        CAPTURE(n, bits, cells, tables, limbs, groups, issue_code(f.issue), rec.flags());
                                        REQUIRE_FALSE(has(advise(r, rec.estimate, o), f.issue));
                                    }
                                }
                                if (a.verdict(false) == Verdict::ok) continue;
                                ++blocking;
                                CAPTURE(n, bits, cells, tables, limbs, groups, policy == OverflowPolicy::drop);
                                REQUIRE(a.fix.size() == 1);  // every case in this grid is fixable
                                ++fixed;
                                Checks checks = everything(r);
                                if (policy == OverflowPolicy::fail) checks.drop_limit = 0.01;
                                require_clean_in_model(r, a.fix.front(), checks);
                                require_flags_name_the_plan(a.fix.front());
                                REQUIRE(advise(r, a.fix.front().estimate, o).verdict(false) == Verdict::ok);
                            }
                        }
                    }
                }
            }
        }
    }
    CAPTURE(blocking, fixed);
    REQUIRE(blocking > 100);
    REQUIRE(fixed == blocking);
}
