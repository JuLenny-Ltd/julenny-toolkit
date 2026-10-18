// The fixed dataset sizes (psi/size_class). Each class makes one promise: a file at the very top of
// it is refused at most once in 100 000 encodes. The table is shared with the platform, so these
// tests also pin its shape: ids, order, and settings the encoder accepts.
#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <set>
#include <string>

#include "psi/encoder.h"
#include "psi/size_class.h"
#include "psi/solver.h"

using namespace fhe_toolkit::psi;

TEST_CASE("every size class keeps a full-size refusal at or below 1 in 100 000", "[psi][size-class]") {
    for (const auto& c : size_classes()) {
        CAPTURE(std::string(c.id));
        Request req;
        req.records = c.max_records;
        req.signature_bits = 128;
        Plan plan;
        plan.cells_total = c.cells;
        plan.levels = c.tables;
        plan.limbs = c.limbs;
        plan.count_groups = c.count_groups;
        plan.shards = c.shards;
        const Estimate e = estimate(req, plan);
        // Expected records that would not fit, at full size: below 1e-5 bounds the chance of any.
        CHECK(e.expected_drop_rate * static_cast<double>(c.max_records) <= 1e-5);
    }
}

TEST_CASE("size classes double, are unique, and are found by their id", "[psi][size-class]") {
    std::set<std::string> ids;
    std::uint64_t previous = 0;
    for (const auto& c : size_classes()) {
        CHECK(ids.insert(std::string(c.id)).second);
        CHECK((previous == 0 || c.max_records == previous * 2));
        previous = c.max_records;
        CHECK(size_class(c.id) == &c);
        // A count group carries at most 65 536 matches; a class must never ask one to carry more.
        CHECK(c.max_records / c.count_groups <= 65536);
        CHECK(c.cells % c.shards == 0);
    }
    CHECK(size_class("3K") == nullptr);
    CHECK(size_class("") == nullptr);
    CHECK(size_class("64k") == nullptr);  // ids are exact: what the permission stores is what is looked up
}

TEST_CASE("the smallest size that holds a count is chosen at the class boundaries", "[psi][size-class]") {
    REQUIRE(smallest_size_class_for(1) != nullptr);
    CHECK(smallest_size_class_for(1)->id == "1K");
    CHECK(smallest_size_class_for(1024)->id == "1K");
    CHECK(smallest_size_class_for(1025)->id == "2K");
    CHECK(smallest_size_class_for(32769)->id == "64K");
    CHECK(smallest_size_class_for(65536)->id == "64K");
    CHECK(smallest_size_class_for(65537) == nullptr);  // above every class: no size holds it
}

TEST_CASE("count_records counts as the encoder reads: lines skipped, columns composed, repeats once",
          "[psi][size-class]") {
    const auto path = std::filesystem::temp_directory_path() / "fhe_toolkit_count_records_test.csv";
    {
        std::ofstream f(path, std::ios::trunc);
        f << "name,dob,email\n"          // header
          << "ann,1990,a@x\n"
          << "ann,1990,a@x\n"            // an exact repeat: one record
          << "  ann , 1990 , b@x \n"     // same name and dob, other email
          << "\n"                        // blank
          << "# a comment\n"
          << "bob,1985,b@y\n";
    }
    const auto all = count_records(path, ',', parse_columns("all"), true, "julenny-psi-v1");
    CHECK(all.lines_seen == 7);
    CHECK(all.lines_skipped == 3);       // header, blank, comment
    CHECK(all.records_read == 4);
    CHECK(all.distinct_records == 3);    // the repeat counts once

    // Only name and dob: the two ann rows are now the same record.
    const auto two = count_records(path, ',', parse_columns("1,2"), true, "julenny-psi-v1");
    CHECK(two.records_read == 4);
    CHECK(two.distinct_records == 2);

    std::filesystem::remove(path);
    CHECK_THROWS_AS(count_records(path, ',', {}, true, "julenny-psi-v1"), EncodeError);
}
