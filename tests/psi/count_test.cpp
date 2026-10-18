// Reading the large-dataset count (psi/count): the total of the G partial sums, and a refusal for
// any result that is not G sums repeated across the slots, so a wrong shape never becomes a
// plausible wrong number.
#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <stdexcept>
#include <vector>

#include "psi/count.h"

using namespace fhe_toolkit::psi;

namespace {

// G partial sums repeated across `slots` slots, as the wrapper's strided sum leaves them.
std::vector<std::int64_t> repeated(const std::vector<std::int64_t>& sums, std::size_t slots) {
    std::vector<std::int64_t> out(slots);
    for (std::size_t s = 0; s < slots; ++s) out[s] = sums[s % sums.size()];
    return out;
}

}  // namespace

TEST_CASE("count_answer adds the G partial sums", "[psi][count]") {
    CHECK(count_answer(repeated({7}, 32), 1) == 7);
    CHECK(count_answer(repeated({3, 0, 5, 2}, 32), 4) == 10);
    CHECK(count_answer(repeated({0, 0}, 16), 2) == 0);
}

TEST_CASE("count_answer refuses a result that is not G repeated sums", "[psi][count]") {
    // An itemized vector, or a count read with the wrong G, is not repeated with period G.
    auto values = repeated({3, 0, 5, 2}, 32);
    CHECK_THROWS_AS(count_answer(values, 2), std::invalid_argument);
    values[17] = 9;
    CHECK_THROWS_AS(count_answer(values, 4), std::invalid_argument);
}

TEST_CASE("count_answer refuses a G that does not divide the slots", "[psi][count]") {
    const auto values = repeated({1}, 32);
    CHECK_THROWS_AS(count_answer(values, 0), std::invalid_argument);
    CHECK_THROWS_AS(count_answer(values, 3), std::invalid_argument);
    CHECK_THROWS_AS(count_answer(values, 64), std::invalid_argument);
}
