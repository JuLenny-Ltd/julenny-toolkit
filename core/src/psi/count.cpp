#include "psi/count.h"

#include <stdexcept>
#include <string>

namespace fhe_toolkit::psi {

std::int64_t count_answer(const std::vector<std::int64_t>& values, std::uint64_t groups) {
    if (groups == 0 || groups > values.size() || values.size() % groups != 0) {
        throw std::invalid_argument(std::to_string(groups) + " count groups do not divide the "
                                    + std::to_string(values.size()) + " slots of this result");
    }
    for (std::size_t s = 0; s < values.size(); ++s) {
        if (values[s] != values[s % groups]) {
            throw std::invalid_argument("this result is not " + std::to_string(groups)
                                        + " partial sums repeated across the slots (slot " + std::to_string(s)
                                        + " differs from slot " + std::to_string(s % groups)
                                        + "): check the count groups against the grant's psiParams.countGroups, "
                                          "and the function");
        }
    }
    std::int64_t total = 0;
    for (std::size_t s = 0; s < groups; ++s) total += values[s];
    return total;
}

}  // namespace fhe_toolkit::psi
