#ifndef FHE_TOOLKIT_PSI_COUNT_H
#define FHE_TOOLKIT_PSI_COUNT_H

// Reading the large-dataset count (psi-signature-match-count) once it is
// decrypted. Shared by the CLI's `crypto combine --count-groups` and the
// desktop app, so both refuse the same wrong shapes.
//
// Slot s holds partial sum s mod G, repeated across the ciphertext (the
// wrapper's strided sum). The answer is the total of the G sums. Only the total
// is returned: the per-group sums say how the matches spread across the key
// space, which is more than a count asks for. The repetition is checked first,
// so a result of another shape is refused rather than summed into a plausible
// wrong number.

#include <cstdint>
#include <vector>

namespace fhe_toolkit::psi {

// Throws std::invalid_argument when `groups` does not divide the slots, or when
// the slots are not `groups` partial sums repeated.
std::int64_t count_answer(const std::vector<std::int64_t>& values, std::uint64_t groups);

}  // namespace fhe_toolkit::psi

#endif  // FHE_TOOLKIT_PSI_COUNT_H
