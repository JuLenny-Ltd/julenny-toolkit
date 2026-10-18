#ifndef FHE_TOOLKIT_PSI_SIZE_CLASS_H
#define FHE_TOOLKIT_PSI_SIZE_CLASS_H

// The fixed dataset sizes a large-dataset permission is made for.
//
// A permission names one class ("64K"), proposed by the data owner and confirmed or increased by
// the partner. Both companies' toolkits look its table settings up here, so nobody types cells or
// tables, and what the permission reveals about either dataset is only that it fits the class.
//
// Every class was sized once with this toolkit's own solver (`crypto psi-estimate`) at
// --target-overflow 1e-5 / max_records: a file at the very top of its class is refused (a record
// would not fit, and none is ever left out) at most once in 100 000 encodes; a smaller file far
// more rarely. A refusal never gives a wrong answer; the company moves up one class.
//
// The platform carries the same table. The two must match EXACTLY, like the crypto context specs:
// a mismatch makes the two parties' tables incomparable. Changing a class means a new id, never
// new numbers under an existing one.

#include <cstdint>
#include <span>
#include <string_view>

namespace fhe_toolkit::psi {

struct SizeClass {
    std::string_view id;           // "64K": what the permission, the CLI and the app call it
    std::uint64_t    max_records;  // distinct records per party; K is binary (64K = 65 536)
    std::uint64_t    cells;
    unsigned         tables;
    unsigned         limbs;
    std::uint64_t    count_groups;
    std::uint64_t    shards;
};

/** Every class, smallest first. */
std::span<const SizeClass> size_classes();

/** The class with this id, or nullptr. */
const SizeClass* size_class(std::string_view id);

/** The smallest class that holds this many distinct records, or nullptr when none does. */
const SizeClass* smallest_size_class_for(std::uint64_t distinct_records);

}  // namespace fhe_toolkit::psi

#endif  // FHE_TOOLKIT_PSI_SIZE_CLASS_H
