#ifndef FHE_TOOLKIT_PSI_BUNDLE_H
#define FHE_TOOLKIT_PSI_BUNDLE_H

// The wire form of a signature-table bundle: which cell every slot of every
// ciphertext carries, and the header that declares it. The platform's
// psi-signature-match ops parse exactly this (wrapper-service/cpp/ops.cpp, the
// BUNDLE contract; design §2.2-2.3).
//
//   PSI-TABLE v1 / ROLE / CELLS / TABLES / LIMBS / GROUPS / SLOTS / LAYOUT /
//   CIPHERTEXTS, then "PAYLOAD\n", then one cereal archive of the ciphertexts.
//
// Nothing here encrypts. Layout is the part that has to agree with the server
// and with the other party, so it is kept apart from the crypto and tested on
// its own; the CLI adds only encode + encrypt + write.
//
// Compared positions are numbered pos = (ja*T + jb)*m + cell, ja being A's level
// and jb B's, cut into chunks of N slots. Which storage form holds them is fixed
// by m and N, not chosen:
//
//   m <  N   prealigned   the chunks themselves; ciphertext c*k + j, and slot s
//                         of chunk c holds this party's own limb at its own level
//                         of that pair. Positions past T^2*m are padding and hold
//                         this role's sentinel, which can never match.
//   m >= N   per-level    one ciphertext per (level, block, limb), N cells to a
//                         block; ciphertext (level*(m/N) + block)*k + j, slot s
//                         holding cell block*N + s. No padding.

#include <cstdint>
#include <span>
#include <string>

#include "psi/table.h"

namespace fhe_toolkit::psi {

struct BundleLayout {
    std::uint64_t cells       = 0;  // m
    std::uint64_t tables      = 0;  // T
    std::uint64_t limbs       = 0;  // k
    std::uint64_t groups      = 1;  // L: partial sums the count comes back as
    std::uint64_t slots       = 0;  // N: the ring dimension this was laid out for
    bool          per_level   = false;
    std::uint64_t blocks      = 1;  // per-level: m / N, else 1
    std::uint64_t chunks      = 0;  // slot-aligned comparisons the server will run
    std::uint64_t ciphertexts = 0;

    const char* layout_name() const noexcept { return per_level ? "per-level" : "prealigned"; }
};

// Throws std::invalid_argument on anything the server would refuse.
BundleLayout bundle_layout(const TableParams& params, std::uint64_t groups, std::uint64_t slots);

// The header, up to and including the PAYLOAD marker.
std::string bundle_header(const BundleLayout& layout, Role role);

// The slot vector ciphertext `index` is encoded from; out.size() must be `slots`.
void bundle_slots(const Table& table, const BundleLayout& layout, std::uint64_t index,
                  std::span<std::int64_t> out);

}  // namespace fhe_toolkit::psi

#endif
