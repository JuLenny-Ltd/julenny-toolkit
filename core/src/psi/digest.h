#ifndef FHE_TOOLKIT_PSI_DIGEST_H
#define FHE_TOOLKIT_PSI_DIGEST_H

// Record -> (position, signature) for the exact joint-record-overlap encoding
// (platform plans/exact-psi-signature-tables.md §2.1).
//
// One SHA-256 per record. The digest is then cut into two DISJOINT byte ranges:
//
//   preimage  = domain_separator || 0x00 || record      (domain must not contain 0x00)
//   digest    = SHA-256(preimage)                        32 bytes
//   address   = digest[0..4)   as little-endian uint32   position = address mod cells
//   limb j    = digest[4+2j .. 6+2j) as little-endian uint16, j = 0 .. limbs-1
//
// The ranges must not overlap, and this is a correctness requirement. `cells` is
// a power of two, so `address mod cells` is the low log2(cells) bits of the
// address. Were the signature cut from those same bits, two records sharing a
// cell would already agree on log2(cells) of the bits being compared, and the
// comparison would discriminate on S - log2(cells) bits while claiming S. The
// scheme would still "work", which is what makes that bug invisible. Starting the
// signature at byte 4 leaves room for up to 2^32 cells and costs nothing.
//
// This byte layout is a cross-party, cross-platform wire contract: both parties,
// and any non-C++ encoder, must reproduce it bit for bit. It is pinned by the
// known-answer vectors in tests/psi/digest_test.cpp.
//
// Sentinel remapping of signatures that land on the reserved empty-cell values
// is placement's job (psi/table), not this file's.
//
// SHARDING (design §2.7 item 1, step F1). Above ~10^6 records one table does not
// fit in memory or in one upload, so the key space is split into P shards and
// each is an independent PSI over ~n/P records. The split has to be a function
// of the record alone - "shard p holds the records with h(x) mod P == p" - so
// that both parties shard identically without exchanging anything.
//
// The bits it uses are NOT free. Taking the shard from the low log2(P) bits of
// the address and then computing the in-shard cell as `address mod cells` would
// leave every record of a shard agreeing on those low bits, collapsing the
// shard's effective cell count from m to m/P and multiplying its collisions by
// P - silently, since the encoding would still "work". So the position is SPLIT
// rather than re-derived:
//
//   position  = address mod cells_total       log2(cells_total) bits
//   shard     = position mod P                the low  log2(P) bits
//   cell      = position div P                the high log2(cells_total/P) bits
//
// Shard and cell together reconstruct the position exactly, so the union of the
// P sharded tables has the same occupancy - cell for cell, collision for
// collision - as one unsharded table of cells_total cells. That is what makes a
// sharded run and an unsharded run of the same data give the same number, and
// what makes P = 1 identical to not sharding at all rather than merely similar.
//
// `shard = position mod P` is `address mod P` (P divides cells_total, both
// powers of two), which is the design's wording; it is written in terms of the
// position because that is the quantity whose bits must not be spent twice.

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

namespace fhe_toolkit::psi {

constexpr std::size_t   digest_bytes     = 32;
constexpr std::size_t   address_bytes    = 4;              // digest[0..4)
constexpr std::size_t   signature_offset = address_bytes;  // signature starts right after
constexpr unsigned      limb_bits        = 16;             // one BFV slot under t = 65537
constexpr unsigned      max_limbs        = (digest_bytes - signature_offset) / 2;  // 14
constexpr std::uint64_t max_cells        = std::uint64_t{1} << (8 * address_bytes);

using Digest = std::array<std::uint8_t, digest_bytes>;

// Plain SHA-256 of `bytes` (OpenSSL). Exposed so it can be checked against the
// FIPS 180-2 vectors independently of the preimage layout above.
Digest sha256(std::string_view bytes);

// SHA-256(domain_separator || 0x00 || record). `record` may contain any bytes.
// Throws std::invalid_argument if the domain separator is empty or contains a
// 0x00 byte (either would make the preimage ambiguous across domains).
Digest record_digest(std::string_view domain_separator, std::string_view record);

// The 32-bit address word, digest[0..4) little-endian.
std::uint32_t address(const Digest& d) noexcept;

// address(d) mod cells. Throws std::invalid_argument unless `cells` is a power
// of two in [1, 2^32].
std::uint32_t position(const Digest& d, std::uint64_t cells);

// Which shard this record belongs to: the low log2(shards) bits of its position,
// which is `address(d) mod shards`. Throws std::invalid_argument unless `shards`
// is a power of two in [1, 2^32].
std::uint32_t shard_of(const Digest& d, std::uint64_t shards);

// The cell this record takes inside its own shard: the remaining high bits of
// its position, `position(d, cells_total) / shards`. A shard therefore holds
// cells_total / shards cells. Throws std::invalid_argument unless both are
// powers of two and `shards` divides `cells_total`.
//
// Invariant, checked by the tests:
//   position(d, cells_total) == position_in_shard(d, cells_total, P) * P + shard_of(d, P)
std::uint32_t position_in_shard(const Digest& d, std::uint64_t cells_total, std::uint64_t shards);

// Split digests into `shards` buckets by shard_of, preserving order within each.
// Done once for a whole dataset rather than filtering per shard, which would be
// O(P * n); the buckets are then what each shard's table is built from. Because
// the split is a function of the digest, duplicates land in the same bucket, so
// deduping the buckets is the same as deduping the whole set.
std::vector<std::vector<Digest>> partition_by_shard(const std::vector<Digest>& digests,
                                                    std::uint64_t shards);

// Limb j of the signature, digest[4+2j .. 6+2j) little-endian. Throws
// std::out_of_range unless j < max_limbs.
std::uint16_t limb(const Digest& d, unsigned j);

// Limbs 0 .. limbs-1. Throws std::invalid_argument unless 1 <= limbs <= max_limbs.
std::vector<std::uint16_t> signature(const Digest& d, unsigned limbs);

// Set semantics (design Q8): collapse repeated records to one, keyed on the FULL
// 256-bit digest. Keying on the truncated (position, signature) instead would let
// a truncation collision silently merge two genuinely different records.
// Leaves `digests` sorted, which also makes everything downstream independent of
// the order rows appeared in the input. Returns the number of entries removed.
std::size_t dedupe(std::vector<Digest>& digests);

}  // namespace fhe_toolkit::psi

#endif
