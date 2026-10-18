#ifndef FHE_TOOLKIT_PSI_ITEMIZED_RESULT_H
#define FHE_TOOLKIT_PSI_ITEMIZED_RESULT_H

// Reading out a large-dataset ITEMIZED result: which of the viewer's own records the other party
// also holds. Shared by the CLI, and through it the connector and the scripts, and by the Windows
// app, so every channel decodes the same way.
//
// The wire format is the platform's: a text header beginning `PSI-ITEMIZED v1`, then
// `PAYLOAD\n`, then one cereal archive of n ciphertexts, mask-major. Bit b of mask q at cell c is
// the viewer's level 16q + b at that cell.
//
// The flow, mirroring the compact itemized functions:
//   1. each party partially decrypts EVERY ciphertext of the result: `partial_decrypt_itemized`
//      writes one PSI-ITEMIZED-PARTIAL v1 file (the result's header, then the partials);
//   2. the viewer combines the two partial files into the masks: `combine_itemized`, applying the
//      platform's decoding rules (residues normalised, nothing above 16 bits, repeats agree);
//   3. the viewer rebuilds its own table from its CSV (placement is a function of the record
//      set) and maps the marked positions back to its rows: `resolve_itemized_rows`.
//
// Sharded results (`PSI-ITEMIZED-SHARDED v1`) are refused for now: no dataset size offered today
// is sharded.

#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "crypto/context.h"
#include "crypto/keys.h"
#include "psi/encoder.h"

namespace fhe_toolkit::psi {

inline constexpr std::string_view kItemizedResultMarker  = "PSI-ITEMIZED v1";
inline constexpr std::string_view kItemizedPartialMarker = "PSI-ITEMIZED-PARTIAL v1";
inline constexpr std::string_view kItemizedShardedMarker = "PSI-ITEMIZED-SHARDED v1";

enum class ItemizedKind { none, result, partial, sharded };

/** What a file is, from its first line. `none` for anything else (an ordinary ciphertext). */
ItemizedKind itemized_kind(std::span<const std::byte> bytes);

struct ItemizedHeader {
    char          viewer = 'A';        // the party the result is laid out for
    std::uint64_t cells = 0;           // this shard's cells
    unsigned      tables = 0;          // the viewer's levels, T
    unsigned      masks = 0;           // ceil(T / 16)
    std::uint64_t slots = 0;           // N
    bool          per_level = false;   // per-level (m >= N) or prealigned (m < N)
    std::uint64_t ciphertexts = 0;     // masks * blocks
    std::uint64_t shards = 1;
    std::uint64_t shard = 0;
};

/** Thrown for a file that is not what it claims to be, or a result the circuit got wrong. */
class ItemizedError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

/**
 * Partially decrypt every ciphertext of a PSI-ITEMIZED v1 result. Returns the PSI-ITEMIZED-PARTIAL
 * v1 file: the result's header, a `PARTIAL lead|main` line, then one archive of the partials.
 */
std::vector<std::byte> partial_decrypt_itemized(const crypto::Context& ctx, const crypto::SecretKey& sk,
                                                std::span<const std::byte> result, bool lead);

/** The viewer's masks: masks[q][cell], the shape `resolve_matches` takes. */
struct ItemizedMasks {
    ItemizedHeader header;
    std::vector<std::vector<std::uint32_t>> masks;
};

/**
 * Combine the parties' partial files into the masks, decoding by the platform's rules. The files
 * must come from the same result (identical headers) and include a lead and a main partial.
 */
ItemizedMasks combine_itemized(const crypto::Context& ctx, std::uint64_t plaintext_modulus,
                               const std::vector<std::vector<std::byte>>& partials);

/** The masks as the JSON file written between combining and resolving. It is the answer, encoded. */
std::string itemized_masks_json(const ItemizedMasks& m);
ItemizedMasks itemized_masks_from_json(const std::string& text);

/** The viewer's rows that the other party also holds, in file order, with the header row if any. */
struct ItemizedRows {
    std::string              header_line;   // empty when the file has no header row
    std::vector<std::string> rows;          // every matching row, duplicates included
    std::size_t              matched_records = 0;  // distinct records the result marked
};

/**
 * Rebuild the viewer's table from its CSV with exactly the encode settings (`req`: input, separator,
 * columns, header, domain, role, and the size class or table settings; the key and output fields are
 * not used) and return the rows whose records the masks mark. Refuses a table that does not match
 * the result's shape, or a result laid out for the other party.
 */
ItemizedRows resolve_itemized_rows(const EncodeRequest& req, const ItemizedMasks& masks);

}  // namespace fhe_toolkit::psi

#endif  // FHE_TOOLKIT_PSI_ITEMIZED_RESULT_H
