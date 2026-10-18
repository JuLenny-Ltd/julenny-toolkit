#ifndef FHE_TOOLKIT_PSI_ENCODER_H
#define FHE_TOOLKIT_PSI_ENCODER_H

// signature-table: the large-dataset encoder.
//
// Rows -> record digests (psi/digest) -> T associative tables with sentinel
// fill (psi/table) -> one ciphertext per (position block, limb) behind the
// header the wrapper's psi-signature-match ops parse (psi/bundle), one file per
// shard, plus the shard manifests.
//
// Kept in core rather than in the CLI because every surface that encodes must
// write the same files and tell the platform the same thing: the CLI (and so
// the connector and the scripts, which call it) and the desktop app, which is
// installed without the CLI. Each surface only renders the result: this file
// prints nothing.
//
// No record is ever left out: if one does not fit the table, nothing is
// encoded, and the fix is a larger table. The answer is exact or there is none.
//
// What the platform is told is `EncodeResult::platform_report` and nothing
// else (zero trust): whether this side's records fit one count group, and the
// table's shape. Never a record count. The counts are in the
// result for the local user, and in <output>.manifest.local.json, which is
// written for this party only and never uploaded. The report is also written
// on its own, as <output>.platform-report.json, for a channel that uploads files
// rather than calling the API (the web UI): the file holds nothing else, so
// what is uploaded is exactly what the user can open and read.

#include <cstdint>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "crypto/context.h"
#include "psi/advice.h"
#include "psi/bundle.h"
#include "psi/solver.h"
#include "psi/table.h"

namespace fhe_toolkit::psi {

// ---------------------------------------------------------------------------
// One input line -> the string that is digested. The rules every schema uses:
// whitespace trimmed, no separator = the whole line, otherwise the selected
// 1-based columns (all when none are named), each trimmed, joined by the ASCII
// Unit Separator (\x1F) so the joined string is unambiguous.
// ---------------------------------------------------------------------------
std::string      trim_field(std::string s);
std::vector<int> parse_columns(const std::string& spec);  // "all" or "" -> empty = every column
std::string      compose_record(const std::string& line, char separator, const std::vector<int>& columns);

// ---------------------------------------------------------------------------
// Sizing, shared by the encoder and the CLI's dry run, so the
// estimate describes the bundle the encoder will actually write. The solver
// picks what the arguments leave at 0.
//
// Sharding: `shards` pins P, 0 leaves the solver's choice. The cell
// count is the WHOLE key space either way - a shard holds cells_total / P of it
// - so pinning cells and shards together says "this many cells, split this
// many ways", not "this many cells per shard". P must divide cells_total.
// Throws std::invalid_argument, with the flag names the CLI uses.
// ---------------------------------------------------------------------------
Plan plan_signature_table(const Request& req, std::uint64_t cells, unsigned tables, unsigned limbs,
                          std::uint64_t count_groups, std::uint64_t shards = 0);

// Splitting past one ciphertext of cells per shard is legal but wasteful: every shard rounds its
// slot layout up to a whole ciphertext. Empty when the split costs nothing.
std::string shard_granularity_note(const Plan& plan, std::uint64_t slots);

// t - 1 at t = 65537: the largest value one BFV slot can carry. A count group holding more of this
// party's records than this could wrap.
constexpr std::uint64_t count_ceiling = 65536;

// The most placed records in any one count group, across every shard (group g collects every cell
// congruent to g mod groups; shards are added slot by slot). Bounds every partial sum from this side.
std::uint64_t max_records_per_group(const std::vector<Table>& tables, std::uint64_t groups);

// ---------------------------------------------------------------------------
// The encoder.
// ---------------------------------------------------------------------------
struct EncodeRequest {
    std::filesystem::path input;             // the CSV
    std::filesystem::path joint_public_key;
    std::filesystem::path output;            // unsharded: this file; sharded: <output>.shard-NNNNN + manifests
    crypto::CryptoContextSpec spec;
    std::uint64_t slot_count = 0;

    char             separator = '\0';       // '\0' = the whole line is the record
    std::vector<int> columns;                // 1-based; empty = every column
    bool             skip_header = false;

    std::string role;                        // "A" or "B": which sentinel fills the empty cells
    std::string domain = "julenny-psi-v1";   // hashed in front of every record; both parties must match

    unsigned      signature_bits = 128;
    std::uint64_t cells = 0;                 // 0 = the solver's choice, as for every sizing field
    unsigned      tables = 0;
    bool          dynamic_tables = false;
    unsigned      limbs = 0;
    std::uint64_t count_groups = 0;
    std::uint64_t shards = 1;
    std::uint64_t capacity = 0;              // size for this many records (0 = the ones read)
    double        target_overflow = 1e-6;

    // A size class (psi/size_class), as named on the permission. When set, its settings replace the
    // sizing fields above (which must then be left at their defaults), and a file with more distinct
    // records than the class allows is refused before anything is built.
    std::string size_class;

    // Provenance, written into the manifests when encoding against a function definition.
    std::string function_slug;
    std::string function_version;
    std::string input_name;
};

// Why an encoding did or did not happen. Every status but `encoded` wrote nothing and carries the
// accuracy advice that explains it.
enum class EncodeStatus {
    encoded,
    refused_before_encoding,  // the model says records would not fit: no table was built
    table_overflow,           // a record did not fit its cell: nothing is ever left out, so refused
    refused,                  // the advice does not pass what the table holds (nothing degraded is encoded)
    too_many_records,         // more distinct records than the permission's size class allows
};

struct EncodeResult {
    EncodeStatus status = EncodeStatus::encoded;
    std::string  reason;         // one line, when not encoded
    Advice       advice;
    Verdict      verdict = Verdict::ok;

    // What was read.
    std::size_t lines_seen = 0;
    std::size_t lines_skipped = 0;
    std::size_t records_read = 0;
    std::size_t distinct_records = 0;  // set when checked against a size class

    // The sizing, as solved and as used.
    Request     request;
    Plan        plan;
    Estimate    estimate;
    unsigned    solved_tables = 0;  // the model's T, before dynamic_tables replaced it
    std::string shard_note;

    // Set once the tables are built.
    PlacementReport totals;
    std::uint64_t   most_records_per_group = 0;
    bool            count_fits_groups = true;

    // Set once encoded.
    BundleLayout                       layout;
    std::uint64_t                      shard_count = 1;
    std::uint64_t                      bytes = 0;
    std::vector<std::filesystem::path> files;            // every ciphertext file, in shard order
    std::filesystem::path              manifest_path;       // sharded only: the uploaded manifest
    std::filesystem::path              local_manifest_path; // sharded only: with the counts, never uploaded
    nlohmann::json                     shard_files_local = nlohmann::json::array();  // with the counts
    nlohmann::json                     platform_report;     // the ONLY part that may leave the machine
    std::filesystem::path              platform_report_path; // <output>.platform-report.json: it, and nothing else
};

// A request that cannot be encoded at all, as opposed to one the accuracy advice turned down.
// `usage` marks a bad argument (the CLI's exit 2) rather than bad data or I/O (exit 1).
class EncodeError : public std::runtime_error {
public:
    EncodeError(const std::string& what, bool usage) : std::runtime_error(what), usage_(usage) {}
    bool usage() const noexcept { return usage_; }
private:
    bool usage_;
};

// Reads, sizes, builds, judges and, when the verdict allows, encrypts and writes. Throws EncodeError
// for a request it cannot act on; exceptions from key or file I/O propagate as they are.
EncodeResult encode_signature_table(const EncodeRequest& req);

// How many records a file holds, read exactly as encode_signature_table reads it: the same lines
// skipped, the same columns composed, repeated rows counted once. It is what picks a permission's
// dataset size from a file, and it must never disagree with the encoder's size check, or a size
// picked here could be refused at encryption. The count stays on this machine: callers report only
// the size it implies. Throws EncodeError when the file cannot be read.
struct RecordCount {
    std::size_t lines_seen = 0;
    std::size_t lines_skipped = 0;
    std::size_t records_read = 0;
    std::size_t distinct_records = 0;
};
RecordCount count_records(const std::filesystem::path& input, char separator, const std::vector<int>& columns,
                          bool skip_header, const std::string& domain);

}  // namespace fhe_toolkit::psi

#endif  // FHE_TOOLKIT_PSI_ENCODER_H
