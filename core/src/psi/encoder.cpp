#include "psi/encoder.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iomanip>
#include <map>
#include <memory>
#include <span>
#include <sstream>

#include "crypto/ciphertext.h"
#include "crypto/keys.h"
#include "psi/digest.h"
#include "psi/size_class.h"
#include "registry/envelope.h"

namespace fhe_toolkit::psi {

using nlohmann::json;
namespace fs = std::filesystem;

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------
std::string trim_field(std::string s) {
    auto not_space = [](unsigned char c) { return !std::isspace(c); };
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), not_space));
    s.erase(std::find_if(s.rbegin(), s.rend(), not_space).base(), s.end());
    return s;
}

namespace {

// Split by a single-character delimiter; fields are not trimmed here.
std::vector<std::string> split_fields(const std::string& s, char delim) {
    std::vector<std::string> out;
    std::string field;
    std::stringstream ss(s);
    while (std::getline(ss, field, delim)) out.push_back(field);
    return out;
}

std::vector<std::byte> read_file(const fs::path& path) {
    std::ifstream in(path, std::ios::binary | std::ios::ate);
    if (!in) throw std::runtime_error("cannot open for reading: " + path.string());
    auto size = static_cast<std::size_t>(in.tellg());
    in.seekg(0, std::ios::beg);
    std::vector<std::byte> bytes(size);
    if (size > 0) {
        in.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(size));
        if (!in) throw std::runtime_error("read failed: " + path.string());
    }
    return bytes;
}

}  // namespace

std::vector<int> parse_columns(const std::string& spec) {
    std::vector<int> out;
    if (spec.empty() || spec == "all") return out;
    for (auto& part : split_fields(spec, ',')) {
        auto t = trim_field(part);
        if (!t.empty()) {
            try { out.push_back(std::stoi(t)); }
            catch (...) { /* skip non-numeric */ }
        }
    }
    return out;
}

std::string compose_record(const std::string& line, char separator, const std::vector<int>& columns) {
    if (separator == '\0') return trim_field(line);
    auto fields = split_fields(line, separator);
    std::string composed;
    if (columns.empty()) {
        for (std::size_t i = 0; i < fields.size(); ++i) {
            if (i > 0) composed.push_back('\x1F');
            composed.append(trim_field(fields[i]));
        }
    } else {
        for (std::size_t i = 0; i < columns.size(); ++i) {
            const int col = columns[i] - 1;
            if (col >= 0 && col < static_cast<int>(fields.size())) {
                if (i > 0) composed.push_back('\x1F');
                composed.append(trim_field(fields[static_cast<std::size_t>(col)]));
            }
        }
    }
    return composed;
}

// ---------------------------------------------------------------------------
// Sizing
// ---------------------------------------------------------------------------
Plan plan_signature_table(const Request& req, std::uint64_t cells, unsigned tables, unsigned limbs,
                          std::uint64_t count_groups, std::uint64_t shards) {
    Plan plan;
    if (cells > 0 && tables > 0) {
        plan.cells_total  = cells;
        plan.levels       = tables;
        plan.count_groups = count_groups > 0 ? count_groups : 1;
    } else {
        plan = solve(req).plan;
        if (cells > 0)  plan.cells_total = cells;
        if (tables > 0) plan.levels = tables;
        if (count_groups > 0) plan.count_groups = count_groups;
    }
    if (shards > 0) plan.shards = shards;
    if (plan.shards == 0 || (plan.shards & (plan.shards - 1)) != 0) {
        throw std::invalid_argument("--shards must be a power of two, got " + std::to_string(plan.shards));
    }
    if (plan.cells_total % plan.shards != 0) {
        throw std::invalid_argument("--shards " + std::to_string(plan.shards) + " does not divide the "
                                    + std::to_string(plan.cells_total) + " cells; a shard must hold a whole "
                                    "number of cells");
    }
    if (plan.count_groups > plan.cells_per_shard()) {
        throw std::invalid_argument("--count-groups " + std::to_string(plan.count_groups)
                                    + " cannot exceed the " + std::to_string(plan.cells_per_shard())
                                    + " cells in one shard: a group is a residue class of a shard's cells");
    }
    plan.limbs = limbs > 0 ? limbs : limbs_for(req.signature_bits, plan.cells_total, req.context.max_limbs);
    return plan;
}

std::string shard_granularity_note(const Plan& plan, std::uint64_t slots) {
    if (plan.shards <= 1 || plan.cells_per_shard() >= slots) return {};
    return "note: " + std::to_string(plan.shards) + " shards of " + std::to_string(plan.cells_per_shard())
         + " cells each are smaller than one ciphertext of " + std::to_string(slots)
         + " slots, so every shard rounds up to a whole ciphertext and the upload is about "
         + std::to_string(slots / plan.cells_per_shard()) + "x what "
         + std::to_string(plan.cells_total) + " cells in one shard would cost. Use fewer shards, or "
           "more cells, unless the split is what you are after.";
}

std::uint64_t max_records_per_group(const std::vector<Table>& tables, std::uint64_t groups) {
    std::vector<std::uint64_t> per_group(static_cast<std::size_t>(groups), 0);
    for (const auto& table : tables) {
        const auto& params = table.params();
        for (unsigned level = 0; level < params.levels; ++level) {
            for (std::uint64_t cell = 0; cell < params.cells; ++cell) {
                if (table.occupant(level, cell) != Table::empty) {
                    ++per_group[static_cast<std::size_t>(cell % groups)];
                }
            }
        }
    }
    std::uint64_t most = 0;
    for (const auto n : per_group) most = std::max(most, n);
    return most;
}

// ---------------------------------------------------------------------------
// The encoder
// ---------------------------------------------------------------------------
namespace {

/** 70123 -> "70,123": the count in the too-many-records message, read by a person. */
std::string with_commas(std::uint64_t n) {
    std::string digits = std::to_string(n);
    for (int i = static_cast<int>(digits.size()) - 3; i > 0; i -= 3) digits.insert(static_cast<std::size_t>(i), ",");
    return digits;
}

// The one way a file becomes record digests, shared by the encoder and count_records so the two
// can never disagree about how many records a file holds.
std::vector<Digest> read_digests(const fs::path& input, char separator, const std::vector<int>& columns,
                                 bool skip_header, const std::string& domain,
                                 std::size_t& lines_seen, std::size_t& lines_skipped) {
    std::ifstream in_file(input);
    if (!in_file) throw EncodeError("cannot open input file: " + input.string(), false);
    std::vector<Digest> digests;
    bool header_pending = skip_header;
    std::string line;
    while (std::getline(in_file, line)) {
        ++lines_seen;
        auto trimmed = trim_field(line);
        if (trimmed.empty() || trimmed[0] == '#') { ++lines_skipped; continue; }
        if (header_pending) { header_pending = false; ++lines_skipped; continue; }
        digests.push_back(record_digest(domain, compose_record(trimmed, separator, columns)));
    }
    return digests;
}

}  // namespace

RecordCount count_records(const fs::path& input, char separator, const std::vector<int>& columns,
                          bool skip_header, const std::string& domain) {
    RecordCount c;
    std::vector<Digest> digests = read_digests(input, separator, columns, skip_header, domain,
                                               c.lines_seen, c.lines_skipped);
    c.records_read = digests.size();
    dedupe(digests);
    c.distinct_records = digests.size();
    return c;
}

EncodeResult encode_signature_table(const EncodeRequest& given) {
    EncodeResult r;
    EncodeRequest in = given;
    const auto& spec = in.spec;

    // A size class fixes every sizing choice, so both companies build the same tables from one name.
    const SizeClass* size = nullptr;
    if (!in.size_class.empty()) {
        size = size_class(in.size_class);
        if (!size) {
            std::string known;
            for (const auto& c : size_classes()) known += (known.empty() ? "" : ", ") + std::string(c.id);
            throw EncodeError("unknown size class '" + in.size_class + "' (known: " + known + ")", true);
        }
        if (in.cells || in.tables || in.limbs || in.count_groups || in.shards > 1 || in.dynamic_tables || in.capacity) {
            throw EncodeError("a size class sets the table settings itself; do not also pass cells, tables, limbs, "
                              "count groups, shards, capacity or dynamic tables", true);
        }
        in.cells = size->cells;
        in.tables = size->tables;
        in.limbs = size->limbs;
        in.count_groups = size->count_groups;
        in.shards = size->shards;
        in.capacity = size->max_records;
    }

    // The circuit tests one 16-bit limb per slot with Fermat's theorem, so it needs an exact
    // scheme and a modulus above the limbs; the wrapper refuses anything else.
    if (spec.scheme != "BFV") {
        throw EncodeError("schema 'signature-table' requires a BFV context spec; got '" + spec.id + "' ("
                          + spec.scheme + ")", true);
    }
    if (spec.plaintext_modulus <= 65536) {
        throw EncodeError("schema 'signature-table' needs a plaintext modulus above 65536 (limbs are 16 bits); '"
                          + spec.id + "' has t = " + std::to_string(spec.plaintext_modulus), true);
    }
    if (in.role != "A" && in.role != "B") {
        throw EncodeError("--role must be A or B (it decides which sentinel fills the empty cells, "
                          "and the two parties must differ)", true);
    }
    const Role role = in.role == "A" ? Role::A : Role::B;
    // Never drop: a record that does not fit refuses the whole encode. psi/table's `drop` policy
    // stays for its own tests; no encode may use it, because a dropped record can never match and
    // the answer would come out short with nothing to show it.
    const OverflowPolicy policy = OverflowPolicy::fail;

    std::vector<Digest> digests = read_digests(in.input, in.separator, in.columns, in.skip_header, in.domain,
                                               r.lines_seen, r.lines_skipped);
    r.records_read = digests.size();
    if (digests.empty()) {
        throw EncodeError("no records found in input (read " + std::to_string(r.lines_seen) + " lines, "
                          + std::to_string(r.lines_skipped) + " skipped as blank/comment/header)", false);
    }

    // The class is a promise both companies made: more records than it allows is refused here,
    // where the count is known, before a table is built. Repeated rows count once, as they are
    // placed once.
    if (size) {
        std::vector<Digest> distinct = digests;
        dedupe(distinct);
        r.distinct_records = distinct.size();
        if (r.distinct_records > size->max_records) {
            r.status = EncodeStatus::too_many_records;
            r.reason = "This file has " + with_commas(r.distinct_records) + " records, more than this permission "
                       "allows (up to " + std::string(size->id) + "). Ask your partner for a permission with a "
                       "larger size.";
            r.verdict = Verdict::refused;
            return r;
        }
    }

    // Size the tables: the solver picks what the request did not pin.
    Request& req = r.request;
    req.records          = in.capacity > 0 ? in.capacity : static_cast<std::uint64_t>(r.records_read);
    req.signature_bits   = in.signature_bits;
    req.target_drop_rate = in.target_overflow;
    req.context.slots    = in.slot_count;
    // Built here rather than at encryption: its tower count prices the recommendations below.
    crypto::Context ctx(spec);
    req.context.towers   = static_cast<unsigned>(ctx.tower_count());
    try {
        if (in.dynamic_tables) {
            if (in.tables > 0) throw std::invalid_argument("--dynamic-tables and --tables are exclusive");
            req.per_level_only = true;
        }
        r.plan = plan_signature_table(req, in.cells, in.tables, in.limbs, in.count_groups, in.shards);
        r.solved_tables = r.plan.levels;
        if (in.dynamic_tables) {
            // Per-level only: a prealigned bundle lays its slots out by both parties' T.
            if (r.plan.cells_total < in.slot_count) {
                throw std::invalid_argument(
                    "--dynamic-tables needs at least " + std::to_string(in.slot_count) + " cells, one ciphertext's "
                    "worth, not " + std::to_string(r.plan.cells_total) + ": below that the bundle is prealigned, "
                    "and its layout depends on the other party's table count");
            }
            // Exactly the levels this data fills: more when it collides more than expected,
            // fewer when the levels above would be empty. Nothing is ever dropped.
            r.plan.levels = static_cast<unsigned>(std::max<std::uint64_t>(1, fullest_cell(digests, r.plan.cells_total)));
        }
        r.estimate = estimate(req, r.plan);
    } catch (const std::exception& e) {
        throw EncodeError(std::string("cannot size the signature tables: ") + e.what(), false);
    }
    r.shard_note = shard_granularity_note(r.plan, in.slot_count);

    // Accuracy. Tables the model says records would not fit are refused
    // before any is built; everything else is judged on what the table actually holds, below.
    AdviceOptions advice_options;
    advice_options.policy = policy;
    advice_options.dynamic_tables = in.dynamic_tables;
    {
        auto before = advise(req, r.estimate, advice_options);
        if (before.refused()) {
            std::erase_if(before.findings, [](const Finding& f) { return f.severity != Severity::refuse; });
            r.status  = EncodeStatus::refused_before_encoding;
            r.reason  = "refused before encoding: the signature tables would not be accurate enough";
            r.advice  = std::move(before);
            r.verdict = Verdict::refused;
            return r;
        }
    }

    // This data's fullest cell at any cell count, so a recommended fix is checked against the
    // records actually read, not only the model. Memoised: the advice asks for a few sizes, repeatedly.
    Observed observed;
    observed.fullest_cell_at = [&digests, memo = std::make_shared<std::map<std::uint64_t, std::uint64_t>>()](
                                   std::uint64_t cells) {
        const auto hit = memo->find(cells);
        if (hit != memo->end()) return hit->second;
        return (*memo)[cells] = fullest_cell(digests, cells);
    };

    // One table per shard. The buckets are computed once - filtering the whole dataset P
    // times would be O(P*n) - and every report is summed, because the accuracy promises are about
    // the dataset, not about whichever shard a record happened to land in.
    const std::uint64_t shard_count = r.plan.shards;
    r.shard_count = shard_count;
    std::vector<Table> tables;
    PlacementReport& totals = r.totals;
    try {
        const auto buckets = partition_by_shard(digests, shard_count);
        tables.reserve(static_cast<std::size_t>(shard_count));
        for (std::uint64_t p = 0; p < shard_count; ++p) {
            tables.push_back(build_table(buckets[p], r.plan.table_params(p), role, policy));
            const auto& rep = tables.back().report();
            totals.rows += rep.rows;
            totals.duplicates += rep.duplicates;
            totals.records += rep.records;
            totals.placed += rep.placed;
            totals.dropped += rep.dropped;
            totals.overflowed_cells += rep.overflowed_cells;
            totals.remapped += rep.remapped;
            totals.cell_max_load = std::max(totals.cell_max_load, rep.cell_max_load);
        }
    } catch (const TableOverflow& e) {
        observed.records = e.report().records;
        observed.dropped = e.report().dropped;
        advice_options.observed = &observed;
        r.status  = EncodeStatus::table_overflow;
        r.reason  = e.what();
        r.advice  = advise(req, r.estimate, advice_options);
        r.verdict = Verdict::refused;
        return r;
    } catch (const std::exception& e) {
        throw EncodeError(std::string("cannot build the signature tables: ") + e.what(), false);
    }
    // Under the fail policy build_table has already refused any record that did not fit, in every
    // shard, so nothing reaching here was left out.
    observed.records = totals.records;
    observed.dropped = totals.dropped;
    advice_options.observed = &observed;
    r.advice  = advise(req, r.estimate, advice_options);
    // A degraded answer is never accepted: at the fixed dataset sizes no accuracy warning can fire,
    // so anything the advice does not pass outright is refused, and nothing degraded is ever
    // encrypted.
    r.verdict = r.advice.verdict(false);
    if (r.verdict != Verdict::ok) {
        // Nothing encrypted or written: the table is cheap, the encryption is not.
        r.status = EncodeStatus::refused;
        r.reason = "This file could not be encrypted for this dataset size. Ask your partner for a "
                   "permission with a larger size.";
        return r;
    }

    try {
        r.layout = bundle_layout(r.plan.table_params(0), r.plan.count_groups, in.slot_count);
    } catch (const std::exception& e) {
        throw EncodeError(e.what(), false);
    }
    const BundleLayout& layout = r.layout;

    // Encode + encrypt under a context built from the spec: a freshly built context embeds itself
    // into the ciphertext, which is what the wrapper needs.
    auto pk = crypto::PublicKey::deserialize(ctx, read_file(in.joint_public_key));

    // One file per shard. Unsharded runs write exactly the path they were given; a sharded run
    // writes <output>.shard-NNNNN beside it plus <output>.manifest.json, so `ls <output>*` shows the
    // whole dataset and nothing is hidden inside a surprise directory.
    const fs::path& out_path = in.output;
    if (out_path.has_parent_path()) fs::create_directories(out_path.parent_path());
    const auto shard_path = [&](std::uint64_t p) {
        if (shard_count == 1) return out_path;
        std::ostringstream name;
        name << out_path.filename().string() << ".shard-" << std::setw(5) << std::setfill('0') << p;
        return out_path.parent_path() / name.str();
    };

    json shard_manifest = json::array();  // uploaded: no record counts
    std::vector<std::int64_t> slots(static_cast<std::size_t>(layout.slots));
    for (std::uint64_t p = 0; p < shard_count; ++p) {
        BundleLayout shard_layout = layout;
        shard_layout.shard = p;
        std::vector<crypto::Ciphertext> cts;
        cts.reserve(shard_layout.ciphertexts);
        for (std::uint64_t i = 0; i < shard_layout.ciphertexts; ++i) {
            bundle_slots(tables[p], shard_layout, i, std::span<std::int64_t>(slots));
            cts.push_back(ctx.encrypt(pk, ctx.encode_packed(slots)));
        }
        const auto payload = ctx.serialize_ciphertext_vector(cts);
        const std::string header = bundle_header(shard_layout, role);
        const fs::path path = shard_path(p);
        {
            std::ofstream out(path, std::ios::binary | std::ios::trunc);
            if (!out) throw EncodeError("cannot open for writing: " + path.string(), false);
            out.write(header.data(), static_cast<std::streamsize>(header.size()));
            out.write(reinterpret_cast<const char*>(payload.data()), static_cast<std::streamsize>(payload.size()));
            if (!out) throw EncodeError("write failed: " + path.string(), false);
        }
        r.files.push_back(path);
        const std::uint64_t shard_bytes = header.size() + payload.size();
        r.bytes += shard_bytes;
        if (shard_count > 1) {
            // Hashed from the bytes just written rather than by re-reading the file: at 10^7 records
            // the manifest would otherwise double the I/O of the whole encode.
            std::string whole = header;
            whole.append(reinterpret_cast<const char*>(payload.data()), payload.size());
            const auto digest = sha256(whole);
            std::ostringstream hex;
            for (const auto byte : digest) hex << std::hex << std::setw(2) << std::setfill('0')
                                               << static_cast<unsigned>(byte);
            const auto& rep = tables[p].report();
            json row = {
                { "shard", p },
                { "file", path.filename().string() },
                { "bytes", shard_bytes },
                { "ciphertexts", shard_layout.ciphertexts },
                { "sha256", hex.str() },
            };
            // The uploaded manifest carries no counts: per-shard counts would show how the records
            // spread across the key space. The local one keeps them for this party's own use.
            shard_manifest.push_back(row);
            row["records"]        = rep.records;
            row["cellMaxLoad"]    = rep.cell_max_load;
            r.shard_files_local.push_back(row);
        }
        // Freed before the next shard is encrypted: at 10^7 records holding every shard's
        // ciphertexts at once is the difference between fitting in memory and not.
        cts.clear();
        cts.shrink_to_fit();
    }

    // What the platform is told about this encoding, and all it is told (zero trust): whether this
    // side's records fit one count group, and the shape. Every channel (connector, scripts, app)
    // forwards this object as-is, so none of them can add a count.
    r.most_records_per_group = max_records_per_group(tables, layout.groups);
    r.count_fits_groups = r.most_records_per_group <= count_ceiling;
    r.platform_report = {
        { "countFitsGroups", r.count_fits_groups },
        { "cells", r.plan.cells_total },
        { "tables", layout.tables },
        { "limbs", layout.limbs },
        { "countGroups", layout.groups },
        { "ciphertexts", layout.ciphertexts * shard_count },
    };

    const auto write_json = [](const fs::path& path, const json& doc) {
        std::ofstream f(path, std::ios::trunc);
        if (!f) throw EncodeError("cannot write " + path.string(), false);
        f << doc.dump(2) << "\n";
        if (!f) throw EncodeError("write failed: " + path.string(), false);
    };
    r.platform_report_path = out_path.parent_path() / (out_path.filename().string() + ".platform-report.json");
    write_json(r.platform_report_path, r.platform_report);

    if (shard_count > 1) {
        // The shard manifest. It is what ties P files into one dataset: the
        // parameters both parties must agree on and every shard's identity and checksum. It is
        // UPLOADED, so it carries no record counts (v2): the overflow check as a yes/no, exactly as
        // platform_report. A copy with the counts is written beside it for this party only
        // (<output>.manifest.local.json) and is never sent anywhere.
        json manifest;
        manifest["schema"]          = "psi-shard-manifest v2";
        manifest["role"]            = in.role;
        manifest["contextSpec"]     = spec.id;
        manifest["domainSeparator"] = in.domain;
        manifest["slotCount"]       = in.slot_count;
        manifest["cellsTotal"]      = r.plan.cells_total;
        manifest["cellsPerShard"]   = r.plan.cells_per_shard();
        manifest["shards"]          = shard_count;
        manifest["tables"]          = layout.tables;
        manifest["limbs"]           = layout.limbs;
        manifest["countGroups"]     = layout.groups;
        manifest["layout"]          = layout.layout_name();
        manifest["countFitsGroups"] = r.count_fits_groups;
        manifest["bytes"]           = r.bytes;
        if (!in.function_slug.empty()) {
            manifest["functionSlug"]    = in.function_slug;
            manifest["functionVersion"] = in.function_version;
            manifest["inputName"]       = in.input_name;
        }

        json local = manifest;
        local["records"]         = totals.records;
        local["mostRecordsPerCountGroup"] = r.most_records_per_group;
        local["shardFiles"]      = r.shard_files_local;
        local["note"]            = "Local only: this file holds record counts and is never uploaded.";
        manifest["shardFiles"]   = shard_manifest;

        r.manifest_path       = out_path.parent_path() / (out_path.filename().string() + ".manifest.json");
        r.local_manifest_path = out_path.parent_path() / (out_path.filename().string() + ".manifest.local.json");
        write_json(r.manifest_path, manifest);
        write_json(r.local_manifest_path, local);
    }
    return r;
}

}  // namespace fhe_toolkit::psi
