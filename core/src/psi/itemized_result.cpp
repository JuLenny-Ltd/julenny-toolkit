#include "psi/itemized_result.h"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <map>
#include <sstream>

#include <nlohmann/json.hpp>

#include "crypto/ciphertext.h"
#include "psi/digest.h"
#include "psi/reference.h"
#include "psi/size_class.h"
#include "psi/table.h"

namespace fhe_toolkit::psi {

using nlohmann::json;

namespace {

constexpr std::string_view kPayload = "PAYLOAD\n";

std::string first_line(std::span<const std::byte> bytes) {
    std::string line;
    for (std::size_t i = 0; i < bytes.size() && i < 64; ++i) {
        const char c = static_cast<char>(bytes[i]);
        if (c == '\n') break;
        line.push_back(c);
    }
    return line;
}

/** The header's lines after the marker, and where the payload starts. */
struct Split {
    std::vector<std::string> lines;
    std::size_t payload_offset = 0;
};

Split split_bundle(std::span<const std::byte> bytes, std::string_view marker) {
    const std::string head = first_line(bytes);
    if (head != marker) {
        throw ItemizedError("expected a " + std::string(marker) + " file, found one starting '" + head + "'");
    }
    // The header is short text; the payload is binary and may contain anything, so the search
    // stops at the first PAYLOAD line, which the header always ends with.
    const std::size_t limit = std::min<std::size_t>(bytes.size(), 4096);
    std::string text(reinterpret_cast<const char*>(bytes.data()), limit);
    const std::size_t at = text.find(std::string("\n") + std::string(kPayload));
    if (at == std::string::npos) throw ItemizedError(std::string(marker) + " file has no PAYLOAD line");
    Split out;
    out.payload_offset = at + 1 + kPayload.size();
    std::istringstream in(text.substr(marker.size() + 1, at - marker.size() - 1));
    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty()) out.lines.push_back(line);
    }
    return out;
}

ItemizedHeader parse_header(const std::vector<std::string>& lines) {
    std::map<std::string, std::string> kv;
    for (const auto& l : lines) {
        const auto sp = l.find(' ');
        if (sp == std::string::npos) throw ItemizedError("malformed result header line '" + l + "'");
        kv[l.substr(0, sp)] = l.substr(l.find_first_not_of(' ', sp));
    }
    const auto num = [&](const char* key, bool required, std::uint64_t fallback) -> std::uint64_t {
        const auto it = kv.find(key);
        if (it == kv.end()) {
            if (required) throw ItemizedError(std::string("result header has no ") + key + " line");
            return fallback;
        }
        try { return std::stoull(it->second); }
        catch (...) { throw ItemizedError(std::string("result header ") + key + " is not a number"); }
    };
    ItemizedHeader h;
    const auto viewer = kv.count("VIEWER") ? kv["VIEWER"] : std::string();
    if (viewer != "A" && viewer != "B") throw ItemizedError("result header VIEWER must be A or B");
    h.viewer = viewer[0];
    h.cells = num("CELLS", true, 0);
    h.tables = static_cast<unsigned>(num("TABLES", true, 0));
    h.masks = static_cast<unsigned>(num("MASKS", true, 0));
    h.slots = num("SLOTS", true, 0);
    const auto layout = kv.count("LAYOUT") ? kv["LAYOUT"] : std::string();
    if (layout != "per-level" && layout != "prealigned") throw ItemizedError("result header LAYOUT is unknown");
    h.per_level = layout == "per-level";
    h.ciphertexts = num("CIPHERTEXTS", true, 0);
    h.shards = num("SHARDS", false, 1);
    h.shard = num("SHARD", false, 0);
    if (h.shards != 1) {
        throw ItemizedError("this result is sharded; reading sharded results is not supported yet");
    }
    const std::uint64_t blocks = h.per_level ? h.cells / h.slots : 1;
    if (h.cells == 0 || h.slots == 0 || h.tables == 0 || h.masks != (h.tables + 15) / 16
        || h.ciphertexts != h.masks * blocks || (h.per_level && h.cells % h.slots != 0)) {
        throw ItemizedError("result header is inconsistent (cells, tables, masks, slots, layout, ciphertexts)");
    }
    return h;
}

std::string join_lines(const std::vector<std::string>& lines) {
    std::string out;
    for (const auto& l : lines) out += l + "\n";
    return out;
}

}  // namespace

ItemizedKind itemized_kind(std::span<const std::byte> bytes) {
    const std::string head = first_line(bytes);
    if (head == kItemizedResultMarker) return ItemizedKind::result;
    if (head == kItemizedPartialMarker) return ItemizedKind::partial;
    if (head == kItemizedShardedMarker) return ItemizedKind::sharded;
    return ItemizedKind::none;
}

std::vector<std::byte> partial_decrypt_itemized(const crypto::Context& ctx, const crypto::SecretKey& sk,
                                                std::span<const std::byte> result, bool lead) {
    if (itemized_kind(result) == ItemizedKind::sharded) {
        throw ItemizedError("this result is sharded; reading sharded results is not supported yet");
    }
    const Split split = split_bundle(result, kItemizedResultMarker);
    const ItemizedHeader h = parse_header(split.lines);
    const auto cts = ctx.deserialize_ciphertext_vector(result.subspan(split.payload_offset));
    if (cts.size() != h.ciphertexts) {
        throw ItemizedError("the result declares " + std::to_string(h.ciphertexts) + " ciphertexts but carries "
                            + std::to_string(cts.size()));
    }
    std::vector<crypto::Ciphertext> partials;
    partials.reserve(cts.size());
    for (const auto& ct : cts) partials.push_back(lead ? ctx.partial_decrypt_lead(sk, ct) : ctx.partial_decrypt_main(sk, ct));
    const auto payload = ctx.serialize_ciphertext_vector(partials);

    const std::string header = std::string(kItemizedPartialMarker) + "\n" + join_lines(split.lines)
                             + "PARTIAL " + (lead ? "lead" : "main") + "\n" + std::string(kPayload);
    std::vector<std::byte> out(header.size() + payload.size());
    std::memcpy(out.data(), header.data(), header.size());
    if (!payload.empty()) std::memcpy(out.data() + header.size(), payload.data(), payload.size());
    return out;
}

ItemizedMasks combine_itemized(const crypto::Context& ctx, std::uint64_t t,
                               const std::vector<std::vector<std::byte>>& partials) {
    if (partials.size() < 2) throw ItemizedError("combining needs every party's partial file (at least two)");

    std::vector<std::string> body;
    bool have_lead = false, have_main = false;
    std::vector<std::vector<crypto::Ciphertext>> per_party;
    for (const auto& bytes : partials) {
        const Split split = split_bundle(bytes, kItemizedPartialMarker);
        std::vector<std::string> lines;
        std::string role;
        for (const auto& l : split.lines) {
            if (l.rfind("PARTIAL ", 0) == 0) role = l.substr(8);
            else lines.push_back(l);
        }
        if (role == "lead") have_lead = true;
        else if (role == "main") have_main = true;
        else throw ItemizedError("a partial file has no PARTIAL lead|main line");
        if (body.empty()) body = lines;
        else if (lines != body) throw ItemizedError("the partial files come from different results");
        per_party.push_back(ctx.deserialize_ciphertext_vector(std::span<const std::byte>(bytes).subspan(split.payload_offset)));
    }
    if (!have_lead || !have_main) throw ItemizedError("combining needs the lead's and the other party's partials");

    ItemizedMasks out;
    out.header = parse_header(body);
    const ItemizedHeader& h = out.header;
    for (const auto& p : per_party) {
        if (p.size() != h.ciphertexts) throw ItemizedError("a partial file carries the wrong number of ciphertexts");
    }

    const std::uint64_t blocks = h.per_level ? h.cells / h.slots : 1;
    out.masks.assign(h.masks, std::vector<std::uint32_t>(h.cells, 0));
    for (std::uint64_t i = 0; i < h.ciphertexts; ++i) {
        std::vector<const crypto::Ciphertext*> parts;
        for (const auto& p : per_party) parts.push_back(&p[i]);
        const auto decoded = ctx.combine_partials(parts).values();
        if (decoded.size() < h.slots) throw ItemizedError("a decrypted mask has fewer slots than the header says");

        // Rule 1: OpenFHE reports residues above (t-1)/2 as negative; a mask with level 15 set is one.
        std::vector<std::uint64_t> v(h.slots);
        for (std::uint64_t s = 0; s < h.slots; ++s) {
            const std::int64_t x = decoded[s];
            v[s] = static_cast<std::uint64_t>(x < 0 ? x + static_cast<std::int64_t>(t) : x);
            // Rule 2: a mask is 16 bits. Anything larger is a broken circuit, not a match.
            if (v[s] > 0xFFFF) throw ItemizedError("a decrypted mask exceeds 16 bits: the result is not well formed");
        }

        const std::uint64_t q = i / blocks;
        const std::uint64_t block = i % blocks;
        if (h.per_level) {
            for (std::uint64_t s = 0; s < h.slots; ++s) out.masks[q][block * h.slots + s] = static_cast<std::uint32_t>(v[s]);
        } else {
            // Rule 4: prealigned slots repeat the m cells; the repeats must agree (a free self-check).
            for (std::uint64_t s = 0; s < h.slots; ++s) {
                if (v[s] != v[s % h.cells]) throw ItemizedError("a prealigned mask does not repeat consistently");
            }
            for (std::uint64_t c = 0; c < h.cells; ++c) out.masks[q][c] = static_cast<std::uint32_t>(v[c]);
        }
    }
    return out;
}

std::string itemized_masks_json(const ItemizedMasks& m) {
    json j;
    j["schema"] = "psi-itemized-masks v1";
    j["viewer"] = std::string(1, m.header.viewer);
    j["cells"] = m.header.cells;
    j["tables"] = m.header.tables;
    j["slots"] = m.header.slots;
    j["layout"] = m.header.per_level ? "per-level" : "prealigned";
    j["masks"] = m.masks;
    return j.dump();
}

ItemizedMasks itemized_masks_from_json(const std::string& text) {
    json j;
    try { j = json::parse(text); } catch (const std::exception& e) { throw ItemizedError(std::string("masks file is not JSON: ") + e.what()); }
    if (j.value("schema", std::string()) != "psi-itemized-masks v1") {
        throw ItemizedError("not a psi-itemized-masks v1 file (it should be what combining wrote)");
    }
    ItemizedMasks m;
    const auto viewer = j.value("viewer", std::string());
    if (viewer != "A" && viewer != "B") throw ItemizedError("masks file VIEWER must be A or B");
    m.header.viewer = viewer[0];
    m.header.cells = j.at("cells").get<std::uint64_t>();
    m.header.tables = j.at("tables").get<unsigned>();
    m.header.slots = j.at("slots").get<std::uint64_t>();
    m.header.per_level = j.value("layout", std::string()) == "per-level";
    m.masks = j.at("masks").get<std::vector<std::vector<std::uint32_t>>>();
    m.header.masks = static_cast<unsigned>(m.masks.size());
    return m;
}

ItemizedRows resolve_itemized_rows(const EncodeRequest& given, const ItemizedMasks& m) {
    EncodeRequest req = given;
    if (!req.size_class.empty()) {
        const SizeClass* size = size_class(req.size_class);
        if (!size) throw ItemizedError("unknown size class '" + req.size_class + "'");
        req.cells = size->cells;
        req.tables = size->tables;
        req.limbs = size->limbs;
        req.count_groups = size->count_groups;
        req.shards = size->shards;
    }
    if (req.role != "A" && req.role != "B") throw ItemizedError("the viewer's role must be A or B");
    if (req.role[0] != m.header.viewer) {
        throw ItemizedError("this result is laid out for role " + std::string(1, m.header.viewer)
                            + ", not this input's role " + req.role + ": it is the other party's to read");
    }
    if (req.cells == 0 || req.tables == 0 || req.limbs == 0) {
        throw ItemizedError("the table settings (or the size class) used to encrypt are needed to read the result");
    }

    // Read the rows exactly as the encoder did, keeping each row's original text.
    std::ifstream in(req.input);
    if (!in) throw ItemizedError("cannot open " + req.input.string());
    ItemizedRows out;
    std::vector<std::pair<Digest, std::string>> rows;
    std::vector<Digest> digests;
    bool header_pending = req.skip_header;
    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        const auto trimmed = trim_field(line);
        if (trimmed.empty() || trimmed[0] == '#') continue;
        if (header_pending) { header_pending = false; out.header_line = line; continue; }
        const Digest d = record_digest(req.domain, compose_record(trimmed, req.separator, req.columns));
        rows.emplace_back(d, line);
        digests.push_back(d);
    }

    Plan plan;
    plan.cells_total = req.cells;
    plan.shards = req.shards == 0 ? 1 : req.shards;
    plan.levels = req.tables;
    plan.limbs = req.limbs;
    plan.count_groups = req.count_groups == 0 ? 1 : req.count_groups;
    if (plan.shards != 1) throw ItemizedError("reading sharded results is not supported yet");
    if (plan.cells_per_shard() != m.header.cells || plan.levels != m.header.tables) {
        throw ItemizedError("this CSV's table (" + std::to_string(plan.cells_per_shard()) + " cells x "
                            + std::to_string(plan.levels) + " tables) does not match the result's ("
                            + std::to_string(m.header.cells) + " x " + std::to_string(m.header.tables)
                            + "): use the dataset size and settings it was encrypted with");
    }

    Table table = [&] {
        try {
            return build_table(digests, plan.table_params(0), req.role == "A" ? Role::A : Role::B, OverflowPolicy::fail);
        } catch (const TableOverflow&) {
            throw ItemizedError("this CSV no longer fits the table it was encrypted into: it is not the file that "
                                "was encrypted for this result");
        }
    }();

    const std::vector<Digest> matched = resolve_matches(table, m.masks);
    out.matched_records = matched.size();
    for (const auto& [d, text] : rows) {
        if (std::binary_search(matched.begin(), matched.end(), d)) out.rows.push_back(text);
    }
    return out;
}

}  // namespace fhe_toolkit::psi
