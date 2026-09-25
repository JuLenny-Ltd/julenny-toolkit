#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <algorithm>
#include <bit>
#include <cmath>
#include <cstdint>
#include <iterator>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

#include "psi/digest.h"

using namespace fhe_toolkit::psi;

namespace {

constexpr std::string_view kDomain = "julenny/joint-record-overlap/exact/v1";
constexpr unsigned kProductionLimbs = 8;  // 128-bit default signature (design §2.4)

std::string record_text(std::uint64_t i) {
    return "record-" + std::to_string(i);
}

std::string to_hex(const Digest& d) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(2 * d.size());
    for (auto byte : d) {
        out.push_back(digits[byte >> 4]);
        out.push_back(digits[byte & 0x0F]);
    }
    return out;
}

using SignatureFn = std::vector<std::uint16_t> (*)(const Digest&, unsigned);

// The natural wrong implementation, and the bug design review caught: the
// signature cut from the front of the digest, so its low bits ARE the position
// bits. Kept here so the tests below can prove they reject it, rather than
// merely passing on the right layout.
std::vector<std::uint16_t> overlapping_signature(const Digest& d, unsigned limbs) {
    std::vector<std::uint16_t> out(limbs);
    for (unsigned j = 0; j < limbs; ++j) {
        out[j] = static_cast<std::uint16_t>(d[2 * j] | (d[2 * j + 1] << 8));
    }
    return out;
}

struct OverlapStats {
    std::uint64_t       pairs         = 0;
    double              mean_distance = 0.0;  // Hamming distance over the stored bits
    double              distance_z    = 0.0;
    std::vector<double> agree_rate;           // per stored bit: fraction of pairs that agree
    double              max_bit_z     = 0.0;
};

// Hash `records` distinct records into 2^b cells and, over every pair that
// lands in the same cell, measure how much their stored signatures agree.
OverlapStats measure_same_cell_pairs(unsigned b, std::size_t records, unsigned limbs,
                                     SignatureFn signature_of) {
    const std::uint64_t cells = std::uint64_t{1} << b;
    struct Row {
        std::uint32_t              pos;
        std::vector<std::uint16_t> sig;
    };
    std::vector<Row> rows;
    rows.reserve(records);
    for (std::size_t i = 0; i < records; ++i) {
        const auto d = record_digest(kDomain, record_text(i));
        rows.push_back({ position(d, cells), signature_of(d, limbs) });
    }
    std::sort(rows.begin(), rows.end(),
              [](const Row& x, const Row& y) { return x.pos < y.pos; });

    const unsigned stored_bits = limbs * limb_bits;
    std::vector<std::uint64_t> agree(stored_bits, 0);
    std::uint64_t pairs = 0;
    std::uint64_t distance_sum = 0;
    for (std::size_t lo = 0; lo < rows.size();) {
        std::size_t hi = lo;
        while (hi < rows.size() && rows[hi].pos == rows[lo].pos) ++hi;
        for (std::size_t x = lo; x < hi; ++x) {
            for (std::size_t y = x + 1; y < hi; ++y) {
                ++pairs;
                for (unsigned l = 0; l < limbs; ++l) {
                    const unsigned diff = static_cast<unsigned>(rows[x].sig[l] ^ rows[y].sig[l]);
                    distance_sum += static_cast<std::uint64_t>(std::popcount(diff));
                    for (unsigned bit = 0; bit < limb_bits; ++bit) {
                        if (((diff >> bit) & 1u) == 0) ++agree[l * limb_bits + bit];
                    }
                }
            }
        }
        lo = hi;
    }

    // Under independence each stored bit agrees with probability 1/2, and the
    // distance of a pair is Binomial(stored_bits, 1/2). Pairs that share a record
    // are still pairwise independent for uniform bits (I[x=y] and I[x=z] are
    // independent given nothing), so the plain binomial standard errors apply.
    OverlapStats s;
    s.pairs = pairs;
    const auto p = static_cast<double>(pairs);
    s.mean_distance = static_cast<double>(distance_sum) / p;
    s.distance_z = (s.mean_distance - stored_bits / 2.0) / (std::sqrt(stored_bits / 4.0) / std::sqrt(p));
    for (auto a : agree) {
        const double rate = static_cast<double>(a) / p;
        s.agree_rate.push_back(rate);
        s.max_bit_z = std::max(s.max_bit_z, std::abs(rate - 0.5) / (0.5 / std::sqrt(p)));
    }
    return s;
}

// 10 sigma on a fixed, deterministic sample. The real layout clears it with room
// to spare; an overlapping layout misses it by hundreds of sigma.
bool looks_independent(const OverlapStats& s) {
    return std::abs(s.distance_z) < 10.0 && s.max_bit_z < 10.0;
}

}  // namespace

// ---------------------------------------------------------------------------
// Known answers
// ---------------------------------------------------------------------------

TEST_CASE("SHA-256 matches the FIPS 180-2 vectors", "[psi][digest]") {
    CHECK(to_hex(sha256("")) ==
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    CHECK(to_hex(sha256("abc")) ==
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    CHECK(to_hex(sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")) ==
          "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    CHECK(to_hex(sha256(std::string(1'000'000, 'a'))) ==
          "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

// Every expected value below was computed by Python's hashlib, not by this code:
//
//   import hashlib
//   d = hashlib.sha256(b"julenny/joint-record-overlap/exact/v1\x00"
//                      b"alice@example.com\x1fAlice Smith").digest()
//   d.hex(); int.from_bytes(d[0:4], "little")
//   [int.from_bytes(d[4+2*j:6+2*j], "little") for j in range(14)]
//
// So this pins the wire contract (preimage layout, byte ranges, endianness) that
// a second implementation, e.g. the Windows app, has to reproduce.
TEST_CASE("record digest and its split match vectors computed outside this codebase",
          "[psi][digest]") {
    // Two joined columns, as compose_record produces them (ASCII unit separator).
    // The literal is split so "\x1F" cannot swallow the 'A' as another hex digit.
    const auto d = record_digest(kDomain, "alice@example.com\x1F" "Alice Smith");

    CHECK(to_hex(d) == "f4d204b66244bd6a29acb6e2b5b55ccd6f65c01fec8156add03724d55705336a");
    CHECK(address(d) == 0xb604d2f4u);
    CHECK(position(d, 1) == 0u);
    CHECK(position(d, std::uint64_t{1} << 16) == 54004u);
    CHECK(position(d, max_cells) == 3053769460u);
    CHECK(signature(d, max_limbs) ==
          std::vector<std::uint16_t>{ 17506, 27325, 44073, 58038, 46517, 52572, 25967,
                                      8128, 33260, 44374, 14288, 54564, 1367, 27187 });
    CHECK(signature(d, kProductionLimbs) ==
          std::vector<std::uint16_t>{ 17506, 27325, 44073, 58038, 46517, 52572, 25967, 8128 });
}

TEST_CASE("the domain separator is unambiguous", "[psi][digest]") {
    // Naive concatenation would make these equal ("abc" both ways).
    // hashlib.sha256(b"ab\x00c") and hashlib.sha256(b"a\x00bc"):
    CHECK(to_hex(record_digest("ab", "c")) ==
          "6c032e631d39a14d85aff7e319546af701e26c97b57ca95fbfe9c6ba855f67bf");
    CHECK(to_hex(record_digest("a", "bc")) ==
          "40bb547d936bbd31318ee37ac8799e7ecbb22eda2651f65e3214bffb8ce97bb4");

    CHECK(record_digest("domain-one", "x") != record_digest("domain-two", "x"));

    // A record may contain NUL; it is hashed in full, not cut at the NUL.
    const std::string with_nul{ "a\0b", 3 };
    CHECK(record_digest(kDomain, with_nul) != record_digest(kDomain, "a"));

    CHECK_THROWS_AS(record_digest("", "x"), std::invalid_argument);
    CHECK_THROWS_AS(record_digest(std::string_view{ "do\0main", 7 }, "x"),
                    std::invalid_argument);
}

// ---------------------------------------------------------------------------
// Position and signature are disjoint
// ---------------------------------------------------------------------------

// The structural half of "provably independent": flip each of the 256 digest
// bits one at a time and check that it moves exactly one of the two outputs, by
// exactly the documented amount. Bits 0..31 move only the address; bits 32..255
// move only one bit of one limb. No bit feeds both.
TEST_CASE("address and signature read disjoint digest bits, in the documented order",
          "[psi][digest]") {
    const Digest base = record_digest(kDomain, "layout probe");
    const auto base_sig = signature(base, max_limbs);

    for (unsigned bit = 0; bit < 8 * digest_bytes; ++bit) {
        Digest d = base;
        d[bit / 8] ^= static_cast<std::uint8_t>(1u << (bit % 8));
        const auto sig = signature(d, max_limbs);
        CAPTURE(bit);
        if (bit < 8 * address_bytes) {
            REQUIRE((address(d) ^ address(base)) == (std::uint32_t{1} << bit));
            REQUIRE(sig == base_sig);
        } else {
            REQUIRE(address(d) == address(base));
            const unsigned s = bit - 8 * address_bytes;
            for (unsigned j = 0; j < max_limbs; ++j) {
                const unsigned expected = (j == s / limb_bits) ? (1u << (s % limb_bits)) : 0u;
                REQUIRE(static_cast<unsigned>(sig[j] ^ base_sig[j]) == expected);
            }
        }
    }
}

// The statistical half, and the regression test for the bug design review
// caught. Among records that share a cell, the stored signature bits must
// still behave like fresh coin flips. The overlapping layout fails this in
// exactly the way design §2.1 predicts: the b position bits always agree, so
// the signature delivers S - b bits of discrimination while claiming S.
TEST_CASE("records that share a cell get independent signatures", "[psi][digest]") {
    const unsigned b = GENERATE(8u, 16u, 20u);
    // Sized so every b sees ~2^17 same-cell pairs: pairs ~ n^2 / 2m.
    const std::size_t records = std::size_t{1} << ((b + 18) / 2);
    const unsigned stored_bits = kProductionLimbs * limb_bits;
    CAPTURE(b, records);

    SECTION("real layout: every stored bit is a fresh coin flip") {
        const auto s = measure_same_cell_pairs(b, records, kProductionLimbs, &signature);
        CAPTURE(s.pairs, s.mean_distance, s.distance_z, s.max_bit_z);
        REQUIRE(s.pairs >= 100'000);
        REQUIRE(looks_independent(s));
    }

    SECTION("overlapping layout (the bug) is rejected, for the predicted reason") {
        const auto s = measure_same_cell_pairs(b, records, kProductionLimbs,
                                               &overlapping_signature);
        CAPTURE(s.pairs, s.mean_distance, s.distance_z, s.max_bit_z);
        REQUIRE_FALSE(looks_independent(s));

        // Exactly the b position bits are wasted, and they are the first b.
        std::vector<unsigned> always_agree;
        for (unsigned i = 0; i < stored_bits; ++i) {
            if (s.agree_rate[i] == 1.0) always_agree.push_back(i);
        }
        REQUIRE(always_agree.size() == b);
        REQUIRE(always_agree.back() == b - 1);

        // ...so the comparison is really over S - b bits: distance ~ (S - b) / 2.
        const double tol = 10.0 * std::sqrt((stored_bits - b) / 4.0)
                         / std::sqrt(static_cast<double>(s.pairs));
        REQUIRE(std::abs(s.mean_distance - (stored_bits - b) / 2.0) < tol);
    }
}

// The most extreme same-cell case there is: brute-force a counter until two
// distinct records share the ENTIRE 32-bit address, i.e. they would sit in the
// same cell of a table of any size up to 2^32.
TEST_CASE("two records sharing all 32 address bits still get unrelated signatures",
          "[psi][digest]") {
    // Birthday bound: expect ~1.18 * 2^16 records before the first address repeat.
    std::unordered_map<std::uint32_t, std::uint64_t> seen;
    std::uint64_t first = 0;
    std::uint64_t second = 0;
    bool found = false;
    for (std::uint64_t i = 0; i < (std::uint64_t{1} << 20) && !found; ++i) {
        const auto [it, inserted] = seen.emplace(address(record_digest(kDomain, record_text(i))), i);
        if (!inserted) {
            first = it->second;
            second = i;
            found = true;
        }
    }
    REQUIRE(found);
    const auto da = record_digest(kDomain, record_text(first));
    const auto db = record_digest(kDomain, record_text(second));
    CAPTURE(first, second, to_hex(da), to_hex(db));
    REQUIRE(da != db);
    REQUIRE(position(da, max_cells) == position(db, max_cells));

    auto compare = [&](SignatureFn signature_of, unsigned& equal_limbs, unsigned& distance) {
        const auto sa = signature_of(da, kProductionLimbs);
        const auto sb = signature_of(db, kProductionLimbs);
        equal_limbs = 0;
        distance = 0;
        for (unsigned j = 0; j < kProductionLimbs; ++j) {
            if (sa[j] == sb[j]) ++equal_limbs;
            distance += static_cast<unsigned>(std::popcount(static_cast<unsigned>(sa[j] ^ sb[j])));
        }
    };
    unsigned equal_limbs = 0;
    unsigned distance = 0;

    SECTION("real layout") {
        compare(&signature, equal_limbs, distance);
        CAPTURE(equal_limbs, distance);
        // Independence: 8 * 2^-16 expected equal limbs, distance Binomial(128, 1/2),
        // i.e. 64 +- 5.66. The band is 6 sigma.
        REQUIRE(equal_limbs == 0);
        REQUIRE(distance >= 30);
        REQUIRE(distance <= 98);
    }

    SECTION("overlapping layout stores the shared address again, as limbs 0 and 1") {
        compare(&overlapping_signature, equal_limbs, distance);
        CAPTURE(equal_limbs, distance);
        REQUIRE(equal_limbs == 2);
    }
}

// ---------------------------------------------------------------------------
// Dedupe (Q8)
// ---------------------------------------------------------------------------

TEST_CASE("dedupe collapses repeated rows, keyed on the full digest", "[psi][digest]") {
    SECTION("repeated rows collapse to one record each") {
        std::vector<Digest> v;
        for (const char* r : { "alice", "bob", "alice", "carol", "bob", "alice" }) {
            v.push_back(record_digest(kDomain, r));
        }
        REQUIRE(dedupe(v) == 3);
        REQUIRE(v.size() == 3);
        REQUIRE(std::is_sorted(v.begin(), v.end()));
        REQUIRE(std::adjacent_find(v.begin(), v.end()) == v.end());
    }

    SECTION("two digests identical once truncated are NOT merged") {
        // y differs from x only in the last byte, beyond the 8 production limbs:
        // same cell, same stored signature, different record.
        const Digest x = record_digest(kDomain, "x");
        Digest y = x;
        y[digest_bytes - 1] ^= 0x01;
        REQUIRE(position(x, max_cells) == position(y, max_cells));
        REQUIRE(signature(x, kProductionLimbs) == signature(y, kProductionLimbs));

        std::vector<Digest> v{ x, y, x };
        REQUIRE(dedupe(v) == 1);
        REQUIRE(v.size() == 2);
    }

    SECTION("the result does not depend on input row order") {
        std::vector<Digest> v;
        for (std::uint64_t i = 0; i < 2000; ++i) v.push_back(record_digest(kDomain, record_text(i % 1500)));
        auto shuffled = v;
        std::mt19937_64 rng(20260911);
        std::shuffle(shuffled.begin(), shuffled.end(), rng);
        REQUIRE(dedupe(v) == 500);
        REQUIRE(dedupe(shuffled) == 500);
        REQUIRE(v == shuffled);
    }

    SECTION("empty input") {
        std::vector<Digest> v;
        REQUIRE(dedupe(v) == 0);
        REQUIRE(v.empty());
    }
}

// ---------------------------------------------------------------------------
// Determinism across parties
// ---------------------------------------------------------------------------

// Two "parties" build their inputs by different code paths, in different
// orders, one with repeated rows. Shared records must land on identical
// (position, signature), and after dedupe the sets must intersect in exactly
// the records they share. (The cross-IMPLEMENTATION version of this is the
// hashlib known-answer test above.)
TEST_CASE("two parties encoding the same records independently agree", "[psi][digest]") {
    constexpr std::uint64_t cells = std::uint64_t{1} << 16;

    std::vector<Digest> party_a;
    for (std::uint64_t i = 0; i < 1000; ++i) party_a.push_back(record_digest(kDomain, record_text(i)));

    const std::string domain_b{ kDomain };  // B's own copy of the pinned parameter
    std::vector<Digest> party_b;
    std::uint64_t repeats = 0;
    for (std::uint64_t i = 1500; i-- > 500;) {
        std::ostringstream row;
        row << "record-" << i;
        party_b.push_back(record_digest(domain_b, row.str()));
        if (i % 7 == 0) {
            party_b.push_back(record_digest(domain_b, row.str()));
            ++repeats;
        }
    }

    for (std::uint64_t i = 500; i < 1000; ++i) {
        std::ostringstream row;
        row << "record-" << i;
        const auto da = record_digest(kDomain, record_text(i));
        const auto db = record_digest(domain_b, row.str());
        REQUIRE(position(da, cells) == position(db, cells));
        REQUIRE(signature(da, kProductionLimbs) == signature(db, kProductionLimbs));
    }

    REQUIRE(dedupe(party_a) == 0);
    REQUIRE(dedupe(party_b) == repeats);
    std::vector<Digest> shared;
    std::set_intersection(party_a.begin(), party_a.end(), party_b.begin(), party_b.end(),
                          std::back_inserter(shared));
    REQUIRE(shared.size() == 500);
}

// ---------------------------------------------------------------------------
// Parameter validation
// ---------------------------------------------------------------------------

TEST_CASE("digest parameters outside what one SHA-256 can deliver are refused",
          "[psi][digest]") {
    const Digest d = record_digest(kDomain, "x");

    CHECK_THROWS_AS(position(d, 0), std::invalid_argument);
    CHECK_THROWS_AS(position(d, 3), std::invalid_argument);          // not a power of two
    CHECK_THROWS_AS(position(d, max_cells + 1), std::invalid_argument);
    CHECK_THROWS_AS(position(d, max_cells << 1), std::invalid_argument);  // needs > 32 address bits
    CHECK_NOTHROW(position(d, max_cells));

    CHECK_THROWS_AS(signature(d, 0), std::invalid_argument);
    CHECK_THROWS_AS(signature(d, max_limbs + 1), std::invalid_argument);
    CHECK_NOTHROW(signature(d, max_limbs));
    CHECK_THROWS_AS(limb(d, max_limbs), std::out_of_range);
}
