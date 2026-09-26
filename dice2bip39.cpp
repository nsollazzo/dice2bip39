// Dice digits to a 24-word BIP39 mnemonic.
//
// Entropy is SHA-256 of the ASCII digit string. This file does not call an RNG,
// does not write files, and does not derive keys.
//
// Two SHA-256 implementations must agree or the process aborts. Algorithm text:
// FIPS 180-4, section 6.2.2 (SHA-256). Initial hash value and K constants:
// FIPS 180-4, sections 5.3.3 and 4.2.2.

#include "english_inc.h"

#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>

namespace {

constexpr char WORDLIST_SHA256[] =
    "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda";

constexpr uint32_t IV[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

// FIPS 180-4 section 4.2.2.
constexpr uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }

uint32_t ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }

uint32_t maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }

uint32_t bsig0(uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }

uint32_t bsig1(uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }

uint32_t ssig0(uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }

uint32_t ssig1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }

void store_be32(uint8_t* p, uint32_t w) {
    p[0] = static_cast<uint8_t>(w >> 24);
    p[1] = static_cast<uint8_t>(w >> 16);
    p[2] = static_cast<uint8_t>(w >> 8);
    p[3] = static_cast<uint8_t>(w);
}

uint32_t load_be32(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | uint32_t(p[3]);
}

// SHA-256 transcribed as a block loop. FIPS 180-4 section 6.2.2.
// Padding is grown, then consumed 64 bytes at a time.
std::array<uint8_t, 32> sha256_fips(const uint8_t* data, size_t len) {
    const uint64_t bit_len = uint64_t(len) * 8;
    std::vector<uint8_t> padded;
    padded.reserve(len + 72);
    padded.insert(padded.end(), data, data + len);
    padded.push_back(0x80);
    while ((padded.size() % 64) != 56) {
        padded.push_back(0);
    }
    for (int i = 7; i >= 0; --i) {
        padded.push_back(static_cast<uint8_t>(bit_len >> (8 * i)));
    }

    uint32_t h[8];
    for (int i = 0; i < 8; ++i) h[i] = IV[i];

    for (size_t offset = 0; offset < padded.size(); offset += 64) {
        const uint8_t* block = padded.data() + offset;
        uint32_t w[64];
        for (int i = 0; i < 16; ++i) w[i] = load_be32(block + i * 4);
        for (int i = 16; i < 64; ++i) {
            w[i] = ssig1(w[i - 2]) + w[i - 7] + ssig0(w[i - 15]) + w[i - 16];
        }
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
        for (int i = 0; i < 64; ++i) {
            uint32_t t1 = hh + bsig1(e) + ch(e, f, g) + K[i] + w[i];
            uint32_t t2 = bsig0(a) + maj(a, b, c);
            hh = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
        h[5] += f;
        h[6] += g;
        h[7] += hh;
    }

    std::array<uint8_t, 32> out{};
    for (int i = 0; i < 8; ++i) store_be32(out.data() + i * 4, h[i]);
    return out;
}

// Second SHA-256. Same FIPS section, different control flow: padding length is
// computed up front, and the message schedule is extended inside compression.
std::array<uint8_t, 32> sha256_ref(const uint8_t* data, size_t len) {
    auto compress = [](uint32_t state[8], const uint8_t* block) {
        uint32_t w[64];
        int j = 0;
        while (j < 16) {
            w[j] = load_be32(block + j * 4);
            j += 1;
        }
        while (j < 64) {
            uint32_t s1 = rotr(w[j - 2], 17) ^ rotr(w[j - 2], 19) ^ (w[j - 2] >> 10);
            uint32_t s0 = rotr(w[j - 15], 7) ^ rotr(w[j - 15], 18) ^ (w[j - 15] >> 3);
            w[j] = s1 + w[j - 7] + s0 + w[j - 16];
            j += 1;
        }
        uint32_t regs[8];
        for (int i = 0; i < 8; ++i) regs[i] = state[i];
        int t = 0;
        while (t < 64) {
            uint32_t s1 = rotr(regs[4], 6) ^ rotr(regs[4], 11) ^ rotr(regs[4], 25);
            uint32_t choose = (regs[4] & regs[5]) ^ ((~regs[4]) & regs[6]);
            uint32_t temp1 = regs[7] + s1 + choose + K[t] + w[t];
            uint32_t s0 = rotr(regs[0], 2) ^ rotr(regs[0], 13) ^ rotr(regs[0], 22);
            uint32_t majority = (regs[0] & regs[1]) ^ (regs[0] & regs[2]) ^ (regs[1] & regs[2]);
            uint32_t temp2 = s0 + majority;
            regs[7] = regs[6];
            regs[6] = regs[5];
            regs[5] = regs[4];
            regs[4] = regs[3] + temp1;
            regs[3] = regs[2];
            regs[2] = regs[1];
            regs[1] = regs[0];
            regs[0] = temp1 + temp2;
            t += 1;
        }
        for (int i = 0; i < 8; ++i) state[i] += regs[i];
    };

    const uint64_t bit_len = uint64_t(len) * 8;
    const size_t with_bit = len + 1;
    const size_t pad_zeros = (64 + 56 - (with_bit % 64)) % 64;
    const size_t total = with_bit + pad_zeros + 8;
    std::vector<uint8_t> buf(total, 0);
    if (len) std::memcpy(buf.data(), data, len);
    buf[len] = 0x80;
    for (int i = 7; i >= 0; --i) {
        buf[total - 8 + (7 - i)] = static_cast<uint8_t>(bit_len >> (8 * i));
    }

    uint32_t state[8];
    for (int i = 0; i < 8; ++i) state[i] = IV[i];
    for (size_t off = 0; off < total; off += 64) compress(state, buf.data() + off);

    std::array<uint8_t, 32> out{};
    for (int i = 0; i < 8; ++i) store_be32(out.data() + i * 4, state[i]);
    return out;
}

std::array<uint8_t, 32> sha256(const uint8_t* data, size_t len) {
    auto a = sha256_fips(data, len);
    auto b = sha256_ref(data, len);
    if (a != b) {
        std::cerr << "sha256-disagree\n";
        std::abort();
    }
    return a;
}

std::array<uint8_t, 32> sha256(const std::string& s) {
    return sha256(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

std::string to_hex(const uint8_t* bytes, size_t n) {
    static const char* HEX = "0123456789abcdef";
    std::string s;
    s.resize(n * 2);
    for (size_t i = 0; i < n; ++i) {
        s[i * 2] = HEX[bytes[i] >> 4];
        s[i * 2 + 1] = HEX[bytes[i] & 0xf];
    }
    return s;
}

std::string to_hex(const std::array<uint8_t, 32>& d) { return to_hex(d.data(), d.size()); }

void fail(const char* name) {
    std::cerr << name << "\n";
    std::exit(1);
}

std::vector<std::string> parse_words(const std::string& text) {
    std::vector<std::string> lines;
    std::string cur;
    for (char ch : text) {
        if (ch == '\n') {
            lines.push_back(cur);
            cur.clear();
        } else if (ch != '\r') {
            cur.push_back(ch);
        }
    }
    if (!cur.empty()) lines.push_back(cur);
    if (!lines.empty() && lines.back().empty()) lines.pop_back();
    if (lines.size() != 2048) fail("wordlist");
    if (lines[0] != "abandon" || lines[2047] != "zoo") fail("wordlist");
    std::unordered_set<std::string> set(lines.begin(), lines.end());
    if (set.size() != 2048) fail("wordlist");
    std::unordered_set<std::string> prefixes;
    for (const auto& w : lines) prefixes.insert(w.substr(0, std::min<size_t>(4, w.size())));
    if (prefixes.size() != 2048) fail("wordlist");
    return lines;
}

std::vector<std::string> load_wordlist() {
    const std::string embedded(EMBEDDED, sizeof(EMBEDDED) - 1);
    if (to_hex(sha256(embedded)) != WORDLIST_SHA256) fail("wordlist");

    std::ifstream in("english.txt", std::ios::binary);
    if (!in) fail("wordlist");
    std::ostringstream ss;
    ss << in.rdbuf();
    const std::string external = ss.str();
    if (to_hex(sha256(external)) != WORDLIST_SHA256) fail("wordlist");
    if (external != embedded) fail("wordlist");
    return parse_words(embedded);
}

std::string mnemonic_from_entropy(const uint8_t* entropy, size_t elen, const std::vector<std::string>& words) {
    if (elen != 16 && elen != 32) return {};
    const size_t ent_bits = elen * 8;
    const size_t cs_len = ent_bits / 32;
    auto digest = sha256(entropy, elen);
    const uint32_t cs_bits = digest[0] >> (8 - cs_len);
    uint32_t acc = 0;
    uint32_t nbits = 0;
    std::vector<std::string> out;
    for (size_t i = 0; i < elen; ++i) {
        acc = (acc << 8) | entropy[i];
        nbits += 8;
        while (nbits >= 11) {
            nbits -= 11;
            size_t idx = (acc >> nbits) & 0x7ff;
            out.push_back(words[idx]);
        }
    }
    acc = (acc << cs_len) | cs_bits;
    nbits += static_cast<uint32_t>(cs_len);
    while (nbits >= 11) {
        nbits -= 11;
        size_t idx = (acc >> nbits) & 0x7ff;
        out.push_back(words[idx]);
    }
    if (nbits != 0 || out.size() != (ent_bits + cs_len) / 11) return {};
    std::string joined;
    for (size_t i = 0; i < out.size(); ++i) {
        if (i) joined.push_back(' ');
        joined += out[i];
    }
    return joined;
}

int hex_val(char b) {
    if (b >= '0' && b <= '9') return b - '0';
    if (b >= 'a' && b <= 'f') return b - 'a' + 10;
    if (b >= 'A' && b <= 'F') return b - 'A' + 10;
    return -1;
}

bool from_hex(const std::string& s, std::vector<uint8_t>& out) {
    if (s.empty() || s.size() % 2 != 0) return false;
    out.clear();
    out.reserve(s.size() / 2);
    for (size_t i = 0; i < s.size(); i += 2) {
        int hi = hex_val(s[i]);
        int lo = hex_val(s[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return true;
}

void expect_sha(const char* label, const uint8_t* data, size_t len, const char* hex_digest) {
    if (to_hex(sha256(data, len)) != hex_digest) fail(label);
}

std::string json_string(const std::string& rest_in) {
    std::string rest = rest_in;
    while (!rest.empty() && (rest.back() == ' ' || rest.back() == '\t' || rest.back() == ',')) rest.pop_back();
    size_t i = 0;
    while (i < rest.size() && (rest[i] == ' ' || rest[i] == '\t')) ++i;
    rest = rest.substr(i);
    if (rest.size() < 2 || rest.front() != '"' || rest.back() != '"') fail("vectors-json");
    rest = rest.substr(1, rest.size() - 2);
    if (rest.find('\\') != std::string::npos) fail("vectors-json");
    return rest;
}

void check_vector_file(const std::vector<std::string>& words) {
    std::ifstream in("tests/vectors.json");
    if (!in) fail("vectors-file");
    std::string entropy, mnemonic, rolls, sha;
    bool has_e = false, has_m = false, has_r = false, has_s = false;
    int bip39_n = 0, dice_n = 0;
    std::string raw;
    while (std::getline(in, raw)) {
        std::string line = raw;
        while (!line.empty() && (line.front() == ' ' || line.front() == '\t')) line.erase(line.begin());
        if (!line.empty() && line.back() == ',') line.pop_back();
        auto take = [&](const char* key, std::string& dest, bool& flag) {
            std::string prefix = std::string("\"") + key + "\":";
            if (line.compare(0, prefix.size(), prefix) != 0) return false;
            dest = json_string(line.substr(prefix.size()));
            flag = true;
            return true;
        };
        if (take("entropy", entropy, has_e) || take("mnemonic", mnemonic, has_m) ||
            take("rolls", rolls, has_r) || take("sha256", sha, has_s)) {
            continue;
        }
        if (line == "{") {
            has_e = has_m = has_r = has_s = false;
        } else if (line == "}") {
            if (has_e && has_m) {
                std::vector<uint8_t> bytes;
                if (!from_hex(entropy, bytes)) fail("vectors-hex");
                auto got = mnemonic_from_entropy(bytes.data(), bytes.size(), words);
                if (got.empty() || got != mnemonic) fail("vectors-bip39");
                bip39_n += 1;
            } else if (has_r && has_s && has_m) {
                auto digest = sha256(rolls);
                if (to_hex(digest) != sha) fail("vectors-dice-hash");
                auto got = mnemonic_from_entropy(digest.data(), digest.size(), words);
                if (got.empty() || got != mnemonic) fail("vectors-dice");
                dice_n += 1;
            }
            has_e = has_m = has_r = has_s = false;
        }
    }
    if (bip39_n < 8 || dice_n < 2) fail("vectors-count");
}

void bip39_self_test(const std::vector<std::string>& words) {
    uint8_t z16[16] = {};
    auto m = mnemonic_from_entropy(z16, 16, words);
    if (m != "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
        fail("bip39-zero128");
    uint8_t z32[32] = {};
    m = mnemonic_from_entropy(z32, 32, words);
    if (m != "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art")
        fail("bip39-zero256");
    uint8_t ff[32];
    std::memset(ff, 0xff, 32);
    m = mnemonic_from_entropy(ff, 32, words);
    if (m != "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote")
        fail("bip39-ff");
    uint8_t sevens[16];
    std::memset(sevens, 0x7f, 16);
    m = mnemonic_from_entropy(sevens, 16, words);
    if (m != "legal winner thank year wave sausage worth useful legal winner thank yellow")
        fail("bip39-7f128");

    const char* short_rolls = "123456";
    if (to_hex(sha256(reinterpret_cast<const uint8_t*>(short_rolls), 6)) !=
        "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92")
        fail("coldcard-hash");
    auto digest = sha256(reinterpret_cast<const uint8_t*>(short_rolls), 6);
    m = mnemonic_from_entropy(digest.data(), digest.size(), words);
    if (m != "mirror reject rookie talk pudding throw happy era myth already payment own sentence push head sting video explain letter bomb casual hotel rather garment")
        fail("coldcard-words");

    const char* rolls =
        "655152231316521321611331544441236164664431121534415633526456254462245546236542364246312613322234612";
    if (to_hex(sha256(reinterpret_cast<const uint8_t*>(rolls), 99)) !=
        "51531761ec7a738946e0b9f46bb11320a695495430e345c14f01ad8b3b898a6d")
        fail("seedsigner-hash");
    digest = sha256(reinterpret_cast<const uint8_t*>(rolls), 99);
    m = mnemonic_from_entropy(digest.data(), digest.size(), words);
    if (m != "eyebrow obvious such suggest poet seven breeze blame virtual frown dynamic donor harsh pigeon express broccoli easy apology scatter force recipe shadow claim radio")
        fail("seedsigner-words");
    check_vector_file(words);
}

void self_test() {
    expect_sha("sha-empty", nullptr, 0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    const char* abc = "abc";
    expect_sha("sha-abc", reinterpret_cast<const uint8_t*>(abc), 3,
               "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    const char* two = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    expect_sha("sha-two-block", reinterpret_cast<const uint8_t*>(two), std::strlen(two),
               "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    std::vector<uint8_t> million(1000000, 'a');
    expect_sha("sha-million-a", million.data(), million.size(),
               "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    auto words = load_wordlist();
    bip39_self_test(words);
}

// Best-effort overwrite. Not a guarantee against swap, core dumps, or the display.
void scrub(std::string& s) {
    volatile char* p = s.empty() ? nullptr : &s[0];
    for (size_t i = 0; i < s.size(); ++i) p[i] = 0;
}

void emit_mnemonic(std::string mnemonic) {
    std::cout << mnemonic << "\n";
    std::cout.flush();
    scrub(mnemonic);
}

std::string read_rolls() {
    std::ostringstream ss;
    ss << std::cin.rdbuf();
    std::string buf = ss.str();
    if (!buf.empty() && buf.back() == '\n') buf.pop_back();
    if (!buf.empty() && buf.back() == '\r') buf.pop_back();
    if (buf.size() < 99 || buf.size() > 4096) {
        std::cerr << "input\n";
        std::exit(2);
    }
    for (unsigned char b : buf) {
        if (b < '1' || b > '6') {
            std::cerr << "input\n";
            std::exit(2);
        }
    }
    return buf;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc == 2 && std::strcmp(argv[1], "--self-test") == 0) {
        self_test();
        std::cout << "ok\n";
        return 0;
    }
    if (argc == 3 && std::strcmp(argv[1], "--hex-to-mnemonic") == 0) {
        auto words = load_wordlist();
        std::vector<uint8_t> entropy;
        if (!from_hex(argv[2], entropy) || (entropy.size() != 16 && entropy.size() != 32)) return 2;
        auto m = mnemonic_from_entropy(entropy.data(), entropy.size(), words);
        if (m.empty()) return 2;
        emit_mnemonic(std::move(m));
        return 0;
    }
    if (argc == 1) {
        auto words = load_wordlist();
        std::string rolls = read_rolls();
        auto digest = sha256(rolls);
        auto mnemonic = mnemonic_from_entropy(digest.data(), digest.size(), words);
        if (mnemonic.empty()) fail("entropy");
        std::cerr << "rolls: " << rolls.size() << "\n";
        std::cerr << "sha256: " << to_hex(digest) << "\n";
        emit_mnemonic(std::move(mnemonic));
        scrub(rolls);
        return 0;
    }
    return 2;
}
