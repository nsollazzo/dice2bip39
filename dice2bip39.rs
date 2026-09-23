//! Dice digits to a 24-word BIP39 mnemonic.
//!
//! Entropy is SHA-256 of the ASCII digit string. This file does not call an RNG,
//! does not write files, and does not derive keys.
//!
//! Two SHA-256 implementations must agree or the process aborts. Algorithm text:
//! FIPS 180-4, section 6.2.2 (SHA-256). Initial hash value and K constants:
//! FIPS 180-4, sections 5.3.3 and 4.2.2.

#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::convert::TryInto;
use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::process;

const WORDLIST_SHA256: &str = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda";
const EMBEDDED: &str = include_str!("english.txt");

const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// FIPS 180-4 section 4.2.2.
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn rotr(x: u32, n: u32) -> u32 {
    x.rotate_right(n)
}

fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

fn bsig0(x: u32) -> u32 {
    rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)
}

fn bsig1(x: u32) -> u32 {
    rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)
}

fn ssig0(x: u32) -> u32 {
    rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)
}

fn ssig1(x: u32) -> u32 {
    rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)
}

/// SHA-256 transcribed as a block loop. FIPS 180-4 section 6.2.2.
/// Padding is built in one buffer, then consumed 64 bytes at a time.
fn sha256_fips(data: &[u8]) -> [u8; 32] {
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut padded = Vec::with_capacity(data.len() + 72);
    padded.extend_from_slice(data);
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    let mut h = IV;
    let mut offset = 0;
    while offset < padded.len() {
        let block = &padded[offset..offset + 64];
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
        }
        for i in 16..64 {
            w[i] = ssig1(w[i - 2])
                .wrapping_add(w[i - 7])
                .wrapping_add(ssig0(w[i - 15]))
                .wrapping_add(w[i - 16]);
        }
        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];
        for i in 0..64 {
            let t1 = hh
                .wrapping_add(bsig1(e))
                .wrapping_add(ch(e, f, g))
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let t2 = bsig0(a).wrapping_add(maj(a, b, c));
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
        offset += 64;
    }

    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// Second SHA-256. Same FIPS 180-4 section 6.2.2, different control flow:
/// message schedule is extended inside the compression function, and padding
/// length is computed up front instead of grown with a while-loop.
fn sha256_ref(data: &[u8]) -> [u8; 32] {
    fn compress(state: &mut [u32; 8], block: &[u8]) {
        let mut w = [0u32; 64];
        let mut j = 0;
        while j < 16 {
            w[j] = u32::from_be_bytes([
                block[j * 4],
                block[j * 4 + 1],
                block[j * 4 + 2],
                block[j * 4 + 3],
            ]);
            j += 1;
        }
        j = 16;
        while j < 64 {
            let s1 = rotr(w[j - 2], 17) ^ rotr(w[j - 2], 19) ^ (w[j - 2] >> 10);
            let s0 = rotr(w[j - 15], 7) ^ rotr(w[j - 15], 18) ^ (w[j - 15] >> 3);
            w[j] = s1
                .wrapping_add(w[j - 7])
                .wrapping_add(s0)
                .wrapping_add(w[j - 16]);
            j += 1;
        }
        let mut regs = *state;
        let mut t = 0;
        while t < 64 {
            let s1 = rotr(regs[4], 6) ^ rotr(regs[4], 11) ^ rotr(regs[4], 25);
            let choose = (regs[4] & regs[5]) ^ ((!regs[4]) & regs[6]);
            let temp1 = regs[7]
                .wrapping_add(s1)
                .wrapping_add(choose)
                .wrapping_add(K[t])
                .wrapping_add(w[t]);
            let s0 = rotr(regs[0], 2) ^ rotr(regs[0], 13) ^ rotr(regs[0], 22);
            let majority = (regs[0] & regs[1]) ^ (regs[0] & regs[2]) ^ (regs[1] & regs[2]);
            let temp2 = s0.wrapping_add(majority);
            regs[7] = regs[6];
            regs[6] = regs[5];
            regs[5] = regs[4];
            regs[4] = regs[3].wrapping_add(temp1);
            regs[3] = regs[2];
            regs[2] = regs[1];
            regs[1] = regs[0];
            regs[0] = temp1.wrapping_add(temp2);
            t += 1;
        }
        let mut i = 0;
        while i < 8 {
            state[i] = state[i].wrapping_add(regs[i]);
            i += 1;
        }
    }

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let with_bit = data.len() + 1;
    let pad_zeros = (64 + 56 - (with_bit % 64)) % 64;
    let total = with_bit + pad_zeros + 8;
    let mut buf = vec![0u8; total];
    buf[..data.len()].copy_from_slice(data);
    buf[data.len()] = 0x80;
    buf[total - 8..].copy_from_slice(&bit_len.to_be_bytes());

    let mut state = IV;
    let mut off = 0;
    while off < total {
        compress(&mut state, &buf[off..off + 64]);
        off += 64;
    }
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 8 {
        let bytes = state[i].to_be_bytes();
        out[i * 4] = bytes[0];
        out[i * 4 + 1] = bytes[1];
        out[i * 4 + 2] = bytes[2];
        out[i * 4 + 3] = bytes[3];
        i += 1;
    }
    out
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let a = sha256_fips(data);
    let b = sha256_ref(data);
    if a != b {
        let _ = writeln!(io::stderr(), "sha256-disagree");
        process::abort();
    }
    a
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

fn parse_words(text: &str) -> Result<Vec<&str>, &'static str> {
    let mut lines: Vec<&str> = text.split('\n').collect();
    if lines.last() == Some(&"") {
        lines.pop();
    }
    if lines.len() != 2048 {
        return Err("wordlist");
    }
    if lines[0] != "abandon" || lines[2047] != "zoo" {
        return Err("wordlist");
    }
    let set: HashSet<&str> = lines.iter().copied().collect();
    if set.len() != 2048 {
        return Err("wordlist");
    }
    let prefixes: HashSet<&str> = lines.iter().map(|w| &w[..w.len().min(4)]).collect();
    if prefixes.len() != 2048 {
        return Err("wordlist");
    }
    Ok(lines)
}

fn load_wordlist() -> Result<Vec<String>, &'static str> {
    let embedded_hash = to_hex(&sha256(EMBEDDED.as_bytes()));
    if embedded_hash != WORDLIST_SHA256 {
        return Err("wordlist");
    }
    let external = fs::read("english.txt").map_err(|_| "wordlist")?;
    let external_hash = to_hex(&sha256(&external));
    if external_hash != WORDLIST_SHA256 {
        return Err("wordlist");
    }
    if external != EMBEDDED.as_bytes() {
        return Err("wordlist");
    }
    let parsed = parse_words(EMBEDDED)?;
    Ok(parsed.into_iter().map(str::to_string).collect())
}

fn mnemonic_from_entropy(entropy: &[u8], words: &[String]) -> Result<String, &'static str> {
    if entropy.len() != 16 && entropy.len() != 32 {
        return Err("entropy");
    }
    let ent_bits = entropy.len() * 8;
    let cs_len = ent_bits / 32;
    let digest = sha256(entropy);
    // BIP39: append the first CS bits of SHA-256(entropy), then take 11-bit groups.
    // Feed entropy bytes, then exactly cs_len checksum bits. No trailing pad bits.
    let cs_bits = digest[0] >> (8 - cs_len);
    let mut acc: u32 = 0;
    let mut nbits: u32 = 0;
    let mut out: Vec<&str> = Vec::new();
    for &byte in entropy {
        acc = (acc << 8) | u32::from(byte);
        nbits += 8;
        while nbits >= 11 {
            nbits -= 11;
            let idx = ((acc >> nbits) & 0x7ff) as usize;
            out.push(words[idx].as_str());
        }
    }
    acc = (acc << cs_len) | u32::from(cs_bits);
    nbits += cs_len as u32;
    while nbits >= 11 {
        nbits -= 11;
        let idx = ((acc >> nbits) & 0x7ff) as usize;
        out.push(words[idx].as_str());
    }
    if nbits != 0 || out.len() != (ent_bits + cs_len) / 11 {
        return Err("entropy");
    }
    Ok(out.join(" "))
}

fn from_hex(s: &str) -> Result<Vec<u8>, ()> {
    if s.len() % 2 != 0 || s.is_empty() {
        return Err(());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_val(bytes[i])?;
        let lo = hex_val(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn hex_val(b: u8) -> Result<u8, ()> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(()),
    }
}

fn expect_sha(label: &'static str, data: &[u8], hex_digest: &str) -> Result<(), &'static str> {
    let got = sha256(data);
    if to_hex(&got) != hex_digest {
        let _ = writeln!(io::stderr(), "{label}");
        return Err(label);
    }
    Ok(())
}

fn bip39_self_test(words: &[String]) -> Result<(), &'static str> {
    let z16 = mnemonic_from_entropy(&[0u8; 16], words).map_err(|_| "bip39-zero128")?;
    if z16 != "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" {
        return Err("bip39-zero128");
    }
    let z32 = mnemonic_from_entropy(&[0u8; 32], words).map_err(|_| "bip39-zero256")?;
    if z32 != "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art" {
        return Err("bip39-zero256");
    }
    let ff = mnemonic_from_entropy(&[0xffu8; 32], words).map_err(|_| "bip39-ff")?;
    if ff != "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote" {
        return Err("bip39-ff");
    }
    let sevens = mnemonic_from_entropy(&[0x7fu8; 16], words).map_err(|_| "bip39-7f128")?;
    if sevens != "legal winner thank year wave sausage worth useful legal winner thank yellow" {
        return Err("bip39-7f128");
    }

    let short = b"123456";
    if to_hex(&sha256(short)) != "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92" {
        return Err("coldcard-hash");
    }
    let short_words = mnemonic_from_entropy(&sha256(short), words).map_err(|_| "coldcard-words")?;
    if short_words != "mirror reject rookie talk pudding throw happy era myth already payment own sentence push head sting video explain letter bomb casual hotel rather garment" {
        return Err("coldcard-words");
    }

    let rolls = b"655152231316521321611331544441236164664431121534415633526456254462245546236542364246312613322234612";
    if to_hex(&sha256(rolls)) != "51531761ec7a738946e0b9f46bb11320a695495430e345c14f01ad8b3b898a6d" {
        return Err("seedsigner-hash");
    }
    let roll_words = mnemonic_from_entropy(&sha256(rolls), words).map_err(|_| "seedsigner-words")?;
    if roll_words != "eyebrow obvious such suggest poet seven breeze blame virtual frown dynamic donor harsh pigeon express broccoli easy apology scatter force recipe shadow claim radio" {
        return Err("seedsigner-words");
    }
    check_vector_file(words)?;
    Ok(())
}

/// Walk tests/vectors.json with a tiny scanner. A ceremony box with no Python
/// still fails closed if a published row drifts. Not a general JSON parser.
fn check_vector_file(words: &[String]) -> Result<(), &'static str> {
    let text = fs::read_to_string("tests/vectors.json").map_err(|_| "vectors-file")?;
    let mut entropy: Option<String> = None;
    let mut mnemonic: Option<String> = None;
    let mut rolls: Option<String> = None;
    let mut sha: Option<String> = None;
    let mut bip39_n = 0usize;
    let mut dice_n = 0usize;
    for raw in text.lines() {
        let line = raw.trim().trim_end_matches(',');
        if let Some(rest) = line.strip_prefix("\"entropy\":") {
            entropy = Some(json_string(rest)?);
        } else if let Some(rest) = line.strip_prefix("\"mnemonic\":") {
            mnemonic = Some(json_string(rest)?);
        } else if let Some(rest) = line.strip_prefix("\"rolls\":") {
            rolls = Some(json_string(rest)?);
        } else if let Some(rest) = line.strip_prefix("\"sha256\":") {
            sha = Some(json_string(rest)?);
        } else if line == "{" {
            entropy = None;
            mnemonic = None;
            rolls = None;
            sha = None;
        } else if line == "}" {
            if let (Some(ent), Some(mn)) = (entropy.clone(), mnemonic.clone()) {
                let bytes = from_hex(&ent).map_err(|_| "vectors-hex")?;
                let got = mnemonic_from_entropy(&bytes, words).map_err(|_| "vectors-bip39")?;
                if got != mn {
                    return Err("vectors-bip39");
                }
                bip39_n += 1;
            } else if let (Some(r), Some(h), Some(mn)) = (rolls.clone(), sha.clone(), mnemonic.clone())
            {
                let digest = sha256(r.as_bytes());
                if to_hex(&digest) != h {
                    return Err("vectors-dice-hash");
                }
                let got = mnemonic_from_entropy(&digest, words).map_err(|_| "vectors-dice")?;
                if got != mn {
                    return Err("vectors-dice");
                }
                dice_n += 1;
            }
            entropy = None;
            mnemonic = None;
            rolls = None;
            sha = None;
        }
    }
    if bip39_n < 8 || dice_n < 2 {
        return Err("vectors-count");
    }
    Ok(())
}

fn json_string(rest: &str) -> Result<String, &'static str> {
    let rest = rest.trim().trim_end_matches(',');
    let rest = rest.strip_prefix('"').ok_or("vectors-json")?;
    let rest = rest.strip_suffix('"').ok_or("vectors-json")?;
    if rest.contains('\\') {
        return Err("vectors-json");
    }
    Ok(rest.to_string())
}

fn self_test() -> Result<(), &'static str> {
    expect_sha(
        "sha-empty",
        b"",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )?;
    expect_sha(
        "sha-abc",
        b"abc",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    )?;
    expect_sha(
        "sha-two-block",
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    )?;
    let million = vec![b'a'; 1_000_000];
    expect_sha(
        "sha-million-a",
        &million,
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
    )?;
    let words = load_wordlist()?;
    bip39_self_test(&words)?;
    Ok(())
}

fn read_rolls() -> Result<Vec<u8>, &'static str> {
    let mut buf = Vec::new();
    io::stdin().read_to_end(&mut buf).map_err(|_| "input")?;
    if buf.last() == Some(&b'\n') {
        buf.pop();
    }
    if buf.last() == Some(&b'\r') {
        buf.pop();
    }
    if buf.len() < 99 || buf.len() > 4096 {
        return Err("input");
    }
    if buf.iter().any(|b| !matches!(b, b'1'..=b'6')) {
        return Err("input");
    }
    Ok(buf)
}

/// Best-effort overwrite. Not a guarantee against swap, core dumps, or the display.
#[inline(never)]
fn scrub(bytes: &mut [u8]) {
    for b in bytes.iter_mut() {
        *b = 0;
    }
    std::hint::black_box(bytes);
}

fn emit_mnemonic(mnemonic: &str) {
    let line = mnemonic.to_string();
    let _ = writeln!(io::stdout(), "{line}");
    let _ = io::stdout().flush();
    let mut raw = line.into_bytes();
    scrub(&mut raw);
    scrub(raw.as_mut_slice());
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.len() == 1 && args[0] == "--self-test" {
        match self_test() {
            Ok(()) => {
                println!("ok");
                process::exit(0);
            }
            Err(name) => {
                let _ = writeln!(io::stderr(), "{name}");
                process::exit(1);
            }
        }
    }
    if args.len() == 2 && args[0] == "--hex-to-mnemonic" {
        let words = match load_wordlist() {
            Ok(w) => w,
            Err(name) => {
                let _ = writeln!(io::stderr(), "{name}");
                process::exit(1);
            }
        };
        let entropy = match from_hex(&args[1]) {
            Ok(v) if v.len() == 16 || v.len() == 32 => v,
            _ => process::exit(2),
        };
        match mnemonic_from_entropy(&entropy, &words) {
            Ok(m) => {
                emit_mnemonic(&m);
                process::exit(0);
            }
            Err(_) => process::exit(2),
        }
    }
    if args.is_empty() {
        let words = match load_wordlist() {
            Ok(w) => w,
            Err(name) => {
                let _ = writeln!(io::stderr(), "{name}");
                process::exit(1);
            }
        };
        let mut rolls = match read_rolls() {
            Ok(v) => v,
            Err(name) => {
                let _ = writeln!(io::stderr(), "{name}");
                process::exit(2);
            }
        };
        let digest = sha256(&rolls);
        let mnemonic = match mnemonic_from_entropy(&digest, &words) {
            Ok(m) => m,
            Err(name) => {
                let _ = writeln!(io::stderr(), "{name}");
                process::exit(1);
            }
        };
        let _ = writeln!(io::stderr(), "rolls: {}", rolls.len());
        let _ = writeln!(io::stderr(), "sha256: {}", to_hex(&digest));
        emit_mnemonic(&mnemonic);
        scrub(&mut rolls);
        process::exit(0);
    }
    process::exit(2);
}
