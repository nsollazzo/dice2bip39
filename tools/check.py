#!/usr/bin/env python3
"""Independent checker for dice2bip39.

Uses hashlib (OpenSSL/libcrypto via CPython), not the Rust binary's SHA-256.
A pass means the binary matched published vectors and this script's own BIP39
packing. It does not mean the ceremony computer is clean.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BIN = ROOT / "dice2bip39"
WORDS_PATH = ROOT / "english.txt"
VECTORS = ROOT / "tests" / "vectors.json"

WORDLIST_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"

SHA_VECTORS = [
    (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    (
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    ),
    (b"a" * 1_000_000, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"),
]


def die(msg: str) -> None:
    print(f"FAIL {msg}", file=sys.stderr)
    raise SystemExit(1)


def load_words() -> list[str]:
    raw = WORDS_PATH.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != WORDLIST_SHA256:
        die(f"english.txt sha256 {digest} != pin")
    words = raw.decode("ascii").splitlines()
    if len(words) != 2048 or words[0] != "abandon" or words[-1] != "zoo":
        die("wordlist shape")
    if len(set(words)) != 2048:
        die("wordlist duplicates")
    prefixes = [w[:4] for w in words]
    if len(set(prefixes)) != 2048:
        die("wordlist prefix collision")
    return words


def mnemonic_from_entropy(entropy: bytes, words: list[str]) -> str:
    if len(entropy) not in (16, 32):
        die(f"entropy length {len(entropy)}")
    ent_bits = len(entropy) * 8
    cs_len = ent_bits // 32
    digest = hashlib.sha256(entropy).digest()
    cs = int.from_bytes(digest, "big") >> (256 - cs_len)
    combined = (int.from_bytes(entropy, "big") << cs_len) | cs
    total = ent_bits + cs_len
    idxs = []
    for i in range(total // 11):
        shift = total - 11 * (i + 1)
        idxs.append((combined >> shift) & 0x7FF)
    return " ".join(words[i] for i in idxs)


def run(args: list[str], stdin: bytes | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(BIN), *args],
        input=None if stdin is None else stdin.decode("ascii"),
        text=True,
        capture_output=True,
        cwd=ROOT,
        check=False,
    )


def main() -> None:
    if not BIN.is_file():
        die(f"missing binary {BIN}; rustc dice2bip39.rs -o dice2bip39 first")
    words = load_words()

    for data, expect in SHA_VECTORS:
        got = hashlib.sha256(data).hexdigest()
        if got != expect:
            die(f"hashlib sha256 mismatch for {data[:16]!r}: {got}")

    proc = run(["--self-test"])
    if proc.returncode != 0 or proc.stdout != "ok\n":
        die(f"self-test rc={proc.returncode} stdout={proc.stdout!r} stderr={proc.stderr!r}")

    vectors = json.loads(VECTORS.read_text())
    for row in vectors["bip39"]:
        entropy = row["entropy"]
        expect = row["mnemonic"]
        ent = bytes.fromhex(entropy)
        independent = mnemonic_from_entropy(ent, words)
        if independent != expect:
            die(f"independent BIP39 != published for {entropy[:16]}")
        proc = run(["--hex-to-mnemonic", entropy])
        if proc.returncode != 0 or proc.stdout.strip() != expect:
            die(
                f"hex-to-mnemonic {entropy[:16]} rc={proc.returncode} "
                f"stdout={proc.stdout!r} stderr={proc.stderr!r}"
            )

    for row in vectors["dice"]:
        rolls = row["rolls"].encode("ascii")
        digest = hashlib.sha256(rolls).hexdigest()
        if digest != row["sha256"]:
            die(f"dice sha256 mismatch {digest}")
        independent = mnemonic_from_entropy(hashlib.sha256(rolls).digest(), words)
        if independent != row["mnemonic"]:
            die(f"independent dice mnemonic mismatch for {row['rolls'][:12]}")
        proc = run([], stdin=rolls + b"\n")
        if row["live"]:
            if proc.returncode != 0 or proc.stdout.strip() != row["mnemonic"]:
                die(f"live dice rc={proc.returncode} stdout={proc.stdout!r} stderr={proc.stderr!r}")
            if f"sha256: {row['sha256']}" not in proc.stderr:
                die(f"stderr missing hash: {proc.stderr!r}")
            if f"rolls: {len(row['rolls'])}" not in proc.stderr:
                die(f"stderr missing count: {proc.stderr!r}")
        else:
            if proc.returncode != 2:
                die(f"short dice should exit 2, got {proc.returncode} stdout={proc.stdout!r}")

    rejects = [
        b"0" * 99 + b"\n",
        b"abcdef\n",
        b"6" * 98 + b"\n",
        b"123456\n",
        b"1" * 99 + b" 2\n",
        b"1" * 4097 + b"\n",
    ]
    for blob in rejects:
        proc = run([], stdin=blob)
        if proc.returncode != 2:
            die(f"expected exit 2 for {blob[:20]!r}, got {proc.returncode}")

    # 100 rolls of 1 must be accepted (over the minimum) and match independent packing.
    hundred = b"1" * 100
    proc = run([], stdin=hundred + b"\n")
    expect = mnemonic_from_entropy(hashlib.sha256(hundred).digest(), words)
    if proc.returncode != 0 or proc.stdout.strip() != expect:
        die(f"100-roll mismatch rc={proc.returncode} stdout={proc.stdout!r}")

    print("ok")


if __name__ == "__main__":
    main()
