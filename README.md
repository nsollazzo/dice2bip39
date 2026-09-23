# dice2bip39

Dice digits in. Twenty-four BIP39 English words out. Nothing else.

This program does not generate entropy. It does not call a random number generator. It does not derive a BIP32 seed, an xpub, an address, or a fingerprint. If you wanted a wallet, this is not one.

The digits you type are the secret, from the first character. Do not type a phrase you intend to fund into a machine that has a network, a camera, or a disk you will keep.

## Algorithm

1. The input is a string of ASCII digits `1` through `6`. No spaces. No `0`. Minimum 99 digits, maximum 4096. Fewer than 99 is a hard error.
2. Entropy is `SHA-256` of those bytes. All 32 bytes. Nothing is truncated and nothing is mixed with output from the operating system.
3. Those 32 bytes become a 24-word mnemonic by BIP39: checksum is the first 8 bits of `SHA-256(entropy)`, appended to the entropy, then split into 24 indices of 11 bits, big-endian, into the English wordlist.[1]

This is the same dice encoding Coldcard's `rolls.py` uses (`SHA-256` of the ASCII digit string, full digest, 24 words)[4] and the same encoding SeedSigner uses for 99 rolls.[6][7] SeedSigner truncates the digest to 16 bytes only for a 50-roll, 12-word path. This program refuses that path.

**Do not verify these rolls in Ian Coleman's "Dice [1-6]" mode.** That mode rewrites a face of 6 into 0. SeedSigner's own verification note says to use Hex or Base 10 of the digit string, not Dice mode.[6] A 6-to-0 rewrite will not match this program, Coldcard, or SeedSigner. If a backup card says KEYSTONE, it is a different encoding. Do not check it here and assume a match.

The English wordlist is the BIP39 list: 2048 words, `abandon` through `zoo`, first four letters unique.[1][2] This repo pins the file bytes:

```
2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda
```

The binary contains that file via `include_str!` and also reads `english.txt` from the current directory. Both must hash to the pin or the program exits. It will not warn and continue.

## What a published vector is

The vectors below are public. They have been printed in other people's docs. **Do not fund them.** They exist so you can see that this program, Coldcard, and SeedSigner emit the same words from the same digits before you roll dice of your own.

SeedSigner 99-roll example:[6]

```
655152231316521321611331544441236164664431121534415633526456254462245546236542364246312613322234612
```

SHA-256 of that string:

```
51531761ec7a738946e0b9f46bb11320a695495430e345c14f01ad8b3b898a6d
```

Words:

```
eyebrow obvious such suggest poet seven breeze blame virtual frown dynamic donor harsh pigeon express broccoli easy apology scatter force recipe shadow claim radio
```

Coldcard's short example `123456` hashes to `8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92` and encodes as `mirror reject rookie talk pudding throw happy era myth already payment own sentence push head sting video explain letter bomb casual hotel rather garment`.[4][5] Six digits are below the live minimum. This program rejects them on purpose. The self-test still checks the encoding.

BIP39 itself points at the Trezor `vectors.json` file for entropy-to-mnemonic checks.[1][3] The rows in `tests/vectors.json` were copied from that file. The passphrase `TREZOR` seed column in the upstream file is not checked here, because this program does not run PBKDF2.

## Build

No Cargo. No crates.

```
rustc -C opt-level=2 -C debuginfo=0 -C strip=symbols dice2bip39.rs -o dice2bip39
```

The binary hash is not portable across `rustc` versions. The source hash is what you pin. Record `rustc -vV` next to any binary you actually run in a ceremony. This tree was developed with rustc 1.97.1 (`8bab26f4f68e0e26f0bb7960be334d5b520ea452`).

`english.txt` must sit next to the binary when you run it. The compiler also embeds the same file. If either copy drifts, the program exits.

## Verify

```
python3 tools/check.py
./dice2bip39 --self-test
```

`tools/check.py` is a second implementation. It uses Python's `hashlib` (not the Rust SHA-256 in this file) to recompute BIP39 and compare. `--self-test` runs two SHA-256 implementations inside the Rust file against each other, then checks published vectors. They must agree. If they do not, exit code 1. Do not pick a favorite.

SHA-256 vectors the self-test requires:

| Input | Digest | Where it was read |
|---|---|---|
| empty | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | Coldcard `rolls.py` empty-input constant[4] |
| `abc` | `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad` | NIST SHA-256 example PDF[9]; NIST NSRL informal page[10] |
| two-block sample `abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq` | `248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1` | same NIST PDF and NSRL page[9][10] |
| 1,000,000 × ASCII `a` | `cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0` | NIST NSRL informal page[10] |

FIPS 180-4 is the algorithm specification.[8] The example PDF is the vector source that was actually fetched for `abc` and the two-block message. The empty-string digest is cited from Coldcard's script, not claimed as a line copied out of the FIPS PDF.

A green `check.py` means: this source, this wordlist, and Python's SHA-256 agree on published dummy data. It does not mean your compiler is honest, your ceremony machine is clean, or your room has no camera.

## How to run

```
./dice2bip39 --self-test
printf '%s\n' "$ROLLS" | ./dice2bip39
```

Stdout is the 24 words, once. Stderr is the roll count and `SHA-256` of the digit string. Exit 0 on success, 1 on an internal check failure, 2 on bad input.

There is no file output, no clipboard helper, and no QR code. `--hex-to-mnemonic` exists so the BIP39 test vectors can be checked. It is not a way to import a seed.

## Ceremony

Compile on a machine that will never see real rolls. Run the binary on a different machine that has never had a network. Two implementations must print the same 24 words from the same digits before any coins move. If they disagree, stop. New rolls. Do not debug with live entropy.

The phrase is written by hand. It is not photographed, not typed into a networked computer, and not spoken aloud.

This repository is the program. It is not the ceremony.

## What this does not stop

- A compromised `rustc` that emits a different binary than the source you read.
- A compromised operating system on the machine that sees the rolls.
- A camera, microphone, or cloud keyboard in the room.
- A second implementation that was patched to lie in the same way.
- Someone reading the screen.
- Swap, a core dump, or the framebuffer retaining the words. The wipe at the end is best-effort (`black_box` so LLVM does not delete the overwrite). It is not a guarantee.

Defeat of the hash, the wordlist, or the bit packing must not silently produce a funded wallet you cannot reconstruct. That is why the program aborts when its two SHA-256 implementations disagree, and why a second language checks the same vectors.

## License

MIT. Copyright Nicholas Sollazzo. See `LICENSE`.

## Sources

[1] BIP-39: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki

[2] BIP-39 English wordlist: https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt

[3] Trezor python-mnemonic test vectors: https://github.com/trezor/python-mnemonic/blob/master/vectors.json

[4] Coldcard `rolls.py`: https://github.com/Coldcard/firmware/blob/master/docs/rolls.py

[5] Coldcard dice-roll math: https://coldcard.com/docs/verifying-dice-roll-math/

[6] SeedSigner dice verification: https://github.com/SeedSigner/seedsigner/blob/dev/docs/dice_verification.md

[7] SeedSigner mnemonic generation: https://github.com/SeedSigner/seedsigner/blob/main/src/seedsigner/helpers/mnemonic_generation.py

[8] FIPS 180-4: https://csrc.nist.gov/pubs/fips/180-4/final

[9] NIST SHA-256 example computation: https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/sha256.pdf

[10] NIST NSRL informal SHA test data: https://www.nist.gov/itl/ai/ai-standards-and-guidelines-group/nsrl-test-data
