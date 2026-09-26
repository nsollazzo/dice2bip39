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

The binary contains that file via `english_inc.h` and also reads `english.txt` from the current directory. Both must hash to the pin or the program exits. It will not warn and continue.

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

No CMake. No third-party libraries. The hash is transcribed, not linked.

```
g++ -std=c++17 -O2 -Wall -Wextra -Werror -o dice2bip39 dice2bip39.cpp
```

The binary hash is not portable across `g++` versions. The source hash is what you pin. Record `g++ -v` next to any binary you actually run in a ceremony. This tree was ported with g++ (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0.

`english.txt` must sit next to the binary when you run it. The compiler also embeds the same file through `english_inc.h`. If either copy drifts, the program exits.

## Verify the release

`v0.1.0` is a source pin, not a binary. A compiled `dice2bip39` changes with `g++`. Do not download a prebuilt binary and treat its hash as this release.

On a machine that still has a network, clone and check the tag before you copy anything to the ceremony machine:

```
git clone https://github.com/nsollazzo/dice2bip39.git
cd dice2bip39
git checkout v0.1.0
git rev-parse HEAD
sha256sum dice2bip39.cpp english_inc.h english.txt tools/check.py README.md
```

`git rev-parse HEAD` must print:

```
928723f6362f90457011a46cb5dcd78175c63e26
```

`sha256sum` must print:

```
25803ce2a1a6fbb330017fcfcf92ebc68a074a99c9aaee3b8e550b6f09df224e  dice2bip39.cpp
beecb20f4978658c07eb302fd700ce49d391fe8d510b219cb1b9825d2c1aceda  english_inc.h
2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda  english.txt
1ce42e7352126a2eda3e79173adfac775c0e612ba5c45055358f8b796262b361  tools/check.py
62bc3e7ea703867423b1191e378c4598111834023e0e541515398fbf4b3ca2ea  README.md
```

If any line differs, stop. Do not compile that tree for a ceremony. The same five lines are on the [v0.1.0 release](https://github.com/nsollazzo/dice2bip39/releases/tag/v0.1.0). Compare the release page to this file. They must match. A release page that disagrees with a tag you just checked out is the thing you do not trust.

If the ceremony machine has no `git`, copy the five files and run `sha256sum` there. The hashes are what you are checking, not the transport.

Then, still before any real rolls:

```
g++ -std=c++17 -O2 -Wall -Wextra -Werror -o dice2bip39 dice2bip39.cpp
./dice2bip39 --self-test
python3 tools/check.py
```

Both must print `ok`. Record `g++ -v` and the commit hash on paper, next to the roll sheet. A later edit of this repository gets a new tag and a new set of hashes. Do not reuse this pin after the source changes.

## Verify the program

```
python3 tools/check.py
./dice2bip39 --self-test
```

`tools/check.py` is a second implementation. It uses Python's `hashlib` (not the SHA-256 in the C++ file) to recompute BIP39 and compare. `--self-test` runs two SHA-256 implementations inside the C++ file against each other, then checks published vectors. They must agree. If they do not, exit code 1. Do not pick a favorite.

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

You need a C++17 compiler and `english.txt` in the current directory. Python is only for the second checker. The ceremony machine does not need it.

```
g++ -std=c++17 -O2 -Wall -Wextra -Werror -o dice2bip39 dice2bip39.cpp
./dice2bip39 --self-test
```

`--self-test` must print `ok` before you type anything you intend to fund. If it does not, stop. Do not roll.

### Practice, on the build machine only

Use the published 99-digit string. Those words are public. Do not fund them.

```
./dice2bip39
```

Paste or type:

```
655152231316521321611331544441236164664431121534415633526456254462245546236542364246312613322234612
```

Press Enter, then Ctrl-D. Stdout must be the SeedSigner words in the section above. Stderr must say `rolls: 99` and the SHA-256 printed next to that example. If either differs, the binary is not the one this README describes.

Do not put real rolls in a shell variable. `ROLLS=...` and `printf '%s' "$ROLLS"` land in shell history.

### Real rolls, on the ceremony machine

Write the faces on paper first. One digit per face, left to right, no spaces, no zeros, only `1` through `6`, at least 99 digits. Count them on the paper before you touch the keyboard.

Copy `dice2bip39` and `english.txt` to that machine. Do not copy your roll sheet as a file.

```
./dice2bip39 --self-test
./dice2bip39
```

Type the digit string. Press Enter. Press Ctrl-D.

You get three pieces of output:

- stderr `rolls: N` — must equal the count on your paper. If it does not, you mistyped. Stop. New rolls.
- stderr `sha256:` — write this down. A second implementation must print the same hash from the same digits.
- stdout, one line — the 24 words. Write them by hand. Do not photograph the screen. Do not copy the line to a networked computer.

Exit 0 is success. Exit 2 is bad input: a `0`, a letter, a space, fewer than 99 digits, or more than 4096. Exit 1 is an internal check failure (wordlist pin, hash disagreement, vector drift). On exit 1 or 2, do not debug with those rolls. New rolls.

`--hex-to-mnemonic` exists so the BIP39 test vectors can be checked. It is not a way to import a seed. There is no file output, no clipboard helper, and no QR code.

## Ceremony

Compile on a machine that will never see real rolls. Run the binary on a different machine that has never had a network. Two implementations must print the same 24 words from the same digits before any coins move. If they disagree, stop. New rolls. Do not debug with live entropy.

The phrase is written by hand. It is not photographed, not typed into a networked computer, and not spoken aloud.

This repository is the program. It is not the ceremony.

## What this does not stop

- A compromised `g++` that emits a different binary than the source you read.
- A compromised operating system on the machine that sees the rolls.
- A camera, microphone, or cloud keyboard in the room.
- A second implementation that was patched to lie in the same way.
- Someone reading the screen.
- Swap, a core dump, or the framebuffer retaining the words. The wipe at the end is best-effort (a volatile write so the compiler does not delete the overwrite). It is not a guarantee.

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
