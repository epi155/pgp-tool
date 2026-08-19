# PGP Tool

A cross-platform **OpenPGP** utility with both a Swing GUI and a headless batch interface.
It is built on [Bouncy Castle](https://www.bouncycastle.org/) 1.84 and is designed to
interoperate with **GnuPG** and other OpenPGP implementations.

Beyond the standard suite, PGP Tool ships a few **private-use extension algorithms**
(librepgp tags `100`–`104`, `128`) for experimenting with modern AEAD ciphers and XZ
compression. Messages produced with those extensions are only readable by this tool
(and by other tools that understand the same private tags).

## Features

- **GUI** (Swing, Java 11):
  - **Send** tab — encrypt with layered recipients/passwords, sign with one or more
    keys, attach files (compound messages), drag-and-drop support.
  - **Receive** tab — decrypt nested messages, verify signatures, save attachments,
    shows full metadata (algorithms, curves, hashes) and warns on failures.
  - **Key** tab — generate key pairs with a master key, multiple user IDs and an
    arbitrary set of subkeys (RSA, NIST/ Brainpool curves, Ed25519, Ed448, X25519, X448).
  - **Advanced mode** (`-a`): multi-signer and multi-layer encryption UI, multiple
    user IDs, subkey reordering.
- **Batch mode** (`-l`, `-g`, `-e`, `-d`) for scripting and headless use.
- **Integrity checking** on decrypt: MDC verification on every encrypted layer plus the
  armor CRC-24 — corruption anywhere **hard-fails** decryption (like gpg).
- **Custom AEAD ciphers**: Serpent-128/192/256 (OCB), ChaCha20-Poly1305 and ASCON,
  emitted as librepgp-style AEAD Encrypted Data packets.
- **XZ compression** (tag 128) for higher compression ratios.
- UI state (window position, last paths, algorithms, keyrings) persisted across runs.

## Requirements

- **Java 11+**
- **Maven 3** only if you build from source (no other runtime dependencies — the
  distribution is a self-contained fat JAR).

## Build

```bash
mvn package
```

This produces the executable shaded JAR `target/pgp-tool-<version>.jar` with all
dependencies (Bouncy Castle, XZ) bundled.

## Run

### GUI

```bash
java -jar target/pgp-tool-<version>.jar [options]
```

| Option          | Effect |
|-----------------|--------|
| `-k, --key`     | Show the **Key generation** tab |
| `-a, --advanced`| Enable advanced multi-signer / multi-layer encryption and multiple user IDs |
| `-p, --private` | Enable **private extension algorithms** (Serpent, ChaCha20-Poly1305, ASCON, XZ, SHA3) |
| `--curve448`    | Enable **Ed448/X448 key generation** (not yet supported by gpg); reading/verifying foreign Ed448 material is always active |
| `-h, --help`    | Print usage |

### Batch mode

If the first argument is a command, PGP Tool runs headless and exits with a code:

- `0` success
- `1` runtime failure (bad passphrase, corrupt message, signature verification failed, …)
- `2` usage error

Every command accepts `-h` / `--help` for its full option list
(e.g. `java -jar pgp-tool.jar -e --help`).

#### List keys in a keyring

```
java -jar pgp-tool.jar -l <keyring.asc>...
```

Shows master keys and subkeys with `[C]` (certify), `[S]` (sign), `[E]` (encrypt) and
`[A]` (authenticate) capability flags, plus the EC curve for curve-based keys. This is
the way to discover key IDs for the other commands.

#### Generate a key pair

```
java -jar pgp-tool.jar -g \
  --user-id "Alice <alice@example.com>" \
  --subkey RSA-3072:sign,encrypt \
  --subkey X25519:encrypt \
  --passphrase "correct horse battery staple" \
  --output ~/keys
```

- `--user-id` is **repeatable** for multiple identities (the first is the primary one).
- `--master SPEC` defaults to `RSA-3072`; `--master-encrypt` lets the RSA master also
  encrypt.
- `--subkey SPEC` is repeatable: `RSA-2048|RSA-3072|RSA-4096 | EC-secp256r1 |
  EC-secp384r1 | EC-secp521r1 | EC-brainpoolP256r1 | EC-brainpoolP384r1 |
  EC-brainpoolP512r1 | Ed25519 | Ed448 | X25519 | X448`, optionally followed by
  `:sign,encrypt,certify,authenticate` and `:EXP_SECONDS`. `Ed448`/`X448` need
  `--curve448`.
- Writes `<name>-public.asc` and `<name>-secret.asc` (armored) into `--output`.

#### Encrypt

```
java -jar pgp-tool.jar -e -i report.txt -o report.gpg \
  --layer KEY:~/keys/alice-public.asc:AES-256 \
  --sign-key ~/keys/alice-secret.asc
```

- Layers are given **inner to outer** and are repeatable:
  - `KEY:file[#id][;file[#id]]...:ALGO` — encrypt to one or more public keys.
  - `PASS:ALGO` — password layer; the password comes from a separate
    `--password` / `--password-file` (or `-` for stdin), never from the layer string.
  - Without `#id`, **every** encryption-capable key in the keyring is used (never
    Bouncy Castle's "last subkey"). `#id` selects exactly one key by short
    (`0xABCDEF12`), full 16-hex, or 32-hex fingerprint.
- `ALGO`: AES-128/192/256, CAST5, Blowfish, Triple-DES, Twofish,
  Camellia-128/192/256; with `-p` also Serpent-128/192/256, ChaCha20-Poly1305, ASCON.
- `--sign-key SPEC` (repeatable): `file[#id][:passphrase][:HASH]`; HASH is SHA-256
  (default), SHA-384, SHA-512, or (with `-p`) SHA3-256, SHA3-512.
- `--compress ALGO`: ZIP, ZLIB (default), BZIP2, UNCOMPRESSED; with `-p` also XZ.
- `--attach FILE` (repeatable) packages the files as a **compound message** together
  with the text input.
- `--armor` (default) / `--no-armor`; `--force` overwrites an existing output;
  input/output default to stdin/stdout.

#### Decrypt

```
java -jar pgp-tool.jar -d -i report.gpg -o report.txt \
  --secret-key ~/keys/alice-secret.asc:pass \
  --verify-key ~/keys/bob-public.asc
```

- Nested messages are unwrapped automatically; every encrypted layer is integrity
  checked (MDC), and armored messages get their CRC-24 validated — corrupt data
  **fails the whole operation**.
- `--secret-key SPEC` (repeatable): `file[:passphrase]`. The key is selected
  automatically from the message's recipient IDs; `#id` is only needed when several
  keys in one file use different passphrases (e.g. `file#0xID1:pass1 file#0xID2:pass2`).
- `--password` values for password layers are consumed in decrypt order
  (outermost layer first).
- `--verify-key FILE` (repeatable) verifies signatures; the signer is matched from the
  signature itself. Exit status is `1` if any signature fails verification.
- `--output-dir DIR` saves message attachments; `--text` (default) / `--binary`.

## Notes on key selection

- Key selection is **explicit**: you always say exactly which key(s) to use, and the
  tool errors out when a requested key is missing, ambiguous, not encrypt/sign capable,
  revoked, or expired.
- `--list` is the quickest way to see the IDs and capabilities available in a keyring.

## Compatibility

- Interoperates with **gpg** for standard keys and messages (RSA, ECDSA/ECDH, Ed25519,
  X25519, AES, Twofish, Camellia, ZIP/ZLIB/BZIP2, SHA-256/384/512, SHA3).
- **Ed448/X448 key generation is gated** behind `--curve448` because gpg does not
  support Curve 448 yet. Once gpg ships it, the gate can simply be lifted.
- Custom extension tags (`100`–`104` AEAD ciphers, `128` XZ compression) are **not
  interoperable** with gpg: only this tool reads messages using them.

## Security notes

- Passphrases are never written on the command line inside layer definitions; use
  `--password`, `--password-file` or `-` (stdin) instead.
- A wrong/missing passphrase on a secret key is reported as
  `checksum mismatch in checksum of 2 bytes` and translated into a clear
  "passphrase required" error naming the key.
- The tool follows standard OpenPGP practice: ZLIB compression by default, MDC integrity
  protection on encrypted data, armor CRC-24 on armored output.

## Releases

Distribution is **GitHub Releases only** (no Maven Central, no GPG signing). Pushing a
`vX.Y.Z` tag triggers the CI workflow, which builds the fat JAR, computes its SHA-256 and
publishes both to GitHub. See `RELEASE.md` for the full flow.

## License

MIT — see [LICENSE](LICENSE).
