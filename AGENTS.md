# PGP Tool — Agent Guide

## Build & run

- **Compile**: `mvn compile`
- **Package fat JAR**: `mvn package` → `target/pgp-tool-1.0.0-SNAPSHOT.jar` (shaded)
- **Run**: `java -jar target/pgp-tool-1.0.0-SNAPSHOT.jar [flags]` or `mvn exec:java`
- **No tests** — no test framework, no test files.

## CLI flags

| Flag | Effect |
|------|--------|
| `-k` / `--key` | Show key generation tab |
| `--advanced` / `--expert` | Enable multi-signer + multi-layer encryption UI |
| `-h` / `--help` | Print usage |

Flags are parsed in `PGPTool.main()`.

## Key architecture facts

- **Java 11**, Swing GUI, **Bouncy Castle 1.84** (`bcprov-jdk18on`, `bcpg-jdk18on`)
- Packages: `model/` (data classes), `service/` (PGP logic), `ui/` (Swing)
- Entry: `io.github.epi155.pgp.PGPTool`
- `PGPEngine` is the core — all encrypt/decrypt/sign/verify logic, ~750 lines, stateful (passphrase cache, providers)
- `KeyGeneratorService.generate()` is static, uses `PGPKeyRingGenerator`
- `KeyringLoader.loadPublicKeys()` / `loadSecretKeys()` return `KeyBundle`; handle armored + binary keyrings

## BC 1.84 quirks

- **SHAKE256 (hash tag 27) not supported** anywhere in BC's OpenPGP layer (`HashAlgorithmTags`, `PGPUtil.getDigestName()`, `BcImplProvider.createDigest()`). Ed448 keys use custom `Ed448PGPContentSignerBuilder` / `Ed448PGPContentVerifierBuilderProvider` that wrap JCA `Signature.getInstance("Ed448")` + BC lightweight `SHAKEDigest(256)`.
- **Null password keys**: must use anonymous `PBESecretKeyEncryptor` subclass with `SymmetricKeyAlgorithmTags.NULL` and passthrough `encryptKeyData()`. `JcePBESecretKeyEncryptorBuilder.build(new char[0])` does NOT produce a NULL-protected key.
- **Key extraction fallback**: `extractPrivateKey()` tries JCE first, falls back to `BcPBESecretKeyDecryptorBuilder`.
- **XDH → ECDH**: `KeyGeneratorService.algoTag()` maps XDH to tag 18 (ECDH) for GPG v4 compatibility, not tag 25 (X25519).

## UI state persistence

- Window position/size and per-tab preferences via `java.util.prefs.Preferences` (derived from `MainFrame.class`'s package, `io.github.epi155.pgp`)
- `MainFrame` saves/restores window bounds on open/close
- `SendPanel` saves/restores encryption algo, compression, last paths, keyrings, signer settings

## Compound message format

- Custom format with magic bytes `PGPC` (checked in `CompoundCodec.isCompound()`)
- Stream format: text part + N binary attachment parts, each length-prefixed
- UI supports drag-and-drop attachments and save-to-disk after decryption

## Common pitfalls

- `Ed448PGPContentSignerBuilder` / `Ed448PGPContentVerifierBuilderProvider` must be used whenever hash tag 27 (SHAKE256) is the algorithm — standard BC builders throw `PGPException("unknown hash algorithm tag")`
- `DecryptResult.Metadata.hashName()` has a hardcoded switch for display names — add new hash tags there
- No test suite; verify changes by building (`mvn compile`) and running the GUI manually
