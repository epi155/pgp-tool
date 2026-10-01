# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Session-encrypted temp files** (`SecureTempFile`): decrypted literal data and tar staging areas are encrypted with ChaCha20-Poly1305 under a random per-JVM session key — plaintext is never written to disk in clear; orphans from `kill -9` hold ciphertext only
- **ZipCodec**: streaming TarArchive → ZIP export (DEFLATE) with POSIX permissions, mtime, owner/group and symlinks (Info-ZIP format)
- CLI `--zip FILE` flag to save message attachments as a single ZIP archive (alternative to `--output-dir`)
- GUI **"Export zip..."** button in ReceivePanel for tar archive ZIP export with progress
- Large entry support: decoded tar entries >50 MB are staged per-entry into session-encrypted temp files and streamed during export/extraction with bounded memory
- `TarCodec.toTarArchive(CompoundMessage)` converts legacy v1 compound attachments for the `--zip` path
- **PAX tar format** for compound messages replacing custom PGPC v1/v2 format: recursive directory support, POSIX file permissions, symlink support, and full metadata preservation
- `TarEntry`, `TarArchive`, `TarCodec` model classes for tar encode/decode
- Symlink support in tar archives (linkFlag 0x32, mode 0120777)
- POSIX file permissions preservation (644, 600, 755 etc.) during encrypt/decrypt
- Owner/group metadata preservation and restoration with POSIX `FileAttributeView`
- JTree-based attachment tree in SendPanel with recursive directory display
- Directory attachment support via file chooser and drag-and-drop in SendPanel
- Delete key binding to remove attachments in SendPanel
- Tree expansion state preservation after attachment removal
- `Ctrl+A` (select all) and `Ctrl+S` (save) key bindings in ReceivePanel
- Conflict resolver dialog (Overwrite/Skip/Rename) in ReceivePanel for duplicate files
- Status bar with click-to-dismiss feedback in ReceivePanel
- Multi-select file attachment support in SendPanel
- CLI `--attach` flag now supports directories and symlinks
- `CliException` constructors accepting a `Throwable` cause to preserve original stack traces
- `AppLog.error()` logging for all CLI failures with full stack trace in `pgp-tools.log`
- `TarArchive.extractTo()` returns `List<String>` of warnings for metadata restoration failures

### Changed

- Bouncy Castle 1.84 → 1.86 (security: 32 CVEs fixed in 1.85 including OpenPGP
  CFB quick-check oracle, inline-signature policy, AEAD final tag, Argon2 S2K and
  user-attribute DoS paths; side-channel hardening in 1.86). Compat fix:
  `CustomPGPDataEncryptorBuilder` now implements the BC 1.85 `build(byte[], byte[])`
  v2-SEIPD method (throws `UnsupportedOperationException`, custom tags never use v6 AEAD).
  Verified with RSA/ECDSA/Ed25519/Ed448 sign+verify, password layers,
  custom AEAD tags 100-104, tar+symlink round-trip and bidirectional gpg interop.
  Fat jar shrinks ~1.6 MB (bcprov 8.9 → 7.2 MB)
- commons-compress 1.26.0 → 1.28.0 (Java 8+, no removed tar/zip APIs in use); the direct
  commons-codec dependency is dropped — codec 1.19.0 (plus commons-io/commons-lang3) now
  arrives transitively via compress, which needs it at runtime
- DecryptCommand streams raw bytes (`decodeText` always `false`); removed `--text`/`--binary` flags (CLI never decoded literal data as text)
- `TarCodec.encode` stages plaintext tar through `SecureTempFile` instead of a plain temp file
- `DecryptResult` exposes `getSecureTempFile()` instead of `getTempFilePath()` — temp staging is always session-encrypted
- EncryptCommand: `Files.getLastModifiedTime` now uses `LinkOption.NOFOLLOW_LINKS` to avoid following symlinks during tar entry creation
- Attachment tree is now the source of truth for tar structure (refactored SendPanel)
- Relative paths shown in SendPanel attachment tree instead of absolute paths
- `ReceivePanel.restoreOwnership()` collects and returns warnings instead of silently swallowing exceptions
- `TarArchive.extractTo()` logs metadata restoration failures via `AppLog.error()`
- DecryptCommand prints metadata warnings to stderr
- `PGPTool.runCli()` logs all CLI failures via `AppLog.error()` in addition to stderr output
- 19 exception wrapping sites across CLI packages now pass the original exception as cause
- Warning messages translated from Italian to English

### Fixed

- Key generation now emits Issuer Fingerprint (subpkt 33) in self-certifications, subkey bindings and extra user-ID certifications, plus the Features/MDC flag (subpkt 30) in self-certifications — keys import cleanly and signatures verify in gpg, Kleopatra and Thunderbird
- Document signatures now carry Issuer Key ID + Issuer Fingerprint unhashed subpackets (both plain and tar paths)
- One-pass `nested` flag is now `true` for all but the last signer (multi-signer messages per RFC 4880 §5.4)
- `--output-dir` no longer dumps plaintext body to stdout when decrypting tar or compound messages
- GUI now shows `[Binary content — see attachment tree]` placeholder instead of garbled text when the decrypted plaintext is binary
- Signing and encryption key selection without `#id` now picks the last capable subkey per master key (gpg convention) instead of all capable keys
- GUI popups in CLI batch mode: `AppLog.setGuiDisabled(true)` prevents `JOptionPane` dialogs in headless-like CLI dispatch
- 777 permissions bug: `TarArchive.extractTo()` was calling `setLastModifiedTime` on symlinks which followed to non-existent targets, causing exceptions that prevented permission restoration on subsequent files
- Exception cause destruction in `CliException`: all 19 wrapping sites now preserve the original exception cause instead of discarding it
- Silent exception swallowing in `ReceivePanel.restoreOwnership()`: exceptions are now logged via `AppLog.error()` and collected as warnings
- `ListCommand` used wrong exception variable (`e` instead of `e2`) when reporting keyring load failure

## [1.0.0] - 2026-08-20

Initial release.
