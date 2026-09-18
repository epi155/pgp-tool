# PGP Tool — Agent Guide

## Build & run

- **Compile**: `mvn compile`
- **Package fat JAR**: `mvn package` → `target/pgp-tool-1.0.1-SNAPSHOT.jar` (shaded)
- **Run**: `java -jar target/pgp-tool-1.0.1-SNAPSHOT.jar [flags]` or `mvn exec:java`
- **No tests** — no test framework, no test files.

## Release (GitHub Actions)

Distribution is **GitHub Releases only** (no Maven Central, no GPG signing — `maven-gpg-plugin` and
`central-publishing-maven-plugin` were removed from the pom). Flow:

1. `mvn release:prepare` (config in pom: `pushChanges=false`, `tagNameFormat=v@{version}`) — bumps
   `X.Y.Z-SNAPSHOT` → `X.Y.Z`, commits `release vX.Y.Z`, tags `vX.Y.Z`, commits next baseline.
2. Manual push: `git push origin master && git push origin vX.Y.Z`.
3. Tag `vX.Y.Z` triggers `.github/workflows/release.yml`: builds the fat jar, writes a `.sha256`, and
   creates the GitHub Release with both files via `softprops/action-gh-release`.

Full details in `RELEASE.md`. The pom must keep a **3-component** version (`1.0.0-SNAPSHOT`, never
`1.0-SNAPSHOT`) so `release:prepare` produces `v1.0.0` and the `tags: ['v*']` trigger fires.
`dependency-reduced-pom.xml` and `release.properties` are gitignored.

## CLI flags

### GUI flags

| Flag | Effect |
|------|--------|
| `-k` / `--key` | Show key generation tab |
| `-a` / `--advanced` | Enable multi-signer + multi-layer encryption UI |
| `-h` / `--help` | Print usage |

GUI flags are parsed in `PGPTool.main()`. `BouncyCastleProvider` is registered for **both** GUI and CLI paths.
`AppLog.setGuiDisabled(true)` is called before CLI dispatch to prevent uncaught-exception handler from
showing `JOptionPane` popups in batch mode.

### Batch commands (headless, in `cli/` package)

If `args[0]` is a command, `PGPTool.main()` dispatches to `Cli.run()` and exits with 0/1/2
(0 success, 1 runtime failure, 2 usage error) — see `CliException.isUsage()`.

| Command | Purpose |
|---------|---------|
| `-l` / `--list <keyring.asc>...` | List master keys + subkeys with `[C]`/`[S]`/`[E]`/`[A]` capability (certify/sign/encrypt/authenticate) |
| `-g` / `--generate ...` | Generate a key pair (armored `<name>-public.asc` / `<name>-secret.asc`) |
| `-e` / `--encrypt [file]` | Encrypt to KEY/PASS layers, sign, optional attachments (directories/symlinks via tar) |
| `-d` / `--decrypt [file]` | Decrypt nested messages, save attachments, verify signatures |

**Ed448/X448 key generation is gated behind a dedicated `--curve448` flag** (GUI `KeyTabPanel`
combos and CLI `-g --master/--subkey Ed448|X448` → `GenerateCommand.parseSpec`): gpg does not
support Curve448 yet. It lives on its **own** flag — not under `-p/--private`, which stays strictly
for private-use extension algorithms (Serpent/ChaCha/ASCON/XZ/SHA3). This is a **transitory gate**:
to lift it when gpg ships Curve448, drop the `if (!curve448Enabled)` checks in
`GenerateCommand.parseSpec`, the `filterCurve448()` filtering in `KeyTabPanel`, and the `--curve448`
parsing in `PGPTool`/`Cli`/`MainFrame`. Reading/decrypting/verifying foreign Ed448 material is
**always** active.

Each command supports `-h` / `--help`. Key selection is **explicit**: `--layer KEY:file[#id]:ALGO` /
`--sign-key file[#id][:pass][:HASH]` / `--secret-key file[#id][:pass]` resolve to exactly the
requested keys via `cli/KeySelector` (short 0x-8-hex, full 16-hex, or 32-hex fingerprint; errors
if missing/ambiguous/not encrypt-or-sign capable/revoked/expired). With no `#id`, **every**
capable key in the keyring is used (never BC's "last subkey"). `--list` is the way to discover IDs.
For `--secret-key` the key is selected automatically from the message's recipient IDs; `#id` there
only associates a per-key passphrase when several keys in one file use different ones.
`--verify-key` takes a plain keyring path (the signer is resolved from the signature, never a `#id`).

Layer order is inner→outer on `--encrypt`; `--password` values for decrypt are consumed
outermost-PASS-layer-first (engine does `pbePasswords.remove(0)` while unwrapping). Passwords are
never inline in `--layer`; they come from repeatable `--password`, `--password-file`, or `-` (stdin).
Default compression is ZLIB (same as the GUI and gpg).

## Key architecture facts

- **Java 11**, Swing GUI, **Bouncy Castle 1.84** (`bcprov-jdk18on`, `bcpg-jdk18on`), **commons-compress 1.26.0**, **commons-codec 1.17.1**
- Packages: `model/` (data classes), `service/` (PGP logic), `ui/` (Swing), `cli/` (headless batch commands)
- Entry: `io.github.epi155.pgp.PGPTool`
- `PGPEngine` is the core — all encrypt/decrypt/sign/verify logic, ~770 lines, stateful (passphrase cache, providers)
- `KeyGeneratorService.generate()` is static, uses `PGPKeyRingGenerator`. **Multiple user IDs**: `KeyConfig.userIds` is a list; the first UID goes to `PGPKeyRingGenerator`, extra UIDs get positive self-certifications via
`PGPSignatureGenerator` + `PGPPublicKeyRing.insertPublicKey` (replaces the master by keyID — do NOT `removePublicKey` the master first, the intermediate ring is invalid), then `PGPSecretKeyRing.replacePublicKeys` syncs the secret ring. CLI: `--user-id` repeatable; GUI: only in advanced mode (`KeyTabPanel(advanced, curve448)` adds "Add User ID"/"X Remove" rows plus an up-arrow icon button on each row that swaps the row's text with the one above — the first row swaps with the primary, non-removable User ID field). Subkey rows (`SubKeyRow`) also get an up-arrow button that swaps the whole row with the one above it (`moveSubKeyUp`, no-op at index 0); the topmost subkey's button is disabled (`refreshSubkeyUpButtons`), the master key is never swappable.
- `KeyringLoader.loadPublicKeys()` / `loadSecretKeys()` return `KeyBundle`; handle armored + binary keyrings
- `KeyringLoader` also resolves each key's EC curve name (`PGPKeyInfo.curve`, `KeyringLoader.curveName()`) from the key packet: `X25519/X448/Ed448/Ed25519` packet classes plus `ECPublicBCPGKey.getCurveOID()` mapped through `ECNamedCurveTable.getName()` with aliases (`curve25519`→`X25519`, `1.3.6.1.4.1.11591.15.1`→`Ed25519`, `prime256v1/384v1/521v1`→`secp256r1/384r1/521r1`); shown as `ECDH 256b (secp256r1)` in `--list` and the GUI tree, and in decrypt metadata (`DecryptResult.EncryptionLayer.curve`, `SignerInfo.curve` → `ECDH (X25519)/AES-256`, `ECDSA (brainpoolP384r1)`) for both CLI and GUI
- `cli/KeySelector` flattens `KeyBundle` (masters + nested subkeys), resolves `#id` filters, checks
  `canEncrypt`/`canSign` and revocation/expiration (`PGPPublicKey.isRevoked()`/`getValidSeconds()`)
- `cli/{Generate,Encrypt,Decrypt,List}Command` reuse `PGPEngine`/`KeyGeneratorService`/`CompoundCodec`
  exactly like the GUI panels do (first layer = `encrypt`/`encryptPassword` with sign+compress,
  outer layers = `encryptRaw`/`encryptRawPassword`, armor only on the outermost layer)

## BC 1.84 quirks

- **SHAKE256 (hash tag 27) not supported** anywhere in BC's OpenPGP layer (`HashAlgorithmTags`, `PGPUtil.getDigestName()`, `BcImplProvider.createDigest()`). Ed448 keys use custom `Ed448PGPContentSignerBuilder` / `Ed448PGPContentVerifierBuilderProvider` that wrap JCA `Signature.getInstance("Ed448")` + BC lightweight `SHAKEDigest(256)`.
- **Null password keys**: must use anonymous `PBESecretKeyEncryptor` subclass with `SymmetricKeyAlgorithmTags.NULL` and passthrough `encryptKeyData()`. `JcePBESecretKeyEncryptorBuilder.build(new char[0])` does NOT produce a NULL-protected key.
- **Key extraction fallback**: `extractPrivateKey()` tries JCE first, falls back to `BcPBESecretKeyDecryptorBuilder`.
- **XDH → ECDH**: `KeyGeneratorService.algoTag()` maps XDH to tag 18 (ECDH) for GPG v4 compatibility, not tag 25 (X25519).

## Custom AEAD tags (100-102 Serpent-OCB, 103 ChaCha20-Poly1305, 104 ASCON)

All five custom symmetric tags are AEAD streams (no MDC; `getIntegrityCalculator()` returns `null`), emitted as
LibrePGP-style **AEAD Encrypted Data packets (tag 20, version 1)** that BC 1.84 parses back. Shared framing lives in
`CustomAeadEncryptor`, which dispatches on the tag to an internal `AeadEngine` (interface:
`init(forEnc, nonce)`, `updateAad(bytes)`, `finish(in, off, len)`):

- **103** (`CustomAlgorithms.CHACHA20_POLY1305`): JCE `Cipher "ChaCha20-Poly1305"` (BC provider). Packet byte
  `aeadAlgorithm=GCM(3)` → BC derives a **12-byte** IV (`AEADUtils.getIVLength`). gpg shows `cipher=103 aead=3 cb=10`.
- **100-102 | Serpent-128/192/256** (`SerpentTags`): lightweight `OCBBlockCipher(new SerpentEngine(), new SerpentEngine())` +
  `AEADParameters(key, 128, nonce)` (OCB3, RFC 7253). Packet byte `aeadAlgorithm=OCB(2)` → BC derives a **15-byte** IV; gpg shows
  `cipher=100/101/102 aead=2 cb=10`. User-facing labels remain "Serpent-128/192/256".
- **104 | ASCON** (`AsconTags.ASCON_128`): lightweight `AsconEngine(AsconEngine.AsconParameters.ascon128)` (BC 1.84,
  NIST SP 800-232 family) + `AEADParameters(key, 128, nonce)`. ASCON uses a 128-bit nonce, so the packet byte is
  `aeadAlgorithm=EAX(1)` → BC derives a **16-byte** IV; gpg shows `cipher=104 aead=1 cb=10`. The EAX byte is a
  **masquerade** (the construction is ASCON, not EAX) — only this tool reads these messages. User-facing label "ASCON".

The `aeadAlgorithm` byte in the packet drives the IV/nonce length **derived by BC on read** (not an explicit field):
GCM(3)→12B, OCB(2)→15B, EAX(1)→16B. `CustomAeadEncryptor` computes `aeadAlgorithm()`/`ivLength()` from the tag
(103 → GCM/12B; Serpent → OCB/15B; ASCON → EAX/16B). Editing a tag's mode means keeping this in sync.

Wire format per chunk (64 KiB, encoded size 10) — `AeadEncryptingStream`/`AeadDecryptingStream` mirror
`BcAEADUtil.PGPAeadOutputStream/InputStream`:
- Chunk nonce = IV xor chunk index (last 8 bytes of the IV; works for 12/15/16-byte IVs).
- AAD = 5-byte `createAAData(VERSION_1, tag, aeadAlgorithm, 10)` + 8-byte BE chunk index; each chunk = `ct + 16B tag`.
- Final 16B tag (nonce with the *next* chunk index, AAD + 8-byte BE `totalBytes`) authenticates the length.
- **Writer**: per-chunk `doFinal` = ct+tag; final empty `doFinal` = final tag; `close()` on the
  `BCPGOutputStream(out, PacketTags.AEAD_ENC_DATA, buffer)` partial-length packet.
- **Reader**: **look-ahead scheme**: prime `2*tagLen` bytes in the constructor; each `readBlock` reads at
  `buf[2*tagLen..)` (up to chunkLength), feeds `buf[0..dataLen+tagLen)` (ct+tag) to the engine via `processBytes`
  then `doFinal` (this is exactly how `BcAEADUtil` handles chunk-aligned messages), copies `buf[dataLen+tagLen..)`
  back to `buf[0..tagLen)`, then either reads the next `tagLen` (full chunk) or verifies the final tag (short chunk).
  A `dataLen==0` block also verifies the final tag (chunk-aligned messages). Do NOT use a read-up-to-EOF helper: it
  would swallow the trailing tags.
- Decrypt wraps `InvalidCipherTextException` into `IOException`. **Note**: OCB3 needs both cipher
  directions (E and E⁻¹), so two `SerpentEngine` instances; nonce reuse is catastrophic, but the
  monotonic chunk index (final tag on the *next* index) keeps nonces distinct.
- The generator (`CustomEncryptedDataGenerator.open()`) branches: for a `PGPAEADDataEncryptor` it writes the
  `AEADEncDataPacket` then returns a `FilterOutputStream` whose `close()` runs the generator close.
- Decrypt factories `CustomAwarePublicKeyDataDecryptorFactory` / `CustomAwarePBEDataDecryptorFactory` override
  `createDataDecryptor(AEADEncDataPacket, PGPSessionKey)`; if `CustomAlgorithms.isAead(sessionKey.getAlgorithm())`
  (100-104) they build `CustomAeadEncryptor(sessionKey.getAlgorithm(), sessionKey.getKey(), iv, chunkSize)`, else
  delegate to the JCE factory.
- **ESK wrapping is unchanged and does NOT depend on the AEAD mode**: SKESK v4 / PKESK v3 wraps the session key in
  CFB for 100-102 (`Serpent/CFB/NoPadding`); tag 103 alone uses the CHACHA7539 convention (`isChaCha20` route in
  `CustomPBEKeyEncryptionMethodGenerator` / `CustomAwarePBEDataDecryptorFactory`). Tag 104 (ASCON) is AEAD-only
  with no stream/CFB mode, so its ESK is wrapped through a **proxy AES-CFB** cipher — both sides go through
  `CustomAlgorithms.eskWrapName()` (Serpent/CHACHA7539/AES), and `makeIv` returns a full 16-byte block. Only the
  **data** packet is AEAD.

## Custom compression tag (128 XZ)

- BC's `PGPCompressedDataGenerator` only accepts IDs 0-3 (`CompressionAlgorithmTags`) and
  `PGPCompressedData.getDataStream()` throws "can't recognise compression algorithm" for anything else.
  Custom private-use IDs are dispatched via `service/CustomCompression` (`isCustom`/`name`/`compress`/`decompress`):
  128 = XZ (streaming LZMA2, `org.tukaani:xz`, `XZOutputStream`/`XZInputStream`, default preset).
  129 was ZSTD (`com.github.luben:zstd-jni`) but was **removed** (JNI natives limited the fat jar to
  x86_64 Linux/Windows; XZ's ratio + acceptable speed made ZSTD redundant). Messages compressed with
  tag 129 by older builds are **no longer readable**.
- **Writer** (`PGPEngine.openCompressedData`, used by `encrypt`/`encryptPassword`/`encryptCompress`): IDs 0-3
  go through BC's generator; custom IDs go through `CustomCompressedDataGenerator`, which mirrors BC's pattern —
  writes `BCPGOutputStream(out, PacketTags.COMPRESSED_DATA)` + the algorithm byte, then streams the codec over a
  `NonClosingOutputStream` adapter so the codec's `close()` finalises its footer without closing the packet;
  `CustomCompressedDataGenerator.close()` then does `pkOut.finish()` + `flush()` (packet end, outer encrypted
  stream stays open). Only the innermost layer compresses (same as before); `encryptRaw*` never compresses.
- **Reader** (`PGPEngine` decompress path): if `compData.getAlgorithm()` is custom, wrap
  `compData.getInputStream()` (raw bytes) with `CustomCompression.decompress(...)` instead of `getDataStream()`.
- **Not interoperable**: gpg and other tools do not know the 128 byte and cannot decrypt such messages
  (same caveat as the custom AEAD ciphers). Compression level is fixed (XZ default preset 6);
  a `--compress-level` knob would be a future extension.

## Session-encrypted temp files (`service/SecureTempFile`)

Decrypted literal data and tar staging areas are **never written in clear to disk**.
`SecureTempFile` encrypts every temp with **ChaCha20-Poly1305** (JCE, JDK 11+) under a
random 256-bit **session key generated once per JVM launch** (heap-only, zeroed by a
shutdown hook). Each file gets its own random 96-bit base nonce (clear header);
per-chunk nonce = `base XOR chunkIndex`, 64 KiB plaintext chunks + 16 B Poly1305 tag
each (per-chunk integrity, random-access slice reads, plaintext-offset semantics so
recorded attachment offsets stay valid).

- Private dir `pgp-tool-secure-*` under `java.io.tmpdir`, `0700`; files `0600`
  (POSIX enforced, best-effort elsewhere). `wipeAndDelete()` zero-passes the
  ciphertext before unlinking; `deleteOnExit` + shutdown-hook cleanup as backstop.
- Orphans from `kill -9` hold **ciphertext only** (unreadable: the session key died
  with the JVM) and dirs older than 24h are swept on next temp creation.
- Users: `PGPEngine` decrypt staging (`pgp-nested-decrypt-*.bin`, owned by the
  `DecryptResult` until GUI `cleanupTempFiles()` / CLI `finally`), `TarCodec`
  encode/decode staging (`tar-*.tar`, wiped in `finally`).
- `InputStream.read()` may return short reads from the decrypting stream — always
  loop (`TarCodec.readFully`) instead of assuming full buffers.

## UI state persistence

- Window position/size and per-tab preferences via `java.util.prefs.Preferences` (derived from `MainFrame.class`'s package, `io.github.epi155.pgp`)
- `MainFrame` saves/restores window bounds on open/close
- `SendPanel` saves/restores encryption algo, compression, last paths, keyrings, signer settings

## Send UI file dialog

- `SendPanel.chooseOutputFile()` (file/attachment output mode) opens a save dialog whose active filter is
  `Encrypted files (*.gpg, *.pgp, *.asc)`; the built-in "All Files" accept-all stays as second choice.
- If the typed name has no extension and the encrypted filter is selected, the chosen extension is auto-appended:
  `asc` when `armorCheckBox` is checked (default), else `gpg`.

## Send UI attachment tree

- The JTree (`attachRoot`) is the **source of truth** for both display and tar structure.
- `addFileToTree(File, AttachmentNode)` adds a single file node under the target.
- `addDirectoryToTree(File, AttachmentNode)` recursively walks the directory and adds FILE nodes
  for each file found. Intermediate DIRECTORY nodes are created for visual hierarchy.
- `getTarPath(AttachmentNode)` computes the tar entry path by walking up the tree from the
  file node to `attachRoot`, joining display names with `/`.
- `addTarEntriesFromTree(AttachmentNode, TarArchive)` walks the tree and creates `TarEntry`
  objects with the computed tar paths — this is what `onEncrypt` calls.
- DnD drop target: dropping on a DIRECTORY places items as children; dropping on a FILE or
  empty space places items as siblings (in the parent directory).
- `removeAttachment` removes the selected node (and all children) from the tree and from
  `attachmentFiles`.

## Compound message format (legacy, read-only)

- Custom format with magic bytes `PGPC` (checked in `CompoundCodec.isCompound()`)
- Stream format: text part + N binary attachment parts, each length-prefixed
- Only used for backward-compatible reading of old v1 messages; new encrypt always produces tar v3

## Tar archive format (v3)

New encryption produces PAX tar archives (`LONGFILE_POSIX`) with full metadata preservation:

- **TarEntry**: wraps `TarArchiveEntry` with POSIX permissions, symlink support, and mode tracking.
  `TarEntry.fromPath()` reads `PosixFileAttributes` for permissions and uses `Files.isSymbolicLink()`
  for symlink detection. The `linkFlag` is set via reflection because `TarArchiveEntry.setMode(int)`
  does not update the internal `linkFlag` field.
- **TarArchive**: hierarchical model (root entry + children). `writeTo()` streams via
  `TarArchiveOutputStream` with `LONGFILE_POSIX` format. `extractTo(Path)` recreates the tree
  including symlinks (via `Files.createSymbolicLink`) and POSIX permissions (via
  `Files.setPosixFilePermissions`). `getFlatEntries()` returns all entries in tree order.
- **TarCodec**: encode/decode between `TarArchive` and byte stream. `encode(TarArchive, OutputStream)`
  stages through a session-encrypted `SecureTempFile` (plaintext tar never hits disk in clear). `decode()` handles v3 tar format and falls
  back to v1 `CompoundCodec` for backward compatibility. `toTarArchive(CompoundMessage)` converts legacy
  attachments for the `--zip` path.
- **ZipCodec** (`model/ZipCodec.convert`, DEFLATE default): streaming `TarArchive` → ZIP used by
  Receive `Export zip...` and CLI `--decrypt --zip`. Per entry: full path, POSIX mode, mtime,
  numeric uid/gid via `AsiExtraField` (best-effort; user/group *names* have no portable ZIP field),
  symlinks as Info-ZIP links (target bytes + `S_IFLNK`, STORED with precomputed CRC — STORED entries
  require upfront CRC when streaming). Dirs STORED size 0/crc 0. UTF-8 names + language flag.
  Large entries stream from session-encrypted staging (see below), never heap-materialized.
- **Large entries**: decoded tar entries >50 MB are staged per-entry into their own `SecureTempFile`
  (`TarCodec.decodeTar`) and referenced as `TarEntry(secureTemp, offset, length)` slices, so tar/zip
  export and `--output-dir` extraction stream them with bounded memory. The staging files are owned by
  the `TarArchive` (`addStagingTemp`/`dispose()`; GUI disposes on next decrypt/clear, CLI in `finally`).
  `extractTo()` warns instead of silently writing empty files when an entry has no readable content.
- **Large literals**: decrypted content >50 MB stays off-heap (`rawData == null`); compound detection
  then uses a 4-byte slice probe (`PGPEngine.compoundProbe`) so tar/zip export still works streaming.
- **PGPEngine**: `writeSignAndLiteralTar()` encodes the tar to bytes and writes a signed+literal
  data packet. Single attachment without directories produces a gpg-compatible literal data packet;
  multiple attachments or directories produce tar v3.

### Symlink handling

- Symlinks are detected via `Files.isSymbolicLink()` during `TarEntry.fromPath()`
- `linkFlag` set to `0x32` (`LF_SYMLINK`) via reflection (`TarEntry.setLinkFlag()`)
- Mode set to `0120777` (symlink); `isSymbolicLink()` checks `(mode & 0170000) == 0120000`
- `TarArchive.extractTo()` creates symlinks via `Files.createSymbolicLink(target, Path.of(linkName))`
- `setLastModifiedTime()` is skipped for symlinks (it follows symlinks and fails if the target
  doesn't exist yet during flat-order extraction)

### Known quirks

- **commons-compress 1.26**: `TarArchiveEntry.setMode(int)` does NOT update the internal `linkFlag`
  field — use reflection to set it for symlinks
- **commons-compress 1.26**: `TarArchiveEntry(File, String)` constructor does NOT read POSIX permissions
  from the filesystem — always returns default 0100644; must use `PosixFileAttributes` explicitly
- **Permission fix**: `setLastModifiedTime` follows symlinks; if the symlink target doesn't exist yet
  (flat extraction order), it throws `NoSuchFileException` — must skip mtime set for symlinks
- `TarCodec.encode(TarArchive)` (byte[] overload) still buffers in memory; both overloads
  stage the plaintext tar through a session-encrypted `SecureTempFile`

## Common pitfalls

- `Ed448PGPContentSignerBuilder` / `Ed448PGPContentVerifierBuilderProvider` must be used whenever hash tag 27 (SHAKE256) is the algorithm — standard BC builders throw `PGPException("unknown hash algorithm tag")`
- **Signature hashes**: the selectable set (CLI `--sign-key ...:HASH`, GUI `hashCombo`) is **SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-512** (RIPEMD160 removed). `Names.hash()` / `SendPanel.mapHashAlgo()` map names to tags; `DecryptResult.Metadata.hashName()` renders them. Only tags 12/14 (SHA3-256/SHA3-512) are standard in BC 1.84 — `HashAlgorithmTags.SHA3_224/384` are **312/314, non-standard**, so SHA3-384/224 cannot be signed interoperably (the packet would carry the wrong tag); they exist in `hashName()` only as display labels for foreign messages. Ed25519 forces SHA-512 and Ed448 forces SHAKE256 via `PGPEngine.defaultHashForAlgo()` (a requested hash is ignored for those keys). SHA3 JCA names are `SHA3-256with{RSA,ECDSA}`/`SHA3-512with{RSA,ECDSA}` (BC provider).
- **`checksum mismatch in checksum of 2 bytes`** = wrong/missing passphrase on a secret key. `PGPEngine.extractPrivateKey()` translates it to `PassphraseRequiredException` (key ID + first user-id); `EncryptCommand`/`DecryptCommand` catch it and prepend the keyring path
- **Decrypt integrity**: after fully reading each encrypted layer, `PGPEngine.verifyEncryptionIntegrity()` calls `PGPEncryptedData.verify()` (inner→outer) — the MDC is compared, and on the outermost armored layer the decrypting stream is drained to EOF so the **armor CRC24** fires on the `=XXXX` line. Corruption anywhere in an armored/binary message now **hard-fails** decryption (`Integrity check failed (MDC)` or `crc check failed in armored message`), matching gpg. Layers without integrity protection (old no-MDC messages, `isIntegrityProtected()` false) are skipped; AEAD layers (100-104) self-verify during reading. `decryptNestedToFile` also drains the input to EOF after parsing, so unencrypted armored messages (signed/compressed only) get their CRC checked too.
- `DecryptResult.Metadata.hashName()` has a hardcoded switch for display names — add new hash tags there
- No test suite; verify changes by building (`mvn compile`) and running the GUI manually
