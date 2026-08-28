# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.1] - 2026-08-28

### Added

- **PAX tar format** for compound messages replacing custom PGPC v1/v2 format:
  recursive directory support, POSIX file permissions, symlink support, and
  full metadata preservation
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

- Attachment tree is now the source of truth for tar structure (refactored SendPanel)
- Relative paths shown in SendPanel attachment tree instead of absolute paths
- `ReceivePanel.restoreOwnership()` collects and returns warnings instead of silently swallowing exceptions
- `TarArchive.extractTo()` logs metadata restoration failures via `AppLog.error()`
- DecryptCommand prints metadata warnings to stderr
- `PGPTool.runCli()` logs all CLI failures via `AppLog.error()` in addition to stderr output
- 19 exception wrapping sites across CLI packages now pass the original exception as cause
- Warning messages translated from Italian to English

### Fixed

- GUI popups in CLI batch mode: `AppLog.setGuiDisabled(true)` prevents `JOptionPane` dialogs in headless-like CLI dispatch
- 777 permissions bug: `TarArchive.extractTo()` was calling `setLastModifiedTime` on symlinks which followed to non-existent targets, causing exceptions that prevented permission restoration on subsequent files
- Exception cause destruction in `CliException`: all 19 wrapping sites now preserve the original exception cause instead of discarding it
- Silent exception swallowing in `ReceivePanel.restoreOwnership()`: exceptions are now logged via `AppLog.error()` and collected as warnings
- `ListCommand` used wrong exception variable (`e` instead of `e2`) when reporting keyring load failure

## [1.0.0] - 2026-08-20

Initial release.
