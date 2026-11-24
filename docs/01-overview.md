# 1. Overview

## Goals (v1)

- One master password, with no biometric unlock in v1.
- Credentials, secret notes and OTP secrets stored as encrypted files in a git repository, synced with push and pull.
- Several devices. A new device must be approved by an already trusted device. Devices can be revoked.
- A command-line tool with the same capabilities as the apps.
- Password generator with character sets and length. No forced security rules.

## Not in v1

- File and folder encryption (`enc`, `dec`, `.arg`).
- Recovery key.
- Import from other managers (Bitwarden, 1Password, Chrome, pass).
- Biometric unlock in the apps.
- iOS AutoFill, passkeys, browser extension.
- Android, Windows and Linux UIs. The core must not block them, but none is built.
- Sharing between users.

## Platforms

- Distribution in v1 is by building from source. Notarisation is not required for source builds.

- macOS 15 or later, and iOS 16 or later, for v1.
- The Mac app is not sandboxed in v1. The app and the CLI share the data folder.

## Architecture

- **Core (Rust, `vault-core`)**: encryption, store format, entries, search, OTP, generator, device list, device trust, git sync, conflict handling. Holds all security-critical logic.
- **FFI (`vault-ffi`)**: UniFFI generates Swift bindings. The core is packaged as an XCFramework. The core exposes plain data types and calls back into a platform-supplied `SecureStorage` interface for the OS keystore.
- **Apps**: SwiftUI, one codebase for the set of screens with a macOS sidebar layout and an iOS tab bar layout. See `07-apps-ui.md`.
- **CLI (`argus`)**: Rust, on top of the core. Starts a small background agent that holds the unlocked key between commands. See `05-sessions-and-lock.md`.
- **Git**: the system `git` when it is available (macOS and the CLI), otherwise libgit2 (iOS, or any machine without `git`). Both sit behind one interface in `vault-core`. Remote over SSH or HTTPS, with SSH host keys checked through `~/.ssh/known_hosts` as `pass` does. Credentials in the Keychain.

## Data folder

- macOS (app and CLI): `~/Library/Application Support/Argus/`. Folder mode 0700, files 0600. Contains `device.key`, `trust.json`, `config`, `join_state.json` (when joining), and `.argus/` (the git checkout of the store; every store file sits directly in its root).
- iOS: the app's `Library/Application Support/Argus/`, excluded from backups so a restore cannot clone the device identity.
- Later: Linux `~/.local/share/argus/`, Windows `%LOCALAPPDATA%\Argus\`.
- `ARGUS_HOME` overrides the data folder (used by tests).


1. Specification, threat model, test vectors.
2. Core: store, entries, search, OTP, generator, with interop tests against the C libsodium reference (the core uses the pure-Rust dryoc library).
3. Core: device keys, signed device list, join, approve, verify, revoke.
4. Core: git sync through the system `git` or libgit2, including an early spike building libgit2 for iOS.
5. CLI and agent.
6. UniFFI bindings, XCFramework, macOS app.
7. iOS app.
8. Hardening: fuzzing the parsers, memory protections, external review before 1.0.

## Core API

Plain data in, plain data out. No platform types cross the boundary.

- Types: `StoreHandle`; `Session` (zeroed on drop and on lock); `EntryId`, `DeviceId`, `StoreId` (26-character base32); `Entry` (an enum: `Credential`, `SecureNote`, `Otp`, `Unsupported`); `EntryHeader` (name fields and flags only, never secrets; search runs on these); `SecretBytes` (the platform zeroes it after use); `DeviceInfo`, `PendingRequest`, `Anchor`, `Fingerprint`, `SyncOutcome`, `GeneratorOptions`.
- `SecureStorage` callback, implemented per platform: `saveKey`, `loadKey`, `deleteKey`. Keychain items only. The core never calls the OS keystore directly.
- Functions: `init`, `join`, `unlock`, `lock`, `search`, `get`, `put`, `delete`, `sync`, `approve`, `verifyAnchor`, `revoke`, `resolveConflict`, `otpCode`, `generatePassword`, `parseOtpauth`.
- Errors, one enum: `Locked`, `WrongPassword`, `FormatUnsupported(version)`, `RemoteUnreachable`, `RemoteRejected`, `VerificationFailed(fork | rollback | badSignature)`, `Conflicts(count)`, `Damaged(id)`, `NotFound`, `Ambiguous(candidates)`, `Revoked`, `InvalidInput(field)`.
- Secret types print no content in `Debug` or `Display`. Errors never include secret or entry-name text.

## Logging

- Levels: error, warn, info. Debug is compiled out of release builds.
- Allowed fields: operation name, entry id, device id, counts, durations, exit codes, error variant.
- Never logged: passwords, notes, OTP secrets and codes, the master password, key material, entry names, URLs, usernames, paths inside the store.
- Log file `argus.log` in the data folder, rotated at 1 MB, three files kept, mode 0600. Off unless `config` sets `log = info`.
- No crash-reporting service in v1.

## Limits and performance

- Up to 20 trusted devices. Up to 10,000 entries per store. 1 MiB per entry.
- Unlock with 1,000 entries builds the search index in under 500 ms on the reference device (an Apple-silicon Mac or an iPhone 11). Search over 1,000 entries takes under 50 ms.

## Distribution

Built from source with the documented toolchain. Notarisation is not required for source builds.
