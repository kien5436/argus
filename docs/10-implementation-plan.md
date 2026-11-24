# 10. Implementation plan

This is the build order for Argus v1. It is a tracker as well as a plan. Each task has a status, a definition of green, and a list of test cases with IDs you can tick off.

## 1. Execution rules

1. **Strict order.** Work through the tasks in the order listed. Do not start a task until every earlier task is green. Do not skip a task that is blocked; stop and report it.
2. **Green means done.** A task is green only when every check in its "Green when" list passes and its test cases all pass. A failing or skipped test means the task is not green.
3. **One commit per green task.** Commit when a task turns green, with the message `<type>: T<id> <title>` following commit-style (`<type>` in feat|fix|chore|refactor|test|docs|build|ops, imperative, lowercase-first, no trailing period), for example `feat: T1.1 canonical JSON (RFC 8785)`. The commit includes the tracker update for that task. Do not combine tasks in one commit. These are commits in the source repository. The store commit rules in `03-store-format.md` (`init` and `update`) apply only to the data store, never to the source repository.
4. **Tracker updates.** Set the task's status in section 3 in the same commit as its code, and record the commit hash.
5. **Blocked tasks.** A task that needs an owner decision is marked BLOCKED and says which decision it needs. Do not guess the answer.
6. **Spec changes.** If implementation shows the spec is wrong or silent, stop, report the gap with its file and section, and wait. Do not edit the spec on your own.
7. **Test data.** Tests use fixed test keys and test fixtures only. No real device key, master password, or repository may appear in the repo or in test output.

## 2. Definition of green (applies to every task)

- **G1 Tests.** Every test ID listed in the task exists and passes. No test is ignored, skipped, or marked as expected to fail.
- **G2 Pipeline.** The CI pipeline is green on the commit: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, `cargo deny check`, `cargo audit`. Apple tasks also run `xcodebuild test` on the macOS runner.
- **G3 Coverage.** Line coverage of every module the task touched is at least 90%, measured with `cargo llvm-cov`. Security-critical modules (verification, crypto wrappers, session, store writes) are at least 95%.
- **G4 Secrets.** The secret-scan check in CI passes: no secret value, master password or private key appears in test output, logs or fixtures.
- **G5 Spec.** Behaviour matches the spec sections named in the task.
- **G6 Tracker and commit.** Status is updated, and the task has exactly one commit.

## 3. Tracker

Status values: TODO, IN PROGRESS, GREEN, BLOCKED. Fill in the commit hash when green.

| ID | Task | Depends on | Status | Commit |
| --- | --- | --- | --- | --- |
| T0.1 | Repository skeleton | none | GREEN | |
| T0.2 | CI pipeline | T0.1 | GREEN | |
| T0.3 | Spec sync check | T0.2 | DROPPED (owner decision 2026-11-23) | |
| T1.1 | Canonical JSON | T0.2 | GREEN | |
| T1.2 | Encodings and ids | T1.1 | GREEN | |
| T1.3 | Domain-separated signatures (dryoc backend) | T1.2 | GREEN | |
| T1.4 | Recipients, fingerprints, anchors | T1.3 | GREEN | |
| T1.5 | Secret types | T1.4 | GREEN | |
| T1.6 | crypto envelope and sealed recipients | T1.5 | GREEN | |
| T1.7 | Entry plaintext format | T1.6 | GREEN | |
| T1.8 | Entry signature | T1.7 | GREEN | |
| T1.9 | Store layout and store.json | T1.8 | GREEN | |
| T1.10 | Data folder and permissions | T1.9 | TODO | |
| T2.1 | device.key: create and open | T1.10 | TODO | |
| T2.2 | Session and lax-time policy | T2.1 | TODO | |
| T2.3 | Master password change | T2.2 | TODO | |
| T2.4 | SecureStorage interface | T2.3 | TODO | |
| T3.1 | Local git operations (system git or libgit2) | T2.4 | TODO | |
| T3.2 | Remote URLs, credentials, host keys | T3.1 | TODO | |
| T3.3 | Fetch and push, refusal checks | T3.2 | TODO | |
| T3.4 | Network error policy | T3.3 | TODO | |
| T3.5 | libgit2 for iOS spike | T3.4 | TODO | |
| T4.1 | Device list model and devices.sig | T3.5 | TODO | |
| T4.2 | Chain verification | T4.1 | TODO | |
| T4.3 | Pin, rollback and fork | T4.2 | TODO | |
| T4.4 | Recipient set and encrypt guard | T4.3 | TODO | |
| T5.1 | init | T4.4 | TODO | |
| T5.2 | join request | T5.1 | TODO | |
| T5.3 | approve | T5.2 | TODO | |
| T5.4 | verify anchor | T5.3 | TODO | |
| T5.5 | reconcile | T5.4 | TODO | |
| T5.6 | concurrent device-list changes | T5.5 | TODO | |
| T6.1 | Entry create, read, update, delete | T5.6 | TODO | |
| T6.2 | Index and search | T6.1 | TODO | |
| T6.3 | Index maintenance and lock | T6.2 | TODO | |
| T6.4 | Damaged entries | T6.3 | TODO | |
| T6.5 | Password generator | T6.4 | TODO | |
| T6.6 | OTP parsing and codes | T6.5 | TODO | |
| T6.7 | OTP separation | T6.6 | TODO | |
| T6.8 | Conflict detection and resolution | T6.7 | TODO | |
| T7.1 | Commit timing | T6.8 | TODO | |
| T7.2 | Pull | T7.1 | TODO | |
| T7.3 | Push and retry | T7.2 | TODO | |
| T7.4 | Offline unlock | T7.3 | TODO | |
| T7.5 | Revoke | T7.4 | TODO | |
| T7.6 | Remote cleanup: GitHub | T7.5 | TODO | |
| T7.7 | Remote cleanup: other hosts | T7.6 | TODO | |
| T7.8 | GitHub App key rotation (manual steps) | T7.7 | TODO | |
| T8.1 | CLI skeleton and exit codes | T7.8 | TODO | |
| T8.2 | Agent and lax time (CLI) | T8.1 | TODO | |
| T8.3 | init and join commands | T8.2 | TODO | |
| T8.4 | add | T8.3 | TODO | |
| T8.5 | ls | T8.4 | TODO | |
| T8.6 | show, --field, picker | T8.5 | TODO | |
| T8.7 | copy to clipboard | T8.6 | TODO | |
| T8.8 | edit | T8.7 | TODO | |
| T8.9 | rm | T8.8 | TODO | |
| T8.10 | push and pull commands | T8.9 | TODO | |
| T8.11 | mfa commands | T8.10 | TODO | |
| T8.12 | device commands | T8.11 | TODO | |
| T8.13 | lock, passwd, config, promote | T8.12 | TODO | |
| T8.14 | Non-interactive mode | T8.13 | TODO | |
| T8.15 | Editor hygiene | T8.14 | TODO | |
| T9.1 | UniFFI bindings and XCFramework | T8.15, T3.5 | TODO | |
| T9.2 | Swift SecureStorage | T9.1 | TODO | |
| T9.3 | macOS shell, unlock and lock | T9.2 | TODO | |
| T9.4 | macOS entries, detail, reveal, copy | T9.3 | TODO | |
| T9.5 | macOS add and edit popup, generator | T9.4 | TODO | |
| T9.6 | macOS sync button, conflicts, rotation list | T9.5 | TODO | |
| T9.7 | macOS devices, MFA, settings | T9.6 | TODO | |
| T9.8 | iOS app | T9.7 | TODO | |
| T9.9 | Blur, lock triggers, clipboard expiry | T9.8 | TODO | |
| T9.10 | Accessibility and localisation | T9.9 | TODO | |
| T10.1 | Fuzzing | T9.10 | TODO | |
| T10.2 | Log audit | T10.1 | TODO | |
| T10.3 | Limits and performance | T10.2 | TODO | |
| T10.4 | Argon2id benchmark and fallback | T10.3 | TODO | |
| T10.5 | Format migration | T10.4 | TODO | |
| T10.6 | Build from source instructions | T10.5 | TODO | |
| T10.7 | External security review | T10.6 | BLOCKED (external) | |

Phase gates: Phase 1 starts after T0.2 is green (T0.3 dropped). Each later phase starts after the previous phase's last task is green.

## 4. Tasks

Each task gives its feature, its spec reference, its test cases, and its green checks. Cases are written so each can be ticked off.

### Phase 0: foundations

#### T0.1 Repository skeleton
- **Feature:** create the repository layout from `AGENTS.md`: `core/vault-core`, `core/vault-ffi`, `core/cli`, `apple/`, `spec/`, `tests/`. Add `.gitignore` covering `target/`, Xcode user data, `*.key`, and any store checkout.
- **Spec:** AGENTS.md, repository layout.
- **Tests:**
  - [x] T0.1-01 `cargo build --workspace` succeeds on an empty workspace.
  - [x] T0.1-02 `.gitignore` excludes a file named `device.key` placed in the repo root.
  - [x] T0.1-03 No secret-like file (`*.key`, `*.arg`) is tracked.
- **Green when:** G2, G6.
- **Commit:** `chore: T0.1 repository skeleton`

#### T0.2 CI pipeline
- **Feature:** CI runs the G2 checks on every push and pull request.
- **Tests:**
  - [x] T0.2-01 A deliberate formatting error fails the pipeline, then the fix passes it.
  - [x] T0.2-02 A deliberate clippy warning fails the pipeline.
  - [x] T0.2-03 A failing unit test fails the pipeline.
  - [x] T0.2-04 `cargo deny` fails on a banned licence (use a fixture).
- **Green when:** G2 passes on the commit, and T0.2-01 to T0.2-04 are demonstrated and recorded in the commit message.
- **Commit:** `build: T0.2 CI pipeline`

#### T0.3 Spec sync check — DROPPED (owner decision 2026-11-23)
- The `spec/` mirror and its CI check were judged unnecessary. `docs/` is the single source of truth; no `spec/` copy is kept.

### Phase 1: core primitives

#### T1.1 Canonical JSON
- **Feature:** serialise JSON to RFC 8785 canonical form. Used before every hash and signature.
- **Spec:** 03 section 3.1.
- **Tests:**
  - [x] T1.1-01 Object keys sorted by UTF-16 code units (including keys with non-BMP characters).
  - [x] T1.1-02 Nested objects and arrays keep array order and sort object keys.
  - [x] T1.1-03 Strings escape only the required characters; non-ASCII is written as UTF-8.
  - [x] T1.1-04 Control characters use the RFC 8785 escapes (`\b`, `\f`, `\n`, `\r`, `\t`, and `\u00XX` for the rest).
  - [x] T1.1-05 Integers serialise without leading zeros or a sign on zero; `-0` is rejected.
  - [x] T1.1-06 Floats are rejected by Argus data types (Argus JSON has no floats).
  - [x] T1.1-07 Duplicate keys in input are rejected.
  - [x] T1.1-08 Empty object `{}` and empty array `[]` round-trip.
  - [x] T1.1-09 Every vector from the RFC 8785 test set produces the expected output.
  - [x] T1.1-10 Output is byte-identical across 1,000 random inputs when serialised twice.
- **Green when:** G1 to G3, G6.
- **Commit:** `feat: T1.1 canonical JSON (RFC 8785)`

#### T1.2 Encodings and ids
- **Feature:** SHA-256 hex, base64url without padding, and 26-character base32 entry ids from 128 random bits.
- **Spec:** 03 section 3.1.
- **Tests:**
  - [x] T1.2-01 SHA-256 matches the NIST vector for `""` and for `"abc"`.
  - [x] T1.2-02 base64url encodes and decodes the RFC 4648 vectors and never emits `=`, `+` or `/`.
  - [x] T1.2-03 An id is exactly 26 characters, all in `[a-z2-7]`.
  - [x] T1.2-04 Id generation uses the injected OS RNG; a fixed RNG produces a fixed id (test seam).
  - [x] T1.2-05 Two ids from the real RNG differ (sampled 10,000 times, no collision).
  - [x] T1.2-06 Decoding an id with a wrong length or character is an error.
- **Green when:** G1 to G3, G6.
- **Commit:** `feat: T1.2 encodings and ids`

#### T1.3 Domain-separated signatures
- **Feature:** Ed25519 signing and verification over `prefix || canonical bytes`, where the prefix ends in a newline, via dryoc `crypto_sign` (libsodium-compatible backend). Keys are seed-based (`SigningKey` holds the 32-byte seed, zeroed on drop); verification uses strict mode.
- **Spec:** 03 sections 3.1 and 3.2 (dryoc backend), and 3.4.
- **Tests:**
  - [x] T1.3-01 A signature verifies with its key and prefix.
  - [x] T1.3-02 The same signature fails under a different prefix (`devices`, `entry`, `join`).
  - [x] T1.3-03 A one-byte change to the payload fails.
  - [x] T1.3-04 A signature from another key fails.
  - [x] T1.3-05 A non-canonical signature encoding (malleable `S` value) is rejected.
  - [x] T1.3-06 Each prefix is exactly its ASCII string followed by `0x0A`.
  - [x] T1.3-07 The Ed25519 test vectors from RFC 8032 verify through the dryoc backend (bare check), and never under a domain prefix.
  - [x] T1.3-08 The error displays without secret text.
- **Green when:** G1 to G4, G6.
- **Commit:** `feat: T1.3 domain-separated Ed25519 signatures`

#### T1.4 Recipients, fingerprints, anchors
- **Feature:** encode and parse `argus1...` recipient keys (bech32m, BIP-350), compute device fingerprints, format and parse anchors.
- **Spec:** 03 sections 3.5 (Fingerprint, Anchor) and 4.4. Anchor input is not case-sensitive and ignores spaces.
- **Tests:**
  - [x] T1.4-01 bech32m matches the BIP-350 vectors; the BIP-173 vector `a12uel5l` (original bech32) is rejected for the `argus` prefix.
  - [x] T1.4-02 A valid recipient round-trips to the same string and is 64 characters long.
  - [x] T1.4-03 A recipient with a bad checksum is rejected.
  - [x] T1.4-04 A recipient with the wrong prefix (not `argus`) is rejected.
  - [x] T1.4-05 A recipient with a bad character is rejected.
  - [x] T1.4-06 Fingerprint equals SHA-256 of `argus-device-v1\n` + Ed25519 key + X25519 key (the raw 32 bytes), for fixed keys.
  - [x] T1.4-07 Fingerprint display is 8 groups of 4 lowercase hex characters from the first 16 bytes.
  - [x] T1.4-08 Anchor is `v<version>` followed by 8 groups from the first 16 bytes of SHA-256 of the file bytes.
  - [x] T1.4-09 Anchor parse accepts the canonical form.
  - [x] T1.4-10 Anchor parse ignores case and spaces (03 section 3.5).
  - [x] T1.4-11 Anchor with a non-hex group, a missing group, or a version of 0 is rejected.
  - [x] T1.4-12 Fingerprint and anchor vectors match `core/vault-core/tests/vectors/`.
- **Green when:** G1 to G3, G6.
- **Commit:** `feat: T1.4 recipients, fingerprints, anchors`

#### T1.5 Secret types
- **Feature:** wrapper types for master password, private keys, decrypted passwords, OTP secrets and codes. They zeroise on drop and never print their contents.
- **Spec:** 01 Core API (secret types); 02 invariants.
- **Tests:**
  - [x] T1.5-01 `Debug` and `Display` of each secret type print a fixed redaction string.
  - [x] T1.5-02 Formatting an `Entry` containing a password does not reveal the password.
  - [x] T1.5-03 Dropping a secret zeroises its buffer (test with a test-only hook that reads the buffer after drop).
  - [x] T1.5-04 `Clone` is not implemented for secret types (compile-fail test).
  - [x] T1.5-05 Equality on secrets compares in constant time (test with a timing-independent check or use `subtle`).
  - [x] T1.5-06 Secrets cannot be serialised with `serde` (compile-fail test).
- **Green when:** G1 to G4, G6.
- **Commit:** `feat: T1.5 secret types`

#### T1.6 crypto envelope and sealed recipients
- **Feature:** implement the entry envelope (03 section 3.4) with dryoc: XSalsa20-Poly1305 `secretbox` under a random file key, the file key sealed to each recipient with `crypto_box_seal`. Adding a recipient appends a sealed key without touching the payload.
- **Spec:** 03 sections 3.2 and 3.4; 04 section 4.3; 08 test 6.
- **Tests:**
  - [x] T1.6-01 Encrypt then decrypt with one recipient returns the same bytes.
  - [x] T1.6-02 Encrypt to two recipients; either identity decrypts.
  - [x] T1.6-03 Decrypt with an identity not in the recipient set fails.
  - [x] T1.6-04 A flipped byte in the magic, version, `plen` or `rcount` fails.
  - [x] T1.6-05 A flipped byte in the payload fails authentication.
  - [x] T1.6-06 Empty plaintext round-trips.
  - [x] T1.6-07 A 1 MiB plaintext round-trips.
  - [x] T1.6-08 Truncated ciphertext fails.
  - [x] T1.6-09 `plen` is a multiple of 512 and at most 1,048,576; otherwise the entry is damaged.
  - [x] T1.6-10 Adding a recipient by appending a sealed key: the new device decrypts, and the original recipients still decrypt (nonce, `plen`, payload and file key unchanged).
  - [x] T1.6-11 `rcount` equals the number of sealed keys; a mismatch marks the entry damaged (T6.4).
  - [x] T1.6-12 Cross-check: a file written by dryoc decrypts through the C libsodium in CI, and vice versa (required once T0.2 runs it).
- **Green when:** G1 to G3, G6, and T1.6-12 passes in CI.
- **Commit:** `feat: T1.6 crypto envelope and sealed recipients`

#### T1.7 Entry plaintext format
- **Feature:** serialise and parse the three entry types with the padding rule.
- **Spec:** 03 section 3.4.
- **Tests:**
  - [x] T1.7-01 A credential round-trips with all four fields.
  - [x] T1.7-02 A secret note round-trips with name and content.
  - [x] T1.7-03 An OTP round-trips with all fields and each algorithm (SHA1, SHA256, SHA512).
  - [x] T1.7-04 An OTP with `digits` 5 or 9 is rejected.
  - [x] T1.7-05 An OTP with both `period` and `counter` set is rejected.
  - [x] T1.7-06 Padding brings the plaintext to a multiple of 512 bytes for lengths 1, 511, 512, 513 and 1000.
  - [x] T1.7-07 Padding is trailing spaces and is ignored by the JSON parser.
  - [x] T1.7-08 An entry larger than 1 MiB is rejected on write and on read.
  - [x] T1.7-09 Unknown fields are preserved when an entry is parsed and rewritten.
  - [x] T1.7-10 An unknown `type` parses as `Unsupported` and its bytes are kept.
  - [x] T1.7-11 `rev` starts at 1 and an edit writes `rev` plus one.
  - [x] T1.7-12 `conflictOf` and `rotate` are optional and round-trip.
  - [x] T1.7-13 Invalid JSON, a missing `v`, and `v` not equal to 1 are rejected.
- **Green when:** G1 to G3, G6.
- **Commit:** `feat: T1.7 entry plaintext format`

#### T1.8 Entry signature
- **Feature:** sign the canonical entry without `sig` with the `argus-entry-v1` prefix; verify against the device list.
- **Spec:** 03 section 3.4 (Entry signature).
- **Tests:**
  - [x] T1.8-01 A signed entry verifies with the signer's key.
  - [x] T1.8-02 Changing any field after signing fails verification.
  - [x] T1.8-03 A signature from a key not in the supplied list fails.
  - [x] T1.8-04 The `sig.by` field names the signer; mismatch with the key found fails.
  - [x] T1.8-05 A signature made with the `devices` prefix does not verify as an entry.
  - [x] T1.8-06 A `sig` missing from the entry fails verification.
- **Green when:** G1 to G4, G6.
- **Commit:** `feat: T1.8 entry signatures`

#### T1.9 Store layout and store.json
- **Feature:** create and read the store layout in a directory; enforce the format rule.
- **Spec:** 03 section 3.3 (the checkout is `.argus/`).
- **Tests:**
  - [x] T1.9-01 A new store has `store.json`, `.gitattributes` with the exact content, and no subdirectories.
  - [x] T1.9-02 `store.json` has `format` 1 and a storeId of 26 characters.
  - [x] T1.9-03 `format` 2 is refused with `FormatUnsupported(2)`, and nothing is written.
  - [x] T1.9-04 A file not matching the known names or an `<id>.arg` pattern is ignored and not modified.
  - [x] T1.9-05 An entry file whose name is not a valid id is ignored.
  - [x] T1.9-06 A store root with `store.json` missing is reported as not a store.
- **Green when:** G1 to G3, G5, G6.
- **Commit:** `feat: T1.9 store layout and store.json`

#### T1.10 Data folder and permissions
- **Feature:** create the per-platform data folder with the right modes; honour `ARGUS_HOME`.
- **Spec:** 01 data folder; 05 section (lock and clipboard) for `argus.log` mode.
- **Tests:**
  - [ ] T1.10-01 The folder is created with mode 0700.
  - [ ] T1.10-02 A file written by the core has mode 0600.
  - [ ] T1.10-03 `ARGUS_HOME` overrides the location for tests.
  - [ ] T1.10-04 An existing folder with looser permissions is tightened or refused (decision recorded in the test name).
  - [ ] T1.10-05 A path with a symbolic link at the data folder is refused.
  - [ ] T1.10-06 The default macOS path is `~/Library/Application Support/Argus/` for a given home directory.
- **Green when:** G1 to G3, G6.
- **Commit:** `feat: T1.10 data folder and permissions`

### Phase 2: keys and session

#### T2.1 device.key: create and open
- **Feature:** generate both keypairs and store them in `device.key`, an Argon2id-encrypted envelope with opslimit = 3 and memlimit = 256 MiB; fall back to opslimit = 2 and memlimit = 64 MiB if 256 MiB cannot be allocated.
- **Spec:** 02 (device keys; master password and unlock); 03 section 3.6.
- **Tests:**
  - [ ] T2.1-01 Creating a device writes `device.key`; reopening it with the right password returns the same keys.
  - [ ] T2.1-02 The wrong password fails with `WrongPassword`.
  - [ ] T2.1-03 A flipped byte in `device.key` fails with an error, not a wrong key.
  - [ ] T2.1-04 The Argon2id parameters in the header are opslimit 3 and memlimit 256 MiB.
  - [ ] T2.1-05 Allocation failure at 256 MiB falls back to 64 MiB and the header records opslimit 2 and memlimit 64 MiB.
  - [ ] T2.1-06 An empty master password is refused.
  - [ ] T2.1-07 Passwords with Unicode (including emoji and combining characters) round-trip.
  - [ ] T2.1-08 `deviceId`, `encSecret` and `signSeed` are the only fields in the plaintext; the JSON shape matches 03 section 3.6.
  - [ ] T2.1-09 Two devices created in a row have different keys.
- **Green when:** G1 to G4, G6.
- **Commit:** `feat: T2.1 device.key create and open`

#### T2.2 Session and lax-time policy
- **Feature:** an unlocked session holding the keys. Two lax-time policies: `FromUnlock` (CLI) and `FromInteraction` (apps). `lax-time` 0 means no cached session.
- **Spec:** 05 (lax time, CLI and apps); 02 (unlock lifecycle).
- **Tests:**
  - [ ] T2.2-01 With `FromUnlock` and 45 s, the session is valid at 44.999 s and expired at 45.000 s.
  - [ ] T2.2-02 With `FromInteraction`, an interaction at 30 s extends the session to 75 s.
  - [ ] T2.2-03 An interaction does not extend a `FromUnlock` session.
  - [ ] T2.2-04 `lax-time` 0 makes every operation that needs the key require a password (session never valid).
  - [ ] T2.2-05 `lock()` zeroises the keys and the search index handle; a later use fails with `Locked`.
  - [ ] T2.2-06 Expiry zeroises the keys (tested with the T1.5 hook).
  - [ ] T2.2-07 Lax time accepts values between 0 and a maximum, and rejects negatives and non-numbers.
  - [ ] T2.2-08 Time is injected, so tests do not sleep.
- **Green when:** G1 to G3, G6.
- **Commit:** `feat: T2.2 session and lax-time policy`

#### T2.3 Master password change
- **Feature:** change the master password by rewriting only `device.key`.
- **Spec:** 02 master password; 06 `passwd`.
- **Tests:**
  - [ ] T2.3-01 After a change, the new password opens `device.key`.
  - [ ] T2.3-02 The old password fails.
  - [ ] T2.3-03 The keys are the same before and after.
  - [ ] T2.3-04 The git tree and every store file are byte-identical before and after.
  - [ ] T2.3-05 A failure midway leaves the old `device.key` intact (atomic write: temp file, then rename).
  - [ ] T2.3-06 A new salt is used on each change.
- **Green when:** G1 to G4, G6.
- **Commit:** `feat: T2.3 master password change`

#### T2.4 SecureStorage interface
- **Feature:** the core calls `saveKey`, `loadKey` and `deleteKey` on a trait. A test double implements it. The core never calls an OS API.
- **Spec:** 01 Core API; AGENTS invariants.
- **Tests:**
  - [ ] T2.4-01 Save then load returns the stored bytes.
  - [ ] T2.4-02 Load of a missing key returns `None`.
  - [ ] T2.4-03 Delete removes the key; a second delete is not an error.
  - [ ] T2.4-04 The core compiles without any platform crate (dependency check in CI).
  - [ ] T2.4-05 The double records each call; a test asserts the expected sequence for unlock.
- **Green when:** G1 to G3, G6.
- **Commit:** `feat: T2.4 SecureStorage interface`

### Phase 3: git layer

#### T3.1 Local git operations
- **Feature:** init a repo, stage files, commit with the configured author, read history. Uses the system `git` when available, otherwise libgit2. Both backends are tested with the same cases.
- **Spec:** 01 architecture (git: system git or libgit2); 03 section 3.7 (author).
- **Tests:**
  - [ ] T3.1-01 Init creates a repository with the expected layout.
  - [ ] T3.1-02 A commit uses the configured name and email as author.
  - [ ] T3.1-03 Commit messages are passed through: `init` for a new store's first commit, `update` otherwise (03 section 3.7).
  - [ ] T3.1-04 With `git` on `PATH`, the system backend is used (checked with a test hook that reports the backend).
  - [ ] T3.1-05 With `git` absent from `PATH` (test with an empty `PATH`), the libgit2 backend is used and every T3.1 case still passes.
  - [ ] T3.1-06 Both backends produce identical commits and refs for the same input (same tree hash and commit contents, except the commit time).
  - [ ] T3.1-07 No secret appears in any `git` argument or environment variable (checked by a test that records the invocation).
  - [ ] T3.1-08 Reading history returns commits in order.
  - [ ] T3.1-09 A commit with no changes is refused or skipped (decision recorded).
  - [ ] T3.1-10 Missing author configuration is refused.
- **Green when:** G1 to G3, G6.
- **Commit:** `feat: T3.1 local git operations`

#### T3.2 Remote URLs, credentials, host keys
- **Feature:** accept scp-like SSH, `ssh://`, and `https://` remotes; store credentials through SecureStorage; verify SSH host keys.
- **Spec:** 04 (remote); 01 (credentials in the Keychain; SSH host keys checked through `~/.ssh/known_hosts`, as `pass` does).
- **Tests:**
  - [ ] T3.2-01 `git@host:owner/repo.git`, `ssh://git@host/owner/repo.git` and `https://host/owner/repo.git` parse.
  - [ ] T3.2-02 A URL with embedded credentials (`https://user:token@host`) is refused.
  - [ ] T3.2-03 A `file://` remote is accepted for tests only.
  - [ ] T3.2-04 An unknown SSH host key is never accepted silently (01 architecture).
  - [ ] T3.2-05 SSH to a host whose key changed fails.
  - [ ] T3.2-06 Credentials are read from SecureStorage and never printed.
  - [ ] T3.2-07 An HTTPS token is sent as a header, not in the URL (checked with a local test server).
- **Green when:** G1 to G4, G6.
- **Commit:** `feat: T3.2 remote URLs, credentials, host keys`

#### T3.3 Fetch and push, refusal checks
- **Feature:** fetch and push with the remote; refuse a shallow clone and a remote that has files but no `store.json`.
- **Spec:** 04 section 4.8 (refusals); 04 section 4.1 (empty remote).
- **Tests:**
  - [ ] T3.3-01 Fetch and push against a local bare repository succeed.
  - [ ] T3.3-02 A push rejected as non-fast-forward is reported as rejected (not as a network error).
  - [ ] T3.3-03 A shallow clone is refused.
  - [ ] T3.3-04 A remote with files but no `store.json` at its root is refused for init.
  - [ ] T3.3-05 An empty remote is accepted for init.
  - [ ] T3.3-06 Push sends only commits; no entry plaintext is sent in the pack (checked by decrypting nothing).
- **Green when:** G1 to G3, G6.
- **Commit:** `feat: T3.3 fetch, push, refusal checks`

#### T3.4 Network error policy
- **Feature:** a network failure retries up to 3 times and then returns a decision request to the caller. Retry is in the core; the asking is in the UI or CLI.
- **Spec:** 04 section 4.8; 08 test 20.
- **Tests:**
  - [ ] T3.4-01 A simulated unreachable host is retried exactly 3 times, then `RemoteUnreachable` is returned with `shouldAsk`.
  - [ ] T3.4-02 A success on attempt 2 stops retrying.
  - [ ] T3.4-03 Backoff delays are injected, so tests do not sleep.
  - [ ] T3.4-04 An auth failure is `RemoteRejected` and is not retried.
  - [ ] T3.4-05 Retry count is the same for fetch and push.
- **Green when:** G1 to G3, G6.
- **Commit:** `feat: T3.4 network error policy`

#### T3.5 libgit2 for iOS spike
- **Feature:** build libgit2 (and its SSH and TLS dependencies) for iOS device and simulator; run the T3.1 and T3.3 smoke tests in the simulator.
- **Spec:** 10 milestone 4 (spike); 01 milestone list.
- **Tests:**
  - [ ] T3.5-01 The static library builds for `aarch64-apple-ios` and `aarch64-apple-ios-sim`.
  - [ ] T3.5-02 A local init and commit run in the iOS simulator test target.
  - [ ] T3.5-03 A fetch over HTTPS to a local test server runs in the simulator.
  - [ ] T3.5-04 Build size and time are recorded in the commit message.
  - [ ] T3.5-05 The build script is documented in `core/README.md`.
- **Green when:** G2 (Apple job), G6. If the spike fails, the task is BLOCKED and the owner decides the fallback.
- **Commit:** `feat: T3.5 libgit2 iOS spike`

### Phase 4: device list and trust

#### T4.1 Device list model and devices.sig
- **Feature:** the device list type, canonical serialisation, and the `devices.sig` file.
- **Spec:** 03 section 3.5.
- **Tests:**
  - [ ] T4.1-01 A device list serialises to canonical JSON with the fields in 03 section 3.5.
  - [ ] T4.1-02 `devices.sig` is `{"signer","sig"}` and parses.
  - [ ] T4.1-03 Adding a device changes `version` only when the caller bumps it (no silent bumps).
  - [ ] T4.1-04 A device entry missing `addedBy` is rejected.
  - [ ] T4.1-05 A device name with control characters is rejected.
  - [ ] T4.1-06 `gitKey` is optional.
- **Green when:** G1 to G3, G6.
- **Commit:** `feat: T4.1 device list model and devices.sig`

#### T4.2 Chain verification
- **Feature:** verify every rule in 03 section 3.5 (Verification) over a chain of versions.
- **Spec:** 03 section 3.5 (rules 1 to 7); 08 test 3.
- **Tests:**
  - [ ] T4.2-01 Valid chain of versions 1, 2 and 3 verifies; returns version 3 and its hash.
  - [ ] T4.2-02 Version 1 with `prev` not empty fails.
  - [ ] T4.2-03 Version 1 with two devices fails.
  - [ ] T4.2-04 Version 1 with `addedBy` not equal to itself fails.
  - [ ] T4.2-05 Version 1 signed by another key fails.
  - [ ] T4.2-06 Version n+1 with wrong `prev` fails with `prev`.
  - [ ] T4.2-07 Version n+1 signed by a device not in version n fails with `signerNotInPrevious`.
  - [ ] T4.2-08 A new device with `addedBy` not equal to the signer fails.
  - [ ] T4.2-09 A device adding itself fails with `selfAdded`.
  - [ ] T4.2-10 A bad signature fails with `badSignature`.
  - [ ] T4.2-11 An empty device list fails with `emptyList`.
  - [ ] T4.2-12 `v` not equal to 1 fails with `unsupported`.
  - [ ] T4.2-13 A `version` out of sequence fails with `versionOrder`.
  - [ ] T4.2-14 A file that is not canonical JSON fails with `notCanonical`.
  - [ ] T4.2-15 `storeId` different from the pinned store id fails.
  - [ ] T4.2-16 A removed device cannot sign the next version.
  - [ ] T4.2-17 A shallow history is refused.
  - [ ] T4.2-18 Every case in `core/vault-core/tests/vectors/` gives its expected result.
- **Green when:** G1 to G4, G6.
- **Commit:** `feat: T4.2 device list chain verification`

#### T4.3 Pin, rollback and fork
- **Feature:** store `(storeId, version, hash)` in `trust.json`; reject lower versions (rollback) and same-version different bytes (fork).
- **Spec:** 03 section 3.5 (rule 6); 02 device list and trust.
- **Tests:**
  - [ ] T4.3-01 No pin yet: any verified version is accepted and pinned.
  - [ ] T4.3-02 A newer verified version replaces the pin.
  - [ ] T4.3-03 A lower version fails with `rollback`.
  - [ ] T4.3-04 The same version and the same hash is accepted.
  - [ ] T4.3-05 The same version with a different hash fails with `fork` and raises a security alert.
  - [ ] T4.3-06 `trust.json` is written atomically.
  - [ ] T4.3-07 A corrupt `trust.json` refuses sync and asks the user (no silent reset).
  - [ ] T4.3-08 `trust.json` cannot be read as a different store's pin (storeId mismatch fails).
- **Green when:** G1 to G4, G6.
- **Commit:** `feat: T4.3 pin, rollback and fork detection`

#### T4.4 Recipient set and encrypt guard
- **Feature:** entries are encrypted only to the recipients of the newest verified list; encryption refuses when the list is not verified.
- **Spec:** 02 invariants; 03 section 3.5 (rule 7); 08 test 9.
- **Tests:**
  - [ ] T4.4-01 The recipient set equals the newest verified list.
  - [ ] T4.4-02 Encrypting with an unverified list fails with `VerificationFailed`.
  - [ ] T4.4-03 A device removed in a newer version is not a recipient of new entries.
  - [ ] T4.4-04 An entry signed by a device not in the current list is refused with a security alert and is not marked damaged (03 section 3.4).
- **Green when:** G1 to G4, G6.
- **Commit:** `feat: T4.4 recipient set and encrypt guard`

### Phase 5: join, approve, verify

#### T5.1 init
- **Feature:** create a new store on an empty remote; or, if the remote has a store, switch to join mode.
- **Spec:** 04 section 4.1 and 4.2.
- **Tests:**
  - [ ] T5.1-01 Empty remote: store, device list version 1 and `devices.sig` are created, committed and pushed.
  - [ ] T5.1-02 `trust.json` pins version 1 after init.
  - [ ] T5.1-03 Remote with files but no `store.json` is refused with exit 1 (core returns the error).
  - [ ] T5.1-04 Remote with a store switches to join mode and returns `joinRequired`.
  - [ ] T5.1-05 Init on an already-initialised data folder is refused with a hint.
  - [ ] T5.1-06 A network failure during push is reported and retried per T3.4.
  - [ ] T5.1-07 The first commit's message is `init`.
- **Green when:** G1 to G4, G6.
- **Commit:** `feat: T5.1 init`

#### T5.2 join request
- **Feature:** a new device writes `pending-<deviceId>.json`, signed with `argus-join-v1`, commits, pushes, and records `join_state.json`.
- **Spec:** 04 section 4.2.
- **Tests:**
  - [ ] T5.2-01 The pending file matches the layout in 04 section 4.2.
  - [ ] T5.2-02 Its signature verifies with the device's own key and the `argus-join-v1` prefix.
  - [ ] T5.2-03 A changed field fails the signature.
  - [ ] T5.2-04 `join_state.json` is written; the device decrypts nothing and trusts no list at this point.
  - [ ] T5.2-05 A store id that differs from the store found on the remote is refused.
  - [ ] T5.2-06 Re-running the join request replaces the pending file for the same device, and does not duplicate it.
  - [ ] T5.2-07 The join commit's message is `update`.
- **Green when:** G1 to G4, G6.
- **Commit:** `feat: T5.2 join request`

#### T5.3 approve
- **Feature:** a trusted device lists valid pending requests, requires fingerprint confirmation, adds the device to a new signed list, adds the new recipient to every entry, commits once, pushes, and shows the anchor.
- **Spec:** 04 section 4.3; T1.6 sealed-recipient addition.
- **Tests:**
  - [ ] T5.3-01 Listing returns only requests with a valid self-signature for the same store id.
  - [ ] T5.3-02 Approve without a confirmed fingerprint is refused.
  - [ ] T5.3-03 Approve with a mismatched fingerprint is refused.
  - [ ] T5.3-04 The new list is version n+1, `prev` equals the hash of version n, `addedBy` equals this device.
  - [ ] T5.3-05 After approval, every entry is decryptable by the new device's key.
  - [ ] T5.3-06 Pending file is removed in the same commit.
  - [ ] T5.3-07 A rejected push triggers pull, verify and redo from the list step; lists are never merged.
  - [ ] T5.3-08 The anchor shown equals the one the new device will compute.
  - [ ] T5.3-09 Adding a recipient appends a sealed key; the payload and file key are unchanged (checked by comparing bytes before and after).
  - [ ] T5.3-10 Approving a device already in the list is refused.
  - [ ] T5.3-11 The approve commit's message is `update`.
- **Green when:** G1 to G4, G6.
- **Commit:** `feat: T5.3 approve device`

#### T5.4 verify anchor
- **Feature:** the new device checks the anchor against the remote history and pins the approved version.
- **Spec:** 04 section 4.4; 03 section 3.5.
- **Tests:**
  - [ ] T5.4-01 A matching anchor verifies, pins the version, and deletes `join_state.json`.
  - [ ] T5.4-02 A mismatching anchor fails with `VerificationFailed`, keeps keys, and exits 7.
  - [ ] T5.4-03 An anchor for a version not in history fails.
  - [ ] T5.4-04 Anchor input is parsed per T1.4 (03 section 3.5).
  - [ ] T5.4-05 After verify, the new device decrypts entries and builds the index.
  - [ ] T5.4-06 Verify without a pending join is refused.
- **Green when:** G1 to G4, G6.
- **Commit:** `feat: T5.4 verify anchor`

#### T5.5 reconcile
- **Feature:** after each pull, compare each entry's `rcount` (sealed file keys) with the number of verified devices and repair mismatches.
- **Spec:** 04 section 4.6.
- **Tests:**
  - [ ] T5.5-01 An entry missing one recipient is repaired by sealing the file key to it (append, payload unchanged).
  - [ ] T5.5-02 An entry with an extra recipient is repaired by full re-encryption.
  - [ ] T5.5-03 A sealed key that no verified device can open is treated as an extra recipient.
  - [ ] T5.5-04 Repaired entries are committed in one commit.
  - [ ] T5.5-05 A repair failure leaves the entry unchanged and reports it.
- **Green when:** G1 to G4, G6.
- **Commit:** `feat: T5.5 reconcile recipients`

#### T5.6 concurrent device-list changes
- **Feature:** when the push of a list change is rejected, the change is re-applied on top of the latest verified list and signed again.
- **Spec:** 04 section 4.7.
- **Tests:**
  - [ ] T5.6-01 Two approvals racing: the second is re-applied on top of the first, giving version n+2.
  - [ ] T5.6-02 The re-applied list is signed by the approving device.
  - [ ] T5.6-03 A re-apply that conflicts with a removal fails with a clear error.
  - [ ] T5.6-04 No automatic merge of two different lists occurs.
- **Green when:** G1 to G4, G6.
- **Commit:** `feat: T5.6 concurrent device-list changes`

### Phase 6: entries, search, OTP, generator, conflicts

#### T6.1 Entry create, read, update, delete
- **Feature:** store operations on entries: create with a random id, read with decryption on demand, update with `rev` plus one, delete with `git rm`.
- **Spec:** 03 section 3.4; 01 core API (`get`, `put`, `delete`).
- **Tests:**
  - [ ] T6.1-01 Create writes `<id>.arg` with the expected envelope and no metadata in the file name.
  - [ ] T6.1-02 Read returns the same plaintext that was written.
  - [ ] T6.1-03 Update increments `rev` by one and changes `updated`.
  - [ ] T6.1-04 Delete removes the file; the old ciphertext remains in history.
  - [ ] T6.1-05 Reading an id that does not exist returns `NotFound`.
  - [ ] T6.1-06 A file whose name does not match its `id` marks the entry damaged (T6.4).
  - [ ] T6.1-07 Writing an entry over 1 MiB is refused.
  - [ ] T6.1-08 Writes do not commit (T7.1 owns commit timing).
- **Green when:** G1 to G4, G6.
- **Commit:** `feat: T6.1 entry create, read, update, delete`

#### T6.2 Index and search
- **Feature:** an in-memory index of headers (name fields only), fuzzy search with the ranking rules in the CLI reference.
- **Spec:** 03 section 3.4 (searchable fields, URL matching); 06 section 6.3; 08 tests 10 and 21.
- **Tests:**
  - [ ] T6.2-01 Searchable fields are URL host and username (credential), name (note), label and issuer (OTP). Passwords and note content are never indexed.
  - [ ] T6.2-02 Matching ignores case.
  - [ ] T6.2-03 URL matching lowercases the host, drops scheme, `www.` and path.
  - [ ] T6.2-04 An exact match on a whole field ranks above fuzzy matches.
  - [ ] T6.2-05 A single fuzzy match is auto-selected.
  - [ ] T6.2-06 Several fuzzy matches return a list, not a selection.
  - [ ] T6.2-07 A keyword matching only a password returns nothing.
  - [ ] T6.2-08 A keyword matching only note content returns nothing.
  - [ ] T6.2-09 A keyword matching an OTP issuer returns the OTP.
  - [ ] T6.2-10 Empty keyword returns all headers sorted by name, ascending (06 section 6.5.3).
  - [ ] T6.2-11 Search over 1,000 entries completes in under 50 ms on the reference runner (performance test, see T10.3).
  - [ ] T6.2-12 Reserved words are rejected as names, with the list in 06 section 6.3.
- **Green when:** G1 to G3, G6.
- **Commit:** `feat: T6.2 index and search`

#### T6.3 Index maintenance and lock
- **Feature:** the index is built on unlock, updated for changed files after pull, and dropped on lock.
- **Spec:** 02 unlock lifecycle; 04 section 4.8; 03 section 3.6 (memory only).
- **Tests:**
  - [ ] T6.3-01 Unlock builds the index from all entries.
  - [ ] T6.3-02 After a pull, only changed and new files are re-read (counted with a test hook).
  - [ ] T6.3-03 A deleted file is removed from the index.
  - [ ] T6.3-04 Lock drops the index; no index data remains reachable.
  - [ ] T6.3-05 The index is never written to disk (test scans the data folder after unlock and search).
- **Green when:** G1 to G4, G6.
- **Commit:** `feat: T6.3 index maintenance and lock`

#### T6.4 Damaged entries
- **Feature:** entries that cannot be read, whose id does not match the file name, or whose signature is invalid are listed as damaged and never deleted automatically.
- **Spec:** 04 section 4.8; 03 section 3.4 (entry signature).
- **Tests:**
  - [ ] T6.4-01 A file with a corrupt envelope (bad magic, version, or length) is listed as damaged.
  - [ ] T6.4-02 An id that does not match the file name is damaged.
  - [ ] T6.4-03 An entry whose signer is not in the current list is refused with a security alert and is not marked damaged (03 section 3.4).
  - [ ] T6.4-04 Damaged entries are never deleted by any operation (test each operation).
  - [ ] T6.4-05 A damaged entry does not stop the rest of the store from loading.
- **Green when:** G1 to G4, G6.
- **Commit:** `feat: T6.4 damaged entries`

#### T6.5 Password generator
- **Feature:** generate passwords from selected sets and a length (default 20), using the OS RNG and rejection sampling.
- **Spec:** 06 section 6.5.2 (add); 01 generator; 02 invariants (no forced rules).
- **Tests:**
  - [ ] T6.5-01 Length 20 by default.
  - [ ] T6.5-02 Each set (letters, digits, symbols) appears when selected.
  - [ ] T6.5-03 Turning every set off is refused with `InvalidInput`.
  - [ ] T6.5-04 Length 1 and length 256 work; 0 and negative are refused.
  - [ ] T6.5-05 Distribution: over 10^6 characters from a 62-character set, a chi-square test does not reject uniformity at p = 0.001.
  - [ ] T6.5-06 Rejection sampling never produces a biased character (checked by T6.5-05 and a set-size test with a non-power-of-two set).
  - [ ] T6.5-07 Output is `SecretBytes` (T1.5).
  - [ ] T6.5-08 The generator never blocks saving; strength is informational only.
- **Green when:** G1 to G4, G6.
- **Commit:** `feat: T6.5 password generator`

#### T6.6 OTP parsing and codes
- **Feature:** parse `otpauth://` URLs for TOTP and HOTP; compute codes; advance the HOTP counter and commit.
- **Spec:** 03 section 3.4 (otp); 06 section 6.5.9; 05 (HOTP counter).
- **Tests:**
  - [ ] T6.6-01 RFC 6238 Appendix B TOTP vectors for SHA1, SHA256 and SHA512 at the listed times (8 digits).
  - [ ] T6.6-02 RFC 4226 Appendix D HOTP vectors (counter 0 to 9).
  - [ ] T6.6-03 `otpauth://totp/...` with `period` and `digits` parses.
  - [ ] T6.6-04 `otpauth://hotp/...` with `counter` parses.
  - [ ] T6.6-05 Missing `secret` is refused.
  - [ ] T6.6-06 `secret` that is not base32 is refused.
  - [ ] T6.6-07 An unknown `algorithm` is refused.
  - [ ] T6.6-08 `digits` outside 6 to 8 is refused.
  - [ ] T6.6-09 Label and issuer are taken from the path and the `issuer` parameter; a mismatch is reported.
  - [ ] T6.6-10 Code time is injected (no real clock in tests).
  - [ ] T6.6-11 HOTP: generating a code advances the counter and produces a commit (T7.1 timing applies).
  - [ ] T6.6-12 A code is zero-padded to its digit count.
  - [ ] T6.6-13 The seconds remaining in a TOTP period are computed correctly at period boundaries.
- **Green when:** G1 to G4, G6.
- **Commit:** `feat: T6.6 OTP parsing and codes`

#### T6.7 OTP separation
- **Feature:** OTP entries are listed only by the MFA listing; they are excluded from the entry listing; edit refuses them.
- **Spec:** 06 section 6.5.3; 07 section 2; 08 test 17.
- **Tests:**
  - [ ] T6.7-01 The entry listing excludes OTP entries.
  - [ ] T6.7-02 The MFA listing includes only OTP entries.
  - [ ] T6.7-03 Edit on an OTP entry is refused with `InvalidInput`.
  - [ ] T6.7-04 The MFA listing does not include credentials or notes.
  - [ ] T6.7-05 Both listings are sorted by name, ascending (06 section 6.5.3).
- **Green when:** G1 to G3, G6.
- **Commit:** `feat: T6.7 OTP separation`

#### T6.8 Conflict detection and resolution
- **Feature:** when the same entry changed on both sides, order the versions by git history, keep the latest as the entry, and keep older versions as conflict copies with `conflictOf`. Resolve with "use current" or "use older".
- **Spec:** 04 section 4.9; 08 test 8.
- **Tests:**
  - [ ] T6.8-01 Two versions of one entry, changed on two devices: the later commit is the entry; the earlier becomes a conflict copy with `conflictOf`.
  - [ ] T6.8-02 Ordering uses git history, not `rev` or timestamps (a case where the clock is wrong).
  - [ ] T6.8-03 Three versions produce two conflict copies, oldest first.
  - [ ] T6.8-04 An edit conflicting with a delete keeps the edit.
  - [ ] T6.8-05 "Use current" keeps the current version and deletes the older copy.
  - [ ] T6.8-06 "Use older" makes the older version current and deletes the copy.
  - [ ] T6.8-07 While any conflict is unresolved, sync is refused with exit 9 (core returns `Conflicts(count)`).
  - [ ] T6.8-08 No version is silently discarded.
  - [ ] T6.8-09 The device list is never merged this way.
- **Green when:** G1 to G4, G6.
- **Commit:** `feat: T6.8 conflict detection and resolution`

### Phase 7: sync and revoke

#### T7.1 Commit timing
- **Feature:** changes are written to the working tree and committed only just before a push or a pull.
- **Spec:** 04 section 4.8; 08 test 18.
- **Tests:**
  - [ ] T7.1-01 Add, edit and delete create no commit.
  - [ ] T7.1-02 A push first commits pending changes as `update`, then pushes.
  - [ ] T7.1-03 A pull with pending changes commits them first, then pulls.
  - [ ] T7.1-04 Every commit made by these operations has the message `update`.
  - [ ] T7.1-05 A process killed after writing and before commit leaves the working tree intact and the next operation commits it.
- **Green when:** G1 to G4, G6.
- **Commit:** `feat: T7.1 commit timing`

#### T7.2 Pull
- **Feature:** fetch, verify the device list, verify and index changed entries, combine the changes (fast-forward or merge commit `update`), report counts.
- **Spec:** 04 sections 4.8 and 4.9.
- **Tests:**
  - [ ] T7.2-01 A pull that fast-forwards reports new, changed and deleted counts.
  - [ ] T7.2-09 Both git backends (T3.1) pass every T7.2 case.
  - [ ] T7.2-02 A failed device list verification aborts; nothing from the pull is used; nothing is reset.
  - [ ] T7.2-03 A pull with a fork fails with `VerificationFailed(fork)` and a security alert.
  - [ ] T7.2-04 A pull with a rollback fails with `VerificationFailed(rollback)`.
  - [ ] T7.2-05 Changed entries are verified before being indexed.
  - [ ] T7.2-06 A pull with a conflict asks the user to keep the older or the newer version of each conflicting entry, then continues.
  - [ ] T7.2-08 If the user postpones a conflict, the older version is kept as a conflict copy and sync is blocked with exit 9 (04 section 4.9).
  - [ ] T7.2-07 With changes on both sides and no conflict, the result is a merge with message `update` and no prompt (04 section 4.8).
- **Green when:** G1 to G4, G6.
- **Commit:** `feat: T7.2 pull`

#### T7.3 Push and retry
- **Feature:** push; if rejected, fetch, verify, combine the changes as in pull (04 section 4.8), and retry, at most 3 times, then return a decision request.
- **Spec:** 04 section 4.8; 08 test 19.
- **Tests:**
  - [ ] T7.3-01 A push with no remote change succeeds on the first attempt.
  - [ ] T7.3-02 A push rejected once then accepted succeeds on attempt 2.
  - [ ] T7.3-03 A push rejected every time is attempted exactly 3 retries, then returns a decision request.
  - [ ] T7.3-04 Verification failure during a retry stops the retry at once.
  - [ ] T7.3-05 Each retry re-verifies the device list.
- **Green when:** G1 to G4, G6.
- **Commit:** `feat: T7.3 push and retry`

#### T7.4 Offline unlock
- **Feature:** unlock and local reads work without a network; sync is offered later.
- **Spec:** 02 unlock; 04 section 4.8 (unreachable).
- **Tests:**
  - [ ] T7.4-01 Unlock with the remote unreachable succeeds.
  - [ ] T7.4-02 Reading, searching and generating work offline.
  - [ ] T7.4-03 Pending local changes are kept while offline.
  - [ ] T7.4-04 A push while offline returns `RemoteUnreachable` and retries per T3.4.
- **Green when:** G1 to G3, G6.
- **Commit:** `feat: T7.4 offline unlock`

#### T7.5 Revoke
- **Feature:** remove a device: new signed list, re-encrypt every entry with fresh file keys, re-sign each entry, set rotate flags, commit as `update`, push.
- **Spec:** 04 section 4.5; 02 revocation; 08 test 9.
- **Tests:**
  - [ ] T7.5-01 The new list is version n+1 without the removed device, signed by a trusted device.
  - [ ] T7.5-02 Every entry is encrypted with a new file key and does not list the removed device as a recipient.
  - [ ] T7.5-03 Every entry is re-signed by the revoking device.
  - [ ] T7.5-04 Every entry has `rotate` set.
  - [ ] T7.5-05 The revoked device cannot decrypt an entry written after revoke (test with its key).
  - [ ] T7.5-06 A device cannot revoke itself (refused).
  - [ ] T7.5-07 A device not in the list cannot revoke (refused).
  - [ ] T7.5-08 Revoke is one commit with the message `update`.
  - [ ] T7.5-09 A revoked device that pulls finds itself missing and returns `Revoked`, with the lock-and-delete-only behaviour.
  - [ ] T7.5-10 The revoked device's previously held data is unchanged on its own disk (documented, not deleted by Argus).
- **Green when:** G1 to G4, G6.
- **Commit:** `feat: T7.5 revoke device`

#### T7.6 Remote cleanup: GitHub
- **Feature:** create an installation token from the GitHub App's private key, and delete the removed device's deploy key through the GitHub API.
- **Spec:** 04 section 4.5 step 4; 02 GitHub App key. Manual steps only.
- **Tests (use a local mock of the GitHub API):**
  - [ ] T7.6-01 The App JWT is signed RS256 with the App's private key and has a short expiry.
  - [ ] T7.6-02 The installation token is requested for the store repository only.
  - [ ] T7.6-03 The deploy key matching `gitKey` is deleted.
  - [ ] T7.6-04 A deploy key that is already gone (404) counts as success.
  - [ ] T7.6-05 A 401 or 403 is reported as a credential problem and is not retried.
  - [ ] T7.6-06 A 5xx is retried 3 times, then the user is asked.
  - [ ] T7.6-07 A network failure leaves cleanup marked pending.
  - [ ] T7.6-08 The App private key is never logged or sent to a server other than GitHub.
  - [ ] T7.6-09 A device without App credentials shows manual steps and marks cleanup pending.
- **Green when:** G1 to G4, G6.
- **Commit:** `feat: T7.6 remote cleanup on GitHub`

#### T7.7 Remote cleanup: other hosts
- **Feature:** for hosts other than GitHub, return the steps to remove the credential and keep the revocation in "remote cleanup pending" until the user confirms.
- **Spec:** 04 section 4.5 step 4; 07 (manual steps).
- **Tests:**
  - [ ] T7.7-01 GitLab and any other host return manual steps.
  - [ ] T7.7-02 The state stays "remote cleanup pending" until the user confirms.
  - [ ] T7.7-03 Confirmation clears the pending state.
  - [ ] T7.7-04 Pending state survives a restart (stored in the data folder).
- **Green when:** G1 to G3, G6.
- **Commit:** `feat: T7.7 remote cleanup on other hosts`

#### T7.8 GitHub App key rotation (manual steps)
- **Feature:** after each revoke, show the manual steps to rotate the GitHub App's private key.
- **Spec:** 02 GitHub App key; 04 section 4.5. Manual steps only.
- **Tests:**
  - [ ] T7.8-01 After a revoke, the manual rotation steps are shown; Argus creates and revokes no App key.
  - [ ] T7.8-02 Cleanup stays pending until the user confirms the rotation.
  - [ ] T7.8-03 `argus config github-app` accepts the new key and replaces the Keychain item (T8.13-06).
- **Green when:** G1 to G4, G6.
- **Commit:** `feat: T7.8 GitHub App key rotation`

### Phase 8: CLI and agent

Every CLI task checks the exit codes in 06 section 6.6 and the stream rules in 06 section 6.1 (data to stdout, prompts to stderr).

#### T8.1 CLI skeleton and exit codes
- **Feature:** the `argus` binary, argument parsing with the exact command names, `-h`, `-v`, and the exit code table.
- **Spec:** 06 sections 6.1, 6.4, 6.6.
- **Tests:**
  - [ ] T8.1-01 `argus -v` prints the version and exits 0.
  - [ ] T8.1-02 `argus -h` prints help and exits 0.
  - [ ] T8.1-03 An unknown command exits 2.
  - [ ] T8.1-04 Each exit code in 06 section 6.6 is produced by at least one test (codes 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 130).
  - [ ] T8.1-05 Ctrl-C exits 130.
  - [ ] T8.1-06 Output for data goes to stdout; prompts and messages to stderr (checked with separate capture).
- **Green when:** G1 to G3, G6.
- **Commit:** `feat: T8.1 CLI skeleton and exit codes`

#### T8.2 Agent and lax time (CLI)
- **Feature:** a background agent holds the unlocked key on a Unix socket in the data folder (mode 0600). The lax time counts from the unlock. `lax-time` 0 means no cached key.
- **Spec:** 05 section (CLI); 08 test 15.
- **Tests:**
  - [ ] T8.2-01 The first unlock starts the agent.
  - [ ] T8.2-02 The socket is mode 0600 and owned by the same user; a connection from another user is refused.
  - [ ] T8.2-03 A second command within 45 s does not ask for the password.
  - [ ] T8.2-04 A command after 45 s asks for the password (time injected).
  - [ ] T8.2-05 Commands do not extend the lax time.
  - [ ] T8.2-06 `argus lock` zeroes the key and exits the agent; it succeeds when no agent runs.
  - [ ] T8.2-07 Sleep (simulated hook) zeroes the key.
  - [ ] T8.2-08 If the agent cannot start, every command asks for the master password.
  - [ ] T8.2-09 A wrong password can be entered 3 times, then exit 5.
  - [ ] T8.2-10 With `lax-time` 0, the rules in 05 apply: every modify and reveal asks each time; listing does not re-prompt beyond the unlock.
  - [ ] T8.2-11 No biometric path exists in the CLI.
- **Green when:** G1 to G4, G6.
- **Commit:** `feat: T8.2 agent and lax time`

#### T8.3 init and join commands
- **Feature:** `argus init` with prompts or `--remote` and `--name`; join mode prints the fingerprint and exits 8; `argus device verify` for the new device is in T8.12.
- **Spec:** 06 section 6.5.1; 04 section 4.1 and 4.2.
- **Tests:**
  - [ ] T8.3-01 `--remote` and `--name` skip those prompts; the master password is always prompted.
  - [ ] T8.3-02 Empty remote: init succeeds and exits 0.
  - [ ] T8.3-03 Remote with a store: join mode prints the fingerprint as 8 groups and exits 8.
  - [ ] T8.3-04 Remote with other files exits 1.
  - [ ] T8.3-05 Already initialised exits 1 with a hint.
  - [ ] T8.3-06 Network failure exits 6.
  - [ ] T8.3-07 The master password is not accepted as an argument (refused with exit 2).
- **Green when:** G1 to G4, G6.
- **Commit:** `feat: T8.3 init and join commands`

#### T8.4 add
- **Feature:** add a credential or secret note: type picker, optional prefill argument, password typed or generated, content from the editor or multi-line input, update on same URL and username with a warning.
- **Spec:** 06 section 6.5.2.
- **Tests:**
  - [ ] T8.4-01 The type picker accepts arrow keys, `j` and `k`, and a number, then Enter.
  - [ ] T8.4-02 Prefill fills the URL for a credential and the name for a note.
  - [ ] T8.4-03 An empty password field generates one with length 20 and the chosen sets.
  - [ ] T8.4-04 `--generate` and `--password-stdin` are the only non-interactive password sources; a password argument is refused (exit 2).
  - [ ] T8.4-05 A reserved name (for example `ls`) is refused for a note.
  - [ ] T8.4-06 Same URL and username prompts for update, shows the change, and asks before overriding.
  - [ ] T8.4-07 Non-interactive update needs `-y`.
  - [ ] T8.4-08 `--no-editor` reads lines until Ctrl-D.
  - [ ] T8.4-09 Ctrl-C cancels with exit 130 and writes nothing.
  - [ ] T8.4-10 The command writes the file and does not commit (T7.1).
  - [ ] T8.4-11 Non-interactive add with all required flags succeeds; a missing flag exits 2.
- **Green when:** G1 to G4, G6.
- **Commit:** `feat: T8.4 add`

#### T8.5 ls
- **Feature:** list credentials and secret notes by decrypted names, with optional filter, count, JSON, and flag filters. OTP entries are excluded.
- **Spec:** 06 section 6.5.3; 08 test 17.
- **Tests:**
  - [ ] T8.5-01 Output shows type and name only; no id column; no secret.
  - [ ] T8.5-02 `-f` filters by fuzzy search (T6.2).
  - [ ] T8.5-03 `-c` prints only the count after any filter.
  - [ ] T8.5-04 `--json` output is valid JSON with no secret field.
  - [ ] T8.5-05 `--rotate` keeps only entries with the rotate flag.
  - [ ] T8.5-06 `--conflicts` keeps only conflict copies.
  - [ ] T8.5-07 No matches prints nothing and exits 0.
  - [ ] T8.5-08 OTP entries never appear in `ls` output.
  - [ ] T8.5-09 The FLAGS column shows `r` and `c` as specified.
- **Green when:** G1 to G4, G6.
- **Commit:** `feat: T8.5 ls`

#### T8.6 show, --field, picker
- **Feature:** `argus <name>` shows an entry; `--field url|username|password|note` prints one value; ambiguous names use the picker or exit 4.
- **Spec:** 06 sections 6.3 and 6.5.4.
- **Tests:**
  - [ ] T8.6-01 A credential prints labelled URL, username, password and note lines.
  - [ ] T8.6-02 A secret note prints its content.
  - [ ] T8.6-03 `--field password` prints only the password with no label.
  - [ ] T8.6-04 Several matches in a terminal show the picker; outside a terminal the command exits 4 and prints candidates to stderr.
  - [ ] T8.6-05 No match exits 3.
  - [ ] T8.6-06 A reveal with `lax-time` 0 asks for the password (T8.2-10).
  - [ ] T8.6-07 The password is printed in clear only when asked; `-c` is the safer path (no test for the warning text beyond presence).
- **Green when:** G1 to G4, G6.
- **Commit:** `feat: T8.6 show, --field, picker`

#### T8.7 copy to clipboard
- **Feature:** `argus -c <name> [-t <seconds>]` copies the password and starts a detached helper that clears the clipboard after the time, only if it still holds the copied value.
- **Spec:** 05 section (clipboard); 06 section 6.5.5; 08 test 14.
- **Tests:**
  - [ ] T8.7-01 The command returns at once.
  - [ ] T8.7-02 Default time is 30 seconds; `-t 20` gives 20.
  - [ ] T8.7-03 `-t 0` is refused (minimum 1).
  - [ ] T8.7-04 The helper clears the clipboard after the time.
  - [ ] T8.7-05 The helper does not clear the clipboard if the user has copied something else.
  - [ ] T8.7-06 On macOS the item is concealed (checked with the pasteboard type).
  - [ ] T8.7-07 A secret note cannot be copied this way (exit 2).
  - [ ] T8.7-08 The helper holds no secret after clearing (T1.5 zeroise).
- **Green when:** G1 to G4, G6.
- **Commit:** `feat: T8.7 copy to clipboard`

#### T8.8 edit
- **Feature:** update fields of a credential or note; Enter keeps, typing replaces, `g` generates a new password; replacing the password clears the rotate flag; OTP entries are refused.
- **Spec:** 06 section 6.5.6; 08 test 17.
- **Tests:**
  - [ ] T8.8-01 Enter keeps each field.
  - [ ] T8.8-02 Typing replaces a field.
  - [ ] T8.8-03 `g` generates a new password.
  - [ ] T8.8-04 An empty password field keeps the password.
  - [ ] T8.8-05 Replacing the password clears `rotate`.
  - [ ] T8.8-06 Notes open the editor with the current text.
  - [ ] T8.8-07 Editing an OTP entry is refused with exit 2.
  - [ ] T8.8-08 `rev` and `updated` change; the entry is re-signed.
  - [ ] T8.8-09 Changing the URL or username updates the index at once.
  - [ ] T8.8-10 `edit` writes the file and does not commit (T7.1).
- **Green when:** G1 to G4, G6.
- **Commit:** `feat: T8.8 edit`

#### T8.9 rm
- **Feature:** delete an entry with a confirmation; `-y` skips it; a warning about git history appears the first time.
- **Spec:** 06 section 6.5.7.
- **Tests:**
  - [ ] T8.9-01 The entry is shown and `Delete? [y/N]` is asked.
  - [ ] T8.9-02 `N` or Enter cancels with nothing changed.
  - [ ] T8.9-03 `y` removes the file.
  - [ ] T8.9-04 `-y` skips the question.
  - [ ] T8.9-05 The first deletion shows the git-history warning; later ones do not.
  - [ ] T8.9-06 No match exits 3.
  - [ ] T8.9-07 Deleting an OTP entry with `rm` is refused (use `mfa rm`).
- **Green when:** G1 to G3, G6.
- **Commit:** `feat: T8.9 rm`

#### T8.10 push and pull commands
- **Feature:** `argus push` and `argus pull`, refusing while conflicts exist (exit 9), with exit 6 and exit 7 for network and verification failures.
- **Spec:** 06 section 6.5.8; 04 section 4.8.
- **Tests:**
  - [ ] T8.10-01 Push with a clean remote exits 0.
  - [ ] T8.10-02 Pull reports new, changed and deleted counts.
  - [ ] T8.10-03 Push and pull with an unresolved conflict exit 9 and do nothing.
  - [ ] T8.10-04 Network failure exits 6 after the 3 retries; the user is asked whether to try again.
  - [ ] T8.10-05 Verification failure exits 7; nothing from the pull is used.
  - [ ] T8.10-06 A rejected push retries exactly 3 times, then asks.
  - [ ] T8.10-07 `promote` resolves the conflict and the next push works.
- **Green when:** G1 to G4, G6.
- **Commit:** `feat: T8.10 push and pull commands`

#### T8.11 mfa commands
- **Feature:** `mfa ls`, `mfa add` (URL or `--qr` image, `--link`), `mfa rm`, and `mfa <name> [-c]` for codes.
- **Spec:** 06 section 6.5.9; 05 (reveal rules; HOTP counter).
- **Tests:**
  - [ ] T8.11-01 `mfa ls` lists label, issuer and TOTP or HOTP, never codes.
  - [ ] T8.11-02 `mfa ls -f` filters.
  - [ ] T8.11-03 `mfa add` shows label, issuer, algorithm, digits and period, and asks to confirm.
  - [ ] T8.11-04 `mfa add` with both a URL and `--qr` exits 2.
  - [ ] T8.11-05 `mfa add --qr` decodes a QR code image (fixture images for valid and invalid cases).
  - [ ] T8.11-06 `--link` ties the OTP to an existing credential; a missing credential is refused.
  - [ ] T8.11-07 `mfa <name>` shows the code and seconds left.
  - [ ] T8.11-08 `mfa <name> -c` copies the code and clears it after 30 s.
  - [ ] T8.11-09 HOTP: showing a code advances the counter and reports it.
  - [ ] T8.11-10 `mfa rm` asks for confirmation; `-y` skips it.
  - [ ] T8.11-11 Showing a code follows the unlock rules (no extra prompt inside the lax time).
- **Green when:** G1 to G4, G6.
- **Commit:** `feat: T8.11 mfa commands`

#### T8.12 device commands
- **Feature:** `device ls`, `device add` (approve), `device verify` (finish joining), `device rm` (revoke).
- **Spec:** 06 section 6.5.10; 04 sections 4.3 to 4.5.
- **Tests:**
  - [ ] T8.12-01 `device ls` shows trusted devices, pending requests with fingerprints, and devices with cleanup pending.
  - [ ] T8.12-02 `device add` prints the fingerprint and asks `Does this match the new device's screen? [y/N]`.
  - [ ] T8.12-03 `N` aborts with nothing changed.
  - [ ] T8.12-04 After `y`, the anchor is printed; `--qr` also prints a QR code.
  - [ ] T8.12-05 `device verify` with the anchor completes joining; a wrong anchor exits 7.
  - [ ] T8.12-06 `device rm` asks for confirmation, revokes, and prints the manual steps or runs GitHub cleanup.
  - [ ] T8.12-07 Revoking the device you are on is refused.
  - [ ] T8.12-08 The command ends by pointing to `argus ls --rotate`.
- **Green when:** G1 to G4, G6.
- **Commit:** `feat: T8.12 device commands`

#### T8.13 lock, passwd, config, promote
- **Feature:** `argus lock`, `argus passwd`, `argus config get|set` (keys `lax-time`, `clear-after`, `editor`, remote URL) and `config github-app`, `argus promote <name>`.
- **Spec:** 06 section 6.5.11 and 6.5.12.
- **Tests:**
  - [ ] T8.13-01 `lock` succeeds with or without an agent.
  - [ ] T8.13-02 `passwd` prompts for old and new password (new typed twice) and changes only `device.key` (T2.3).
  - [ ] T8.13-03 `config set lax-time 0` and `get` round-trip.
  - [ ] T8.13-04 `config set clear-after 0` is refused.
  - [ ] T8.13-05 Unknown config keys are refused with exit 2.
  - [ ] T8.13-06 `config github-app` stores credentials in the Keychain, not in `config`.
  - [ ] T8.13-07 `promote <name>` lists conflict copies, takes a choice, and deletes the previous current version.
  - [ ] T8.13-08 `promote` on an entry without conflicts exits 3.
- **Green when:** G1 to G4, G6.
- **Commit:** `feat: T8.13 lock, passwd, config, promote`

#### T8.14 Non-interactive mode
- **Feature:** when stdin or stdout is not a terminal, commands that would prompt fail with an exit code, not a guess.
- **Spec:** 06 section 6.1.
- **Tests:**
  - [ ] T8.14-01 `argus add` without a terminal and without flags exits 2.
  - [ ] T8.14-02 `argus rm` without `-y` and without a terminal exits 2.
  - [ ] T8.14-03 Ambiguous names without a terminal exit 4 (T8.6-04).
  - [ ] T8.14-04 Colours are off when output is not a terminal or `NO_COLOR` is set.
  - [ ] T8.14-05 A command with all flags given never prompts (checked with a closed stdin).
- **Green when:** G1 to G3, G6.
- **Commit:** `feat: T8.14 non-interactive mode`

#### T8.15 Editor hygiene
- **Feature:** the editor runs in a private temporary folder (mode 0700), with swap, backup and undo off; the temp file is deleted afterwards, even on error.
- **Spec:** 05 section (editing with an editor).
- **Tests:**
  - [ ] T8.15-01 `$VISUAL` is used first, then `$EDITOR`, then vim.
  - [ ] T8.15-02 The temp folder is mode 0700.
  - [ ] T8.15-03 Vim is started with `-n -i NONE`.
  - [ ] T8.15-04 The temp file is deleted after a normal exit.
  - [ ] T8.15-05 The temp file is deleted after the editor fails.
  - [ ] T8.15-06 The temp file is deleted after Ctrl-C.
- **Green when:** G1 to G4, G6.
- **Commit:** `feat: T8.15 editor hygiene`

### Phase 9: apps

Apps use the same core through UniFFI. Each screen task names its wireframe section in `07-apps-ui.md`. UI tests are XCUITest in `xcodebuild test`.

#### T9.1 UniFFI bindings and XCFramework
- **Feature:** UniFFI-generated Swift bindings; an XCFramework for macOS, iOS device and simulator; a smoke test that unlocks a test store.
- **Spec:** 01 architecture; 01 core API.
- **Tests:**
  - [ ] T9.1-01 The XCFramework builds for macOS, iOS device and simulator.
  - [ ] T9.1-02 The Swift package imports the framework.
  - [ ] T9.1-03 A smoke test unlocks a fixture store from Swift.
  - [ ] T9.1-04 No platform type crosses the boundary (checked by the FFI interface file).
  - [ ] T9.1-05 Errors map to the enum in 01 core API.
- **Green when:** G2 (Apple job), G3, G6.
- **Commit:** `feat: T9.1 UniFFI bindings and XCFramework`

#### T9.2 Swift SecureStorage
- **Feature:** implement the core's `SecureStorage` with the Keychain, this device only, no biometrics in v1.
- **Spec:** 02 (Keychain items); 01 core API.
- **Tests:**
  - [ ] T9.2-01 Save, load and delete work with the Keychain on macOS.
  - [ ] T9.2-02 Items are marked this-device-only (no iCloud sync).
  - [ ] T9.2-03 A missing item returns nil.
  - [ ] T9.2-04 No biometric access control is set in v1.
- **Green when:** G2 (Apple job), G6.
- **Commit:** `feat: T9.2 Swift SecureStorage`

#### T9.3 macOS shell, unlock and lock
- **Feature:** the app window, the Unlock screen, the lax time from the last interaction, lock on inactivity.
- **Spec:** 07 sections 7.2 and 7.3.1; 05 apps.
- **Tests:**
  - [ ] T9.3-01 The app opens on Unlock (7.3.1 layout).
  - [ ] T9.3-02 A wrong password shows "Wrong password. Try again."
  - [ ] T9.3-03 A correct password opens the sidebar layout.
  - [ ] T9.3-04 Interaction restarts the lax time; no interaction for 45 s locks.
  - [ ] T9.3-05 Lock zeroes the keys and returns to Unlock.
- **Green when:** G2 (Apple job), G6.
- **Commit:** `feat: T9.3 macOS shell, unlock and lock`

#### T9.4 macOS entries, detail, reveal, copy
- **Feature:** the sidebar, the All list grouped by type with collapsible labels (OTP excluded), the detail pane, inline reveal, copy with a 30 s clear.
- **Spec:** 07 sections 7.2, 7.3.2, 7.3.4; 06 copy rules.
- **Tests:**
  - [ ] T9.4-01 All groups entries under Logins and Notes; OTP entries are absent.
  - [ ] T9.4-02 Labels show a count; collapsing hides the children.
  - [ ] T9.4-03 Sidebar items Logins, Notes, Rotate(n), Conflicts filter correctly.
  - [ ] T9.4-04 The detail pane shows the 7.3.2 layout; Edit and Delete sit on the right.
  - [ ] T9.4-05 Show reveals the password inline; hides when the entry is left.
  - [ ] T9.4-06 Copy places the password on the pasteboard, concealed, and clears it after 30 s.
  - [ ] T9.4-07 A countdown toast shows during the clear.
- **Green when:** G2, G6.
- **Commit:** `feat: T9.4 macOS entries, detail, reveal, copy`

#### T9.5 macOS add and edit popup, generator
- **Feature:** the add and edit sheet (7.3.5), the generator panel, the duplicate warning, the note variant.
- **Spec:** 07 section 7.3.5; 06 section 6.5.2 and 6.5.6.
- **Tests:**
  - [ ] T9.5-01 Add shows the credential fields; the type radio switches to the note fields.
  - [ ] T9.5-02 Edit uses the same sheet with the title "Edit entry" and values filled.
  - [ ] T9.5-03 Generate opens the panel with length 20 and three set checkboxes.
  - [ ] T9.5-04 Turning all sets off disables Use and shows the reason.
  - [ ] T9.5-05 A matching URL and username shows the update warning.
  - [ ] T9.5-06 Strength is shown and never blocks Save.
  - [ ] T9.5-07 Save writes the entry and does not commit (T7.1).
- **Green when:** G2, G6.
- **Commit:** `feat: T9.5 macOS add and edit popup, generator`

#### T9.6 macOS sync button, conflicts, rotation list
- **Feature:** the sync button with its states (7.4), the conflict screen (7.4.1), the passwords-to-change screen (7.4.2).
- **Spec:** 07 sections 7.4, 7.4.1, 7.4.2; 04 sync.
- **Tests:**
  - [ ] T9.6-01 Up to date shows the green icon; out of date the orange `!`; conflict the red `x`.
  - [ ] T9.6-02 Tapping out of date pulls or pushes per the rule.
  - [ ] T9.6-03 Syncing shows a spinning button.
  - [ ] T9.6-04 Conflict blocks sync and opens the conflict list.
  - [ ] T9.6-05 "Use current" and "Use older" each delete the other copy.
  - [ ] T9.6-06 The security alert shows the red shield banner on every screen.
  - [ ] T9.6-07 Passwords to change lists flagged entries; Generate saves a new password and clears the flag; Done clears the flag only.
  - [ ] T9.6-08 The count "N of M left" updates.
- **Green when:** G2, G6.
- **Commit:** `feat: T9.6 macOS sync, conflicts, rotation list`

#### T9.7 macOS devices, MFA, settings
- **Feature:** the Devices screen (7.3.7), the MFA screen (7.3.6), Settings (7.3.9).
- **Spec:** 07 sections 7.3.6, 7.3.7, 7.3.9.
- **Tests:**
  - [ ] T9.7-01 Devices lists Trusted (this device marked), Waiting for approval, Removed with cleanup pending.
  - [ ] T9.7-02 Review shows the fingerprint and Approve or Reject; Approve shows the anchor and Done.
  - [ ] T9.7-03 Remove device shows the warning text from 7.3.7 and Cancel or Remove.
  - [ ] T9.7-04 MFA lists OTP entries with Show; after Show, the code, seconds and Copy appear.
  - [ ] T9.7-05 Add OTP takes a URL or a QR image; Link to lists credentials.
  - [ ] T9.7-06 Settings shows theme, sync fields, security fields (lax time, clipboard time), and Biometrics "Next version".
  - [ ] T9.7-07 Changing lax time or clipboard time writes `config`.
- **Green when:** G2, G6.
- **Commit:** `feat: T9.7 macOS devices, MFA, settings`

#### T9.8 iOS app
- **Feature:** the same screens in the tab layout (7.2 iOS), the first-launch flows (7.3.8), pull-to-sync, and the backup-excluded data folder.
- **Spec:** 07 sections 7.2, 7.3.3, 7.3.8; 01 data folder (iOS).
- **Tests:**
  - [ ] T9.8-01 Tab bar shows Entries, MFA, Devices, Settings.
  - [ ] T9.8-02 Entries shows the sync button and Add in the top bar.
  - [ ] T9.8-03 Pulling down on the list syncs.
  - [ ] T9.8-04 The detail screen shows Edit above Delete.
  - [ ] T9.8-05 First launch shows Welcome, Setup, and (when joining) Waiting for approval and Verify.
  - [ ] T9.8-06 The data folder has the backup-excluded attribute.
  - [ ] T9.8-07 Clipboard copy uses local-only with an expiry (07 and 05).
- **Green when:** G2 (Apple job), G6.
- **Commit:** `feat: T9.8 iOS app`

#### T9.9 Blur, lock triggers, clipboard expiry
- **Feature:** blur in previews and background; lock on display off, screen lock and user switch; the same rules on every device.
- **Spec:** 05 apps; 07 section 7.1.
- **Tests:**
  - [ ] T9.9-01 Moving to the background blurs the content (macOS and iOS).
  - [ ] T9.9-02 Switching to another app blurs the content.
  - [ ] T9.9-03 Display off, screen lock and user switch lock the app.
  - [ ] T9.9-04 Each of these locks zeroes the key (verified with a test hook).
  - [ ] T9.9-05 `lax-time` 0 requires the password for every modify and reveal in the app.
  - [ ] T9.9-06 Copy's expiry on iOS is set to 30 s.
- **Green when:** G2, G6.
- **Commit:** `feat: T9.9 blur, lock triggers, clipboard expiry`

#### T9.10 Accessibility and localisation
- **Feature:** the accessibility rules in 07 section 7.6; dates in DD-MM-YYYY and HH:mm in device time in every language.
- **Spec:** 07 section 7.6; 09 Vietnamese (next version, not in v1).
- **Tests:**
  - [ ] T9.10-01 Every control has a VoiceOver label (automated audit lists zero missing labels).
  - [ ] T9.10-02 A revealed secret is announced once.
  - [ ] T9.10-03 Dynamic Type at the largest size does not clip the main screens (snapshot test).
  - [ ] T9.10-04 Full keyboard access on macOS covers the sidebar, list and popups.
  - [ ] T9.10-05 Status is never shown by colour alone (the symbol is present for every sync state).
  - [ ] T9.10-06 Contrast meets WCAG 2.1 AA on all screens (automated check).
  - [ ] T9.10-07 Reduce Motion stops the sync animation.
  - [ ] T9.10-08 Dates render as DD-MM-YYYY and times as HH:mm for three device locales.
  - [ ] T9.10-09 All user strings are in resource files (no literal strings in views; checked by a lint).
- **Green when:** G2, G6.
- **Commit:** `feat: T9.10 accessibility and localisation`

### Phase 10: hardening and release

#### T10.1 Fuzzing
- **Feature:** fuzz targets for the entry parser, the device list parser, the join request parser, `store.json`, and the `otpauth` parser.
- **Spec:** 08 test 16; 01 milestone 8.
- **Tests:**
  - [ ] T10.1-01 Each target builds with `cargo-fuzz`.
  - [ ] T10.1-02 Each target runs for at least 10 minutes in CI with no crash, panic or timeout.
  - [ ] T10.1-03 Every crash found is turned into a regression test before the fix.
  - [ ] T10.1-04 The corpus is committed.
- **Green when:** G1, G2, and the fuzz runs pass.
- **Commit:** `test: T10.1 fuzzing`

#### T10.2 Log audit
- **Feature:** an audit that the logs contain only the allowed fields and never a forbidden one.
- **Spec:** 01 logging; 08 test 13.
- **Tests:**
  - [ ] T10.2-01 A full run of unlock, add, reveal, copy, sync and revoke writes logs containing no password, note, OTP code, master password or entry name.
  - [ ] T10.2-02 `argus.log` is mode 0600.
  - [ ] T10.2-03 Logging is off unless `config` sets `log = info`.
  - [ ] T10.2-04 Rotation at 1 MB keeps three files.
  - [ ] T10.2-05 Debug-level output is absent from release builds.
- **Green when:** G1, G4, G6.
- **Commit:** `chore: T10.2 log audit`

#### T10.3 Limits and performance
- **Feature:** enforce 20 devices, 10,000 entries, 1 MiB per entry, and measure unlock and search times.
- **Spec:** 01 limits and performance.
- **Tests:**
  - [ ] T10.3-01 The 21st trusted device is refused.
  - [ ] T10.3-02 The 10,001st entry is refused.
  - [ ] T10.3-03 Unlock with 1,000 entries completes in under 500 ms on the reference runner.
  - [ ] T10.3-04 Search over 1,000 entries completes in under 50 ms.
  - [ ] T10.3-05 Results and the reference hardware are recorded in the commit message.
- **Green when:** G1 to G3, performance tests pass on the reference runner, G6. If a target is missed, the task is BLOCKED and the owner decides.
- **Commit:** `chore: T10.3 limits and performance`

#### T10.4 Argon2id benchmark and fallback
- **Feature:** measure Argon2id at opslimit 3 / memlimit 256 MiB and the 2 / 64 MiB fallback on the reference devices; confirm the parameters fit the memory limit.
- **Spec:** 02 master password and unlock; 03 section 3.2.
- **Tests:**
  - [ ] T10.4-01 opslimit 3 / 256 MiB takes about one second on the reference Mac (recorded).
  - [ ] T10.4-02 opslimit 3 / 256 MiB takes about one second on the reference iPhone (recorded).
  - [ ] T10.4-03 The fallback to opslimit 2 / 64 MiB triggers on a device that cannot allocate 256 MiB (simulated).
  - [ ] T10.4-04 The app does not exceed its memory limit at 256 MiB on the reference iPhone.
- **Green when:** G6, measurements recorded. If the iPhone cannot run 256 MiB, the owner decides.
- **Commit:** `chore: T10.4 Argon2id benchmark and fallback`

#### T10.5 Format migration
- **Feature:** `argus migrate` for a breaking format change: back up, rewrite, commit once as `update`, push; a failure leaves the backup and an unchanged remote.
- **Spec:** 03 section 3.9.
- **Tests:**
  - [ ] T10.5-01 A format 1 store with a fixture format 2 migration produces `store.bak-1/`.
  - [ ] T10.5-02 After migration the store reads as format 2.
  - [ ] T10.5-03 A failure midway leaves the backup in place and the remote unchanged.
  - [ ] T10.5-04 Other devices refuse to sync until they update (`FormatUnsupported`).
  - [ ] T10.5-05 Additive changes keep format 1 and older clients keep unknown types.
- **Green when:** G1 to G4, G6.
- **Commit:** `feat: T10.5 format migration`

#### T10.6 Build from source instructions
- **Feature:** a documented build from a clean checkout, with the toolchain versions.
- **Spec:** 01 distribution.
- **Tests:**
  - [ ] T10.6-01 A clean CI container follows the instructions and builds `argus`.
  - [ ] T10.6-02 The macOS app builds from the instructions.
  - [ ] T10.6-03 The build uses no network beyond fetching declared dependencies.
  - [ ] T10.6-04 The toolchain versions are pinned in the repo.
- **Green when:** G2 (clean-container job), G6.
- **Commit:** `docs: T10.6 build from source instructions`

#### T10.7 External security review
- **Feature:** an independent review of the core, the protocol and the apps before 1.0.
- **Spec:** 01 milestone 8.
- **BLOCKED (external):** needs a reviewer and a scope. Not automatable.
- **Green when:** the review is complete and every finding is fixed or accepted by the owner.
- **Commit:** `fix: T10.7 external review fixes`
