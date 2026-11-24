# 8. Testing

## Required test categories

1. **Interop**: the core encrypts and decrypts entries with dryoc; vectors written by dryoc decrypt through the C libsodium (via `libsodium-sys-stable`) in CI, and vice versa, an independent implementation, so a format bug in either is still caught.
2. **Canonical JSON and hashing**: device list and entry signing inputs match vectors.
3. **Device list chain**: valid chains of versions 1 to 3; invalid chains for: wrong `prev`, signer not in the previous version, self-added device, lower version (rollback), same version with different bytes (fork), empty device list.
4. **Fingerprints and anchors**: fixed keys produce fixed fingerprints and anchors.
5. **Join request**: a request verifies only with its own self-signature.
6. **Sealed-recipient addition**: an added recipient can decrypt, and the payload still decrypts for the original recipients after a sealed key is appended (the nonce, payload and file key are unchanged).
7. **Reconcile**: an `rcount` mismatch is repaired in both directions.
8. **Conflicts**: ordering by git history, not by `rev` or timestamps; older versions become conflict copies; sync is blocked until resolved.
9. **Revoke**: all entries re-encrypted, re-signed, rotate flags set; revoked device cannot decrypt new entries.
10. **Search**: fuzzy ranking; exact match preferred; single fuzzy match auto-selected; picker used otherwise; reserved names rejected.
11. **Padding**: plaintext sizes are multiples of 512 bytes.
12. **CLI exit codes**: each code in `06-cli.md` section 6.6 is produced by at least one test.
13. **Secrets hygiene**: no secret appears in logs, arguments, or error text (scan test output in CI).
14. **Clipboard**: the helper clears only when the value still matches.
15. **Lock**: the agent zeroes the key at lax-time expiry, on `lock`, and on sleep (CLI); apps lock per `05-sessions-and-lock.md`.
16. **Parsers**: fuzzing of entry, device list, join request and store.json parsers.
17. **OTP separation**: `argus ls` and the apps' All list never include OTP entries; `argus edit` refuses OTP entries.
18. **Commit timing**: add, edit, rm and mfa changes create no commit until push or pull; every commit message is `update`, except `init`.
19. **Retries**: a rejected push or pull retries exactly 3 times, then asks.
20. **Unreachable remote**: network failure retries 3 times then asks; a removed device locks all sessions and offers only Delete local data.
21. **Search scope**: `-f` matches name fields only, including OTP issuer.
22. **Git backends**: the system `git` and libgit2 give identical commits and refs for the same input, and every sync case passes on both.

## Vectors to produce (milestone 1)

- One entry encrypted with dryoc and decrypted by the C libsodium reference, with its signature.
- Canonical JSON and hashes for a device list.
- A valid chain of three versions, plus each invalid case above.
- Fingerprints and an anchor from fixed keys.
- A join request and its signature.
- A sealed-recipient addition, decryptable by dryoc and by the C libsodium reference.

Vectors live in `core/vault-core/tests/vectors/`. They are generated from fixed seeds by the Rust core. Run `cargo test` in `core/`.
