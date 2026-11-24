# 2. Security model

## Core idea

The repository is encrypted to public keys, as in `pass`. Each device holds a private key that never leaves it. A repository reader without a trusted device learns nothing about entry contents. A stolen repository is useless without a trusted device's private key and its master password.

## Device keys

Each device generates two keypairs at setup:

- An X25519 keypair (`crypto_box` in the dryoc library). Used to decrypt entries.
- An Ed25519 signing keypair. Used to sign the device list and each entry.

Both private keys are stored in `device.key` in the data folder, encrypted with the master password (see below). Only public keys are shared, via the repository.

## Master password and unlock

- The master password protects `device.key` through Argon2id (`crypto_pwhash` in dryoc), which derives a 32-byte key that encrypts the device keys.
- Parameters: Argon2id with opslimit = 3 and memlimit = 256 MiB. If the device cannot allocate 256 MiB, reduce opslimit to 2. The salt and both parameters are stored in the file header.
- Target: about one second on the slowest supported device.
- Changing the master password rewrites only `device.key`, with a new passphrase, salt and nonce. Nothing in git changes.
- The master password is never stored, never synced, and never written to the repository.
- Strength is estimated at setup and shown for information. It never blocks.

## Unlock lifecycle

- Unlock decrypts `device.key` into memory and starts the lax time (see `05-sessions-and-lock.md`).
- Locking zeroes the private keys and the in-memory search index.

## Biometrics (next version)

Not in v1. When added, biometrics unlock a cached copy of the device key held in the Keychain behind biometric access control. The master password remains the root of trust. After three failed biometric attempts, or after a reboot, the master password is required.

## Device list and trust

- The device list (`devices.json` in the store root, `.argus/devices.json` from the data folder) is signed by a trusted device's signing key and hash-chained to the previous version.
- The first version is signed by the device that created the store.
- Clients verify the chain before using any recipient. They pin the newest verified version in `trust.json`.
- A lower version is a rollback and is rejected. The same version with different bytes is a fork and raises a security alert. Both stop sync.
- Any trusted device can approve a join request. The new device is never trusted by itself.

## Entry signatures

Entries are signed by the device that wrote them. A client accepts an entry only if its signer is in the current verified device list. This stops a writer with only repository access from inserting entries.

## Recovery

No recovery key in v1. The surviving trusted devices are the backup. If every device is lost, the vault is lost. The next version may add a recovery key; see `09-next-version.md`.

## Revocation

Revoking a device:

- Removes it from the device list, with a new signed version.
- Re-encrypts every entry for the remaining devices, with fresh file keys, re-signs each entry, and sets its rotate flag.
- Removes its remote access where Argus can (GitHub in v1). Otherwise shows the manual steps.

Revocation cannot undo what the device already has. Its clone and old ciphertext in git history remain readable with its key. Argus says so and asks the user to rotate important passwords.

## Threat model

In scope for v1:

| Adversary | Protection |
| --- | --- |
| Reader of the repository, no trusted device | Sees only ciphertext. Learns entry count, file sizes, and commit times. Cannot learn names. |
| Writer to the repository (stolen git token) | Cannot add a recipient or insert an entry without a valid signature. Cannot roll back the device list on a device that has pinned a newer version. |
| Thief of a device's `device.key` file | Must guess the master password. The KDF cost and the strength warning are the defence. |
| Revoked device | Keeps what it already has. Re-encryption stops it reading new entries. |

Out of scope for v1:

- Malware or another process running as the user on an unlocked device.
- Memory forensics of a running, unlocked process beyond zeroing.
- Coercion of the master password.

## Known risks accepted for v1

- **One unlock exposes everything.** While unlocked, the user can reveal every password, secret note, and OTP code without re-entering the master password, so one unlocked session defeats both factors. This was accepted for usability. Accepted for v1.
- **Search index in memory.** The index of decrypted names and URLs is a sensitive structure. It is memory-only and dropped on lock, but it is not yet protected. Hardening is planned.
- **Swift strings are not zeroable.** Passwords that reach SwiftUI text fields leave copies that cannot be wiped. Keep plaintext lifetimes short and pass bytes where possible.
- **GitHub App private key.** It can manage deploy keys on the store repository. It lives in the Keychain of the device that set it up. Compromise of that device exposes the ability to change the repository's deploy keys. After each revoke, Argus rotates the App's private key.
- **Crypto library.** The core uses dryoc, a pure-Rust, libsodium-compatible library with a smaller audit history than the C libsodium. Its wire formats are cross-tested against the C libsodium in CI. Every crypto call goes through one wrapper module, so the backend can be swapped later without touching callers. Accepted for v1.

## Invariants for implementers

- Never decrypt an entry for a recipient not in the verified list.
- Verify the device list before every encryption.
- Never log secrets, including in debug builds.
- Compare fingerprints only by an out-of-band channel (QR scan or the person reading the 8 groups). Never by git.
