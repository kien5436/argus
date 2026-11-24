# 9. Next version (out of v1)

Specified so the v1 design leaves room for them. Do not implement in v1. Where v1 code must not block a future feature, that is noted.

## File and folder encryption (`enc`, `dec`)

- `argus enc <file>` and `argus dec <file>`; `-r <folder>` for folders. Output uses the `.arg` suffix. Original names and folder structure are kept, and the original is kept.
- Encryption is to one dedicated file-encryption keypair, shared by all trusted devices. Its public key is in the repository. Its private key is stored in the store, encrypted to every trusted device like an entry.
- `dec` tries file-encryption private keys from newest to oldest. Revoking a device creates a new key generation for new files; old private keys stay in the store.
- Encrypted files are not synced. The user moves them to another machine. A recipient needs Argus and a trusted device.
- Folders: stream large files. Do not follow symlinks. Skip files that are already encrypted. Write to a temporary file and rename.
- Later option: `--passphrase` for handing a file to someone without Argus. A passphrase-encrypted file cannot have other recipients.
- v1 requirement: the core's recipient handling must not assume there is only one kind of recipient.

## Recovery key

- An extra offline recipient, generated once at `init` and shown to the user.
- Optional, with a clear warning. Because it can decrypt everything, it is a second secret that must be stored carefully.
- Not decided: offer, require, or omit.

## Import from other managers

- Candidates: Bitwarden, 1Password, Chrome, pass. Which first is undecided.

## Vietnamese localisation

- Add Vietnamese as a UI language in the next version. All user-facing strings must already be in resource files (see `07-apps-ui.md`, section 7.6).
- Dates stay DD-MM-YYYY, and times stay HH:mm, in device time, in every language.
- The CLI picker and its prompts are translated too; command names, flags and exit codes stay in English.

## Biometric unlock in the apps

- Touch ID or Face ID unlocks a cached copy of `device.key` held in the Keychain behind biometric access control (current enrolment only, this device only).
- The master password remains the root of trust. Three failed biometric attempts, or a reboot, require the master password.
- The CLI never uses biometrics, and does not read the app's biometric cache.
- The biometric unlock button joins the Unlock screen.

## iOS AutoFill and passkeys

- Credential provider extension for passwords (iOS 12+), passkeys in third-party providers (iOS 17+), and OTP codes in the credential provider (iOS 18+; macOS 15 equivalent). Because the minimum iOS version is 16, passkey and OTP AutoFill degrade to copy and paste there.
- The extension needs low memory and no UI beyond system sheets. It needs the data folder moved to an App Group container. v1 must keep the data folder path behind the platform layer so this move is possible.
- It cannot run Argon2id at the full memory limit. It needs the biometric-cached key, so it depends on the biometric feature.

## Other

- Browser extension: WASM build of the same core, when needed.
- Qt (via cxx-qt or a C ABI) and WinUI (via a community UniFFI generator for C#) clients.
- Linux and Windows data folder paths, and their keystore implementations of `SecureStorage`.
- Automatic remote cleanup for GitLab and other hosts.
- Blur, lock and clipboard behaviour on Android and other platforms, when those exist.
