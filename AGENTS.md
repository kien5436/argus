# Argus: instructions for AI coding agents

Argus is a password and MFA manager whose encrypted data lives in a git repository, similar to `pass`. Each entry is one age-encrypted file, readable only by trusted devices. Security-critical logic lives in one Rust core. Native UIs (SwiftUI for macOS and iOS first; Qt and WinUI later) and a command-line tool (`argus`) sit on top of it.

Status: design complete for v1, no code yet. Spec version 0.2, 22 November 2026.

## Read order

1. `docs/01-overview.md`: goals, scope, architecture, data folders, repository layout.
2. `docs/02-security-model.md`: keys, unlock, device trust, threat model, accepted risks.
3. `docs/03-store-format.md`: exact on-disk format. Byte-level rules live here.
4. `docs/04-device-lifecycle.md`: init, join, approve, verify, revoke, sync, conflicts.
5. `docs/05-sessions-and-lock.md`: lax time, agent, locking, clipboard.
6. `docs/06-cli.md`: every `argus` command, flags, exit codes.
7. `docs/07-apps-ui.md`: screens, sync button states, lock and blur behaviour.
8. `docs/08-testing.md`: required tests and test vectors.
9. `docs/09-next-version.md`: features specified but out of v1.
10. `docs/10-implementation-plan.md`: the build order, the tracker, and the test cases. Work from this file.

## Rules

1. These documents are the source of truth. If code and documents disagree, stop and report the file and section. Do not silently change either.
2. Implement what the documents specify. If a rule is missing, ask the owner.
3. Do not build anything from `09-next-version.md` in v1, not even partially.
4. Use exact names. CLI command and flag names, exit codes, file names, JSON field names and domain-separation prefixes are part of the contract.
5. Use the glossary below. Do not introduce synonyms in code or UI text.
6. MUST is required. SHOULD is a strong default; deviating needs a stated reason. MAY is optional.
7. If a rule is ambiguous or missing, ask the owner. Do not choose a default and bury it in code.
8. Build in the order of `docs/10-implementation-plan.md`. Do not start a task until every earlier task is green. A task is green only when its test cases pass and its green checks hold. Commit once per green task with the message `T<id>: <title>`, updating the tracker in the same commit. Do not skip a BLOCKED task; stop and report it.
9. Tests use only the production API. Never add test-only methods, hooks, seams or backdoors to production code to make testing easier. Design the production API so tests exercise shipped code: genuine dependencies (clocks, RNGs, KDFs, storage) enter through constructor parameters, and anything unobservable from outside is verified by `#[cfg(test)]` unit tests, which never ship. Security is the most important criterion of this project; it outranks test convenience. Where `docs/10-implementation-plan.md` mandates a test-only hook, implement it as a `#[cfg(test)]` unit test instead and record the deviation in the commit.

## Security invariants (MUST hold everywhere)

- Never write a master password, private key, decrypted password, OTP secret or OTP code to disk, git, logs, crash reports, environment variables or command-line arguments.
- Zero secret memory when it is no longer needed. Use `zeroize` or equivalent in Rust. Do not keep decrypted passwords in long-lived structures.
- Git runs through the system `git` when it is available, otherwise through libgit2 in the core. Both backends sit behind one interface and must give the same commits and refs.
- Never pass a secret to `git` in an argument or environment variable. Credentials come from ssh-agent, the ssh configuration, or the Keychain through a credential helper.
- Verify the signed device list before encrypting to any recipient or trusting any entry. Reject rollbacks and forks. Never auto-merge device lists.
- Never order conflicting versions by timestamps or `rev`. Order comes from git history.
- Entry file names are random ids. Never put site names, usernames, entry names or other metadata in file names, directory names or commit messages.
- Never delete a damaged entry automatically. Never resolve or overwrite a conflict without the user's choice.
- Network calls go only to the configured git remote and, for GitHub, the GitHub API during revoke.
- The core never calls OS keystore APIs directly. It calls the `SecureStorage` interface, which each platform implements.
- Do not force password rules. The generator and the strength meter are informational.

## Glossary

- **store**: the git repository plus its `.argus/` metadata folder.
- **entry**: one encrypted file holding one credential, one note, or one OTP.
- **credential**: an entry type with URL, username, password and note.
- **note**: an entry type with a name and content, shown in the UI as "secret note". The word also names a credential field; check the context.
- **otp**: an entry type holding a TOTP or HOTP secret. Managed only by `argus mfa` commands and the MFA screen.
- **device**: one installation of Argus with its own keys (`device.key`).
- **trusted device**: a device in the newest verified device list.
- **device list**: `.argus/devices.json`, signed, versioned, hash-chained.
- **pending request**: a join request waiting for approval.
- **fingerprint**: 8 groups of hex shown on a device so a person can compare it with another screen.
- **anchor**: the version and 8 groups of hex that an approving device shows so the new device can verify the approval.
- **lax time**: the period during which the user is not asked for the master password again. Default 45 seconds.
- **agent**: the background process that holds the unlocked key for the CLI.
- **conflict copy**: an older version of an entry kept when two devices changed the same entry.
- **rotate flag**: marks an entry whose password should be changed on the website. Set on every entry after a revoke.
- **data folder**: the per-platform folder holding `device.key`, `trust.json`, `config` and the git checkout under `.argus/`.

## Repository layout to build

```
core/
  vault-core/     age, store, entries, OTP, generator, device list, git (system git or libgit2)
  vault-ffi/      UniFFI interface and generated bindings
  cli/            the argus binary and the agent
apple/            Swift package wrapping the XCFramework; SwiftUI apps
```

## Working with these docs

- A behaviour change changes the document in the same commit, and the commit message cites the file and section.
- Add the tests from `08-testing.md` for every feature you finish.
- If you find a gap, report it to the owner. Do not add rules to the docs yourself.
