# 6. CLI reference (`argus`)

## 6.1 Conventions

- `<x>` is required. `[x]` is optional.
- Data the user asked for (`argus <name>`, `argus mfa <name>`, `argus ls`) goes to stdout. Prompts, progress and messages go to stderr. Prompts read from the terminal directly, so pipes keep working.
- Secrets never appear in arguments, environment variables or logs. Passwords come from a hidden prompt, or from stdin with `--password-stdin`.
- Menus and prompts need a terminal. When stdin or stdout is not a terminal, a command that would prompt fails with an exit code instead of guessing.
- Colours are off when output is not a terminal or `NO_COLOR` is set.
- Dates and times are shown as DD-MM-YYYY and HH:mm, the same as in the apps, in device time.
- `argus -h` shows help. `argus -v` shows the version.
- `ARGUS_HOME` overrides the data folder (mainly for tests).

## 6.2 Sessions

See `05-sessions-and-lock.md`. Summary: the lax time (45 s, `0` disables) counts from the unlock. The CLI and the apps unlock separately. Commands that need the key ask for the master password only when the agent has no unlocked session; when `lax-time` is `0` there is never an unlocked session, so every modify and every reveal prompts each time.

## 6.3 Naming and search

Commands that take `<name>` accept a web address, a username, a note name, or an OTP label.

- **Fuzzy search** over name fields only: URL host and username for credentials, note name for secret notes, label and issuer for OTP entries. Passwords and note content are never searched. A credential is matched on its host and username together, so a few letters of each find it. Case is ignored. URL matching compares host names only: scheme, `www.` and path are ignored.
- An exact match on a whole field is preferred over fuzzy matches.
- A fuzzy match is chosen automatically only when it is the single result. Otherwise the picker is used.
- **Several matches**: in a terminal, a picker. Arrow keys, `j` and `k`, or a typed number, Enter to choose, `q` to cancel. Outside a terminal, the candidates (type, name) go to stderr and the command exits with code 4.
- **No match**: exit code 3.
- **Reserved words**: a note cannot be named like a command (`add`, `ls`, `rm`, `edit`, `push`, `pull`, `mfa`, `device`, `lock`, `passwd`, `config`, `promote`, and similar). `add` and `edit` refuse such names. So `argus <name>` never runs a different command. Credentials are reached by words from their URL and username.

## 6.4 Command summary

| Command | Purpose | Status |
| --- | --- | --- |
| `argus init` | Create a store, or request to join one | v1 |
| `argus add [<url or name>]` | Add a credential or secret note | v1 |
| `argus ls [-f <keyword>] [-c] [--json] [--rotate] [--conflicts]` | List credentials and secret notes | v1 |
| `argus <name>` | Show an entry | v1 |
| `argus -c <name> [-t <seconds>]` | Copy a password, then clear the clipboard | v1 |
| `argus edit <name>` | Edit an entry | v1 |
| `argus rm <name> [-y]` | Delete an entry | v1 |
| `argus push` and `argus pull` | Sync with the remote | v1 |
| `argus mfa ls [-f <keyword>]` | List OTP entries | v1 |
| `argus mfa add [<otpauth url>] [--qr <image file>] [--link <name>]` | Add an OTP | v1 |
| `argus mfa rm <name> [-y]` | Remove an OTP | v1 |
| `argus mfa <name> [-c]` | Show or copy the current code | v1 |
| `argus device ls`, `add`, `verify`, `rm` | Manage devices | v1 |
| `argus lock` | End the unlocked session | v1 |
| `argus passwd` | Change the master password | v1 |
| `argus config get\|set <key> [value]`, `config github-app` | Settings | v1 |
| `argus promote <name>` | Resolve a conflict by choosing a conflict copy | v1 |
| `argus -v`, `argus -h` | Version and help | v1 |
| `argus enc`, `argus dec` (`-r` for folders) | File encryption | next version |

## 6.5 Command details

### 6.5.1 init

Asks for: the master password (typed twice, strength shown, never blocks); the remote URL; the git credential (an SSH key file, or an HTTPS username and token); the git author name and email (prefilled from `git config`); a device name (default: host name).

`--remote <url>` and `--name <device name>` skip those prompts. The master password only comes from the prompt.

- Empty remote: create the store (`03-store-format.md`), commit, push.
- Remote with a store: join mode. Generate device keys, push a join request, print the fingerprint (8 groups), exit 8. The user approves on a trusted device, then runs `argus device verify`.
- Remote with other files: refused, exit 1.
- Already initialised: refused, exit 1, with a hint.
- Network or credential problems: exit 6.

### 6.5.2 add

`argus add [<url or name>]`. The optional argument prefills the first field: the URL for a credential, the name for a secret note.

1. Choose the type from a list: credential or secret note. Arrow keys, vim keys or a number, then Enter.
2. Credential fields: web URL, username, password, note (optional). Secret note fields: name, content.
3. Password: type it, or leave empty to generate. The generator asks for length (default 20) and which sets to use: letters, digits, symbols, all on by default. It shows the result and lets the user accept, generate again, or type their own. No rules are forced.
4. Content: opens the system editor (see `05-sessions-and-lock.md`). With `--no-editor`, or when no editor exists, the user types lines and ends with Ctrl-D.

Non-interactive use needs `--type credential` or `--type note`, plus `--url`, `--username`, `--name`, `--note <text>`, and either `--password-stdin` or `--generate`. Generator flags: `--length <n>`, `--no-letters`, `--no-digits`, `--no-symbols`. At least one set stays on.

An entry with the same URL and username as an existing one is updated, not duplicated. The command shows what will change and asks before overriding. Non-interactively it needs `-y`. A note with the same name is handled the same way. The change is committed just before the next push or pull; the command reminds the user to run `argus push`. Ctrl-C cancels with exit 130.

### 6.5.3 ls

`argus ls [-f <keyword>] [-c]` lists credentials and secret notes by their decrypted names and never shows secrets. OTP entries are listed only by `argus mfa ls`.

```
TYPE        NAME                                   FLAGS
credential  accounts.google.com (me@example.com)
credential  github.com (octocat)
note        Router PIN
```

- `-f <keyword>` keeps entries matching the keyword by fuzzy search.
- `-c` prints only the count, after any filter.
- FLAGS: `r` (password should be rotated), `c` (conflict copy).
- `--rotate` and `--conflicts` keep only flagged entries. `--json` prints machine-readable output.
- No matches is not an error: empty output, exit 0.

Results are sorted by name, ascending, ignoring case. The name is the host and username for credentials, the note name for secret notes, and the label for OTP entries. Search results use the same order.

### 6.5.4 argus <name>

Shows an entry. A credential prints labelled lines for URL, username, password and note. A secret note prints its content. The password is printed in clear, so it can remain in terminal scrollback; `-c` is safer.

- `--field url|username|password|note` prints only that value, unlabelled, for scripts.

### 6.5.5 -c (copy)

`argus -c <name> [-t <seconds>]` copies a credential's password and clears the clipboard after `<seconds>` (default 30; minimum 1). The command returns at once. A detached helper clears the clipboard only if it still holds the copied value. On macOS the item is concealed. A secret note cannot be copied this way (exit 2).

### 6.5.6 edit

`argus edit <name>` goes through each field. Enter keeps the current value; typing replaces it. For the password, empty keeps it and `g` generates a new one. Notes open the editor with the current text. Edit covers credentials and secret notes only; OTP entries are changed with `argus mfa add` and `argus mfa rm`.

- The entry's `rev` and `updated` change, it is re-signed, and the change is committed just before the next push or pull.
- Replacing the password clears the rotate flag.
- Changing the URL or username updates the search index at once.

### 6.5.7 rm

`argus rm <name>` shows the entry and asks `Delete? [y/N]`. `-y` skips the question. It removes the file; the removal is committed just before the next push or pull. The first time, it warns that old ciphertext stays in git history. Exit 3 if nothing matches.

### 6.5.8 push and pull

Pull combines the changes without a prompt when nothing conflicts (a fast-forward, or a merge commit with the message `update`). When an entry conflicts, pull asks the user to keep the older or the newer version, then continues (`04-device-lifecycle.md` section 4.9).

- `pull`: fetch, verify the device list and every changed entry, merge. Reports counts of new, changed and deleted entries. Conflicts follow the rule in `04-device-lifecycle.md` section 4.9 and the count is printed. A trusted device also repairs recipients and commits that.
- `push`: sends local commits. If rejected, pulls as above and retries up to 3 times, then asks the user whether to try again.
- Both refuse to run while conflicts are unresolved (exit 9). To resolve, run `argus promote <name>` (use the older version), or `argus rm` on the conflict copy (use the current version).
- Network or credential failure: exit 6. If the remote is unreachable, retry up to 3 times, then ask whether to retry later. If the device has been removed from the device list, lock every session and offer only Delete local data. Failed verification (fork, rollback, bad signature): exit 7. Nothing from a failed pull is used, and the message says why.

### 6.5.9 mfa

- `argus mfa ls [-f <keyword>]` lists OTP entries (label, issuer, TOTP or HOTP). Never codes.
- `argus mfa add [<otpauth url>] [--qr <image file>] [--link <name>]` reads an `otpauth://` URL from the argument, or from a QR code image with `--qr`. The URL can be omitted when `--qr` is given. Giving both is exit 2. It shows label, issuer, algorithm, digits and period, and asks to confirm. `--link` ties the OTP to a credential.
- `argus mfa rm <name> [-y]`.
- `argus mfa <name> [-c]` prints the current code and seconds left, or copies it with `-c` (cleared after 30 seconds). For HOTP it advances the counter, committed at the next push or pull.
- Showing a code uses the same unlock rules as other secrets. There is no extra master password prompt. When `lax-time` is `0`, showing or copying a code prompts each time.

### 6.5.10 device

- `argus device ls`: trusted devices (name, short id, date added, which one is this device), pending join requests with fingerprints, and revoked devices still waiting for remote cleanup.
- `argus device add`: runs on a trusted device. Pulls, lists pending requests, asks which one. Prints its fingerprint (8 groups) and asks `Does this match the new device's screen? [y/N]`. After yes: updates the device list, adds the recipient to every entry with a progress display, makes one commit, pushes. Prints the anchor (version and 8 groups). `--qr` also draws it in the terminal.
- `argus device verify [<anchor>]`: runs on the new device. Enters the anchor, verifies the approval, decrypts and indexes. Exit 7 if the anchor does not match. The anchor is not case-sensitive and spaces are ignored.
- `argus device rm <device>`: asks for confirmation, then revokes (see `04-device-lifecycle.md` 4.5). Re-encrypts every entry, sets rotate flags, commits, pushes. Removes the deploy key if GitHub App credentials are set up on this device; otherwise prints the manual steps and marks cleanup pending. Ends by pointing to `argus ls --rotate`. Revoking the device you are on is refused.

### 6.5.11 lock and version

`argus lock` makes the agent zero its key and exit. It succeeds even when no agent runs. `argus -v` prints the version. `argus -h` prints help.

### 6.5.12 passwd, config, promote

- `argus passwd`: changes the master password. Rewrites only the local `device.key`.
- `argus config get|set <key> [value]`: keys `lax-time` (default 45, `0` disables the lax time), `clear-after` (default 30), `editor`, and the remote URL. `argus config github-app` stores the GitHub App ID, installation ID and private key in the Keychain.
- `argus promote <name>`: lists the entry's conflict copies, lets the user choose one, makes it current, and deletes the previous current version.

### 6.5.13 Next version: enc and dec

`argus enc <file>` and `argus dec <file>`, with `-r <folder>` for folders, use the `.arg` suffix. Specified in `09-next-version.md`. Not in v1; do not implement.

## 6.6 Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success |
| 1 | General error |
| 2 | Usage error: bad arguments or unsupported action |
| 3 | No matching entry |
| 4 | Several matches and no terminal to choose |
| 5 | Authentication failed (wrong master password) |
| 6 | Remote, network or git credential problem |
| 7 | Verification failed: fork, rollback, bad signature, or wrong anchor |
| 8 | Not initialised, or waiting for device approval |
| 9 | Sync blocked by unresolved conflicts |
| 130 | Cancelled with Ctrl-C |

## 6.7 Examples

Daily use:

```
$ argus add github.com
$ argus ls -f github
$ argus -c github -t 20
$ argus push
```

Joining a new machine:

```
new$      argus init --remote git@github.com:me/vault.git
          (prints a fingerprint and exits with code 8)
trusted$  argus pull
trusted$  argus device add
          (compare the fingerprint, confirm, note the anchor)
new$      argus device verify
          (enter the anchor)
```
