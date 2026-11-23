# 5. Sessions, lock and clipboard

## Lax time

- Default: 45 seconds. Configurable with `argus config set lax-time <seconds>` and in app settings. Setting `lax-time` to `0` disables the lax time: there is no cached unlocked session.
- The lax time lets the user act without re-entering the master password. Every operation that needs the key needs an unlocked session.

### CLI

- Each command is a separate process. A background agent holds the unlocked key.
- The CLI and the apps unlock separately; an unlock in one does not unlock the other.
- The lax time counts from the unlock and then ends. It is NOT extended by later commands. The CLI is turn-based, and the user may run other commands in between, so the window is fixed.
- When `lax-time` is `0`, the agent keeps no unlocked key: every modify (`add`, `edit`, `rm`, `mfa add`, `mfa rm`, `promote`, `passwd`, `device add`, `device rm`, and the HOTP counter advance on `mfa <name>`) and every reveal (`<name>`, `-c`, `mfa <name>`, `--field password`) asks for the master password each time. Listing names (`ls`, `mfa ls`) does not re-prompt beyond the unlock.
- The agent starts on the first unlock. It listens on a Unix socket in the data folder, mode 0600, for the same user only.
- The agent zeroes the key when the time runs out, on `argus lock`, and when the Mac sleeps.
- If the agent cannot run, every command asks for the master password.
- A wrong password can be re-entered up to 3 times, then the command exits with code 5.
- There are no biometrics in the CLI in v1.

### Apps

- The lax time counts from the last interaction. Each interaction restarts it, so an active app stays unlocked.
- When `lax-time` is `0`, the app does not stay unlocked: names and lists remain visible after unlock, but every modify (add, edit, delete, OTP add/remove, conflict resolve) and every Show/Copy of a password, note or OTP code asks for the master password each time.
- When the lax time passes without interaction, the app locks: it zeroes the device key and drops the in-memory search index, and the next screen is Unlock.
- The app also locks when the display turns off, when the screen locks, and when the user switches user.
- Showing a password, note or OTP code does not ask for the master password again while unlocked.

## Blur

The app's content is blurred in app previews (the app switcher, Mission Control), whenever the app is in the background, and when the user switches to another app.

## Revealing secrets

- Passwords, notes and OTP codes are hidden until the user reveals them. Reveal is inline.
- A revealed value hides again when the user leaves the entry or the app locks.
- OTP codes refresh at the end of each period. HOTP codes advance the counter and commit; the command says so.

## Clipboard

- Copy clears the clipboard after 30 seconds by default (`clear-after`).
- macOS: the item is marked concealed so clipboard managers skip it. The CLI starts a detached helper that waits, then clears the clipboard only if it still holds the copied value.
- iOS: the item is local-only with an expiry date, because the app cannot clear the clipboard in the background.

## Editing with an editor

`argus add` and `argus edit` (notes) open the system editor (`$VISUAL`, then `$EDITOR`, then vim) in a private temporary folder. Swap, backup and undo files are disabled (for vim: `-n -i NONE`). The temporary file is deleted afterwards, even on error.

## Logging and output

- Secrets never appear in logs, crash reports, environment variables or command-line arguments.
- CLI output that the user asked for goes to stdout. Prompts and messages go to stderr.
