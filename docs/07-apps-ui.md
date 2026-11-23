# 7. Apps and UI

Boxes and text only in the wireframes. Colours and fonts are not specified. macOS uses a sidebar window. iOS uses a tab bar. Add and edit open as a popup sheet on both.

## 7.1 Principles

- One set of screens, two layouts.
- The app opens on Unlock. There are no biometrics in v1. A Touch ID or Face ID button joins the screen in the next version.
- Names are visible after unlock. Passwords, notes and OTP codes stay hidden until the user reveals them inline. No extra screen or dialog.
- Locking follows `05-sessions-and-lock.md`: lax time counted from the last interaction (`0` disables: every modify and every Show/Copy prompts); locks on display off, screen lock and user switch; blur in previews, background and app switching.
- One sync button. See 7.4.
- Copy clears the clipboard after 30 seconds, with a small countdown.
- Dates and times: DD-MM-YYYY and HH:mm, in device time.
- Generator and strength estimate never block saving. No security rules are forced.
- Destructive actions (delete, remove device) ask for confirmation and state what will happen.

## 7.2 Navigation

- **macOS**: sidebar with Entries (All, Logins, Notes, Needs rotation, Conflicts), MFA, Devices, Settings. Toolbar: search, sync button, Add.
- **iOS**: tab bar with Entries, MFA, Devices, Settings. Entries screen has the sync button and Add in the top bar. An entry opens as a detail screen on the stack.
- **First launch**: Welcome, then Setup, then (when joining) Waiting for approval and Verify, then Entries.

In All, entries are grouped by type under collapsible labels: Logins and Notes; OTP entries appear only under MFA. Labels show a count. `!` marks a conflict copy. `Rotate(n)` in the sidebar shows the number of rotate-flagged entries.

## 7.3 Screens

### 7.3.1 Unlock

macOS window or iOS full screen. Unlocking starts the lax time (45 seconds by default), and every interaction restarts it.

```
Unlock
-----------------------------------------------
                    ARGUS

  Master password
  [ ************************ ]   [ Unlock ]

  Wrong password. Try again.
-----------------------------------------------
```

### 7.3.2 Entries on macOS

Sidebar, list and detail. In All, entries are grouped by type under collapsible labels: `v` means open, `>` means collapsed, and the number is the count. `!` marks a conflict copy. `Rotate(3)` means three passwords are flagged for rotation. The action buttons sit on the right side of the detail pane, and the sync button and Add sit at the right of the toolbar.

```
| Argus   [ Search...            ]                       [ ⟳ ]  [ + Add ]
+-------------+---------------------------+--------------------------------------------
| Entries     | v Logins (3)              | accounts.google.com                     
|   All       |   accounts.google.com     |                                         
|   Logins    |     me@example.com        | URL       https://accounts.google.com
|   Notes     |   github.com              | Username  me@example.com   [Copy]
|   Rotate(3) |     octocat               | Password  ************   [Show] [Copy]
|   Conflicts |   ! shop.example          | Note      PIN 1234
| MFA         | v Notes (1)               |
| Devices     |   Router PIN              |                       [ Edit ] [ Delete ]
| Settings    |                           |
```

The sync button shows the status by colour and symbol. The symbol is the rotate-arrows icon, with the `!` or the `x` drawn inside it.

```
[ ⟳ ]    green    up to date
[ ⟳! ]   orange   out of date
[ ⟳x ]   red      conflict
```

### 7.3.3 Entries on iOS

The list, then the detail screen after tapping an entry. The top bar has the sync button (section 7.4), and pulling down on the list also syncs. Entries are grouped by type under collapsible labels.

```
+--------------------------------+
| Entries            [ ⟳ ]  [ + ]|
| [ Search...               ]    |
|                                |
| v Logins (3)                   |
|   accounts.google.com          |
|     me@example.com           > |
|   github.com                   |
|     octocat                  > |
| v Notes (1)                    |
|   Router PIN                 > |
|                                |
+--------------------------------+
| Entries  MFA  Devices  Settings|
+--------------------------------+
```

Detail screen. Edit sits above Delete.

```
+--------------------------------+
| < Entries                      |
|                                |
| accounts.google.com            |
|                                |
| URL                            |
| https://accounts.google.com    |
| Username              [ Copy ] |
| me@example.com                 |
| Password       [ Show ] [Copy] |
| ************                   |
| Note                           |
| PIN 1234                       |
|                                |
| [ Edit entry ]                 |
| [ Delete entry ]               |
+--------------------------------+
```

### 7.3.4 Showing a secret

Showing is inline, on the entry itself, with no dialog or extra screen. A password, a note or an OTP code is revealed in place. The value hides again when the user leaves the entry or the app locks.

```
Password or note
  Password  ************          [ Show ]  [ Copy ]
  (tap Show)
  Password  k3Fq9-Lm2x-Tt8Z       [ Hide ]  [ Copy ]

OTP code
  GitHub (octocat)   *** ***      [ Show ]
  (tap Show)
  GitHub (octocat)   284 193  18s   [ Hide ]  [ Copy ]
```

### 7.3.5 Add and edit

A popup (sheet) on both platforms. Edit uses the same popup with the title Edit entry and the current values filled in.

```
+- Add entry -----------------------------------------
| Type      (o) Credential    ( ) Secret note
|
| Web URL   [ https://                             ]
| Username  [                                      ]
| Password  [ ******************** ]   [ Generate ]
|           Strength: medium
| Note      [                                      ]
|           [                                      ]
|
| ! An entry with this URL and username exists.
|   Saving will update it.
|
|                           [ Cancel ]   [ Save ]
+-------------------------------------------------------
```

Generate opens a small panel under the password field:

```
| Length [ 20 ]    [x] Letters   [x] Digits   [x] Symbols
| Result k3Fq9...  [ Use ]   [ Generate again ]
```

The secret note variant:

```
+- Add entry -----------------------------------------
| Type      ( ) Credential    (o) Secret note
|
| Name      [ Router PIN                           ]
| Content   [                                      ]
|           [                                      ]
|                           [ Cancel ]   [ Save ]
+-------------------------------------------------------
```

### 7.3.6 MFA

Codes are hidden until Show, which reveals the code inline (section 7.3.4). After Show, the code refreshes at the end of each period.

```
+- MFA ---------------------------------------  [ + Add ]
| GitHub (octocat)           ***  ***    [ Show ]
| Google (me@example.com)    ***  ***    [ Show ]
|
| After Show:
| GitHub (octocat)           284 193    18s   [ Copy ]
```

Adding an OTP. Either the URL or the QR code fills in the fields below.

```
+- Add OTP -------------------------------------------
| URL       [ otpauth://totp/GitHub:octocat?secret=... ]
| QR code   [ Scan with camera ]    (iPhone)
|           [ Choose image...  ]    (Mac and iPhone)
| Label     [ GitHub (octocat)                       ]
| Issuer    [ GitHub                                 ]
| Link to   [ none                                v ]   (a credential)
|                           [ Cancel ]   [ Add ]
+-------------------------------------------------------
```

### 7.3.7 Devices

```
+- Devices -------------------------------------------
| Trusted
|   MacBook (this device)     added 19-11-2026
|   iPhone                    added 20-11-2026      [ Remove ]
|
| Waiting for approval
|   iPad    3fa2 91bc 77d0 12ee ...                 [ Review ]
|
| Removed, remote cleanup pending
|   Old laptop                                      [ Done ]
+-------------------------------------------------------
```

Review a request. The fingerprint must match the screen of the new device.

```
+- Approve this device? ------------------------------
| iPad
| Fingerprint
|   3fa2 91bc 77d0 12ee 04ab c9d1 5e60 8821
|   [ QR code ]
| Compare this with the screen of the new device.
|
|                          [ Reject ]   [ Approve ]
+-------------------------------------------------------
```

After approval, the code the new device needs:

```
+- Device approved -----------------------------------
| On the new device, enter or scan this code.
|   v3   a41c 09fd 62be 71a0 8c13 d5e9 04f7 3b2a
|   [ QR code ]
|                                         [ Done ]
+-------------------------------------------------------
```

Removing a device:

```
+- Remove iPhone? ------------------------------------
| Every entry will be encrypted again for the remaining
| devices, and every password will be marked as needing
| a change. The removed device keeps anything it already
| has.
|
| Remote access: the GitHub deploy key is removed
| automatically.   (Other hosts: the steps are shown.)
|
|                  [ Cancel ]   [ Remove device ]
+-------------------------------------------------------
```

### 7.3.8 First launch: create or join

```
Welcome
-----------------------------------------------
  Argus

  ( ) Create a new store
  ( ) Join an existing store           [ Continue ]

Setup (both)
-----------------------------------------------
  Remote URL       [ git@github.com:me/vault.git ]
  Git credential   [ SSH key: ~/.ssh/id_ed25519 v ]
  Author           [ Name ]   [ email ]
  Device name      [ MacBook ]
  Master password  [ ************ ]  
                   Strength: strong
  Confirm          [ ************ ]
                                           [ Continue ]

Waiting for approval (joining only)
-----------------------------------------------
  Approve this device on a trusted device.
  Fingerprint:  3fa2 91bc 77d0 12ee 04ab c9d1 5e60 8821
  [ QR code ]
                                  [ I have the code ]

Verify (joining only)
-----------------------------------------------
  Enter or scan the code shown on the trusted device.
  Code  [ ____ ____ ____ ____ ____ ____ ____ ____ ]
  [ Scan QR code ]                       [ Verify ]
```

### 7.3.9 Settings

```
+- Settings ------------------------------------------
| Appearance
|   Theme             ( ) Light   ( ) Dark   (o) System
| Sync
|   Git remote        [ git@github.com:me/vault.git ]
|   Git credential    SSH key                [ Change ]
|   Author            Name <email>           [ Change ]
|   GitHub App        Not set up             [ Set up ]
| Security
|   Master password   [ Change... ]
|   Lax time          [ 45 ] seconds
|   Clear clipboard   [ 30 ] seconds
|   Biometrics        Next version
| About
|   Version           0.1.0
+-------------------------------------------------------
```

The lax time and clipboard time mirror `argus config`.

## 7.4 Sync button and states

One button, in the toolbar on macOS and the top bar on iOS. Its colour and symbol show the status (the rotate arrows, with `!` or `x` inside):

| State | Icon | Meaning and action |
| --- | --- | --- |
| Up to date | Green rotate arrows | This device and the remote match. Tapping syncs anyway. |
| Syncing | Button spins | A pull or push is running. |
| Out of date | Orange rotate arrows with `!` | Behind or ahead of the remote, or the last sync failed (reason shown). Tapping pulls or pushes. Offline shows the number of unpushed changes and a retry. |
| Conflict | Red rotate arrows with `x` | Entries conflict. Syncing is blocked until resolved. Tapping opens the conflict list. |
| Security alert | Red broken shield, banner on every screen | The device list did not verify. Sync is stopped. Details. |
| Needs unlock | Banner | New entries were pulled while locked. Unlock to show them. |
| Removed device | Full screen | This device was removed from the store. Delete local data. |
| Waiting for approval | Full screen | See First launch. |

Rules:

- Pull when behind, push when ahead, pull then push when both changed.
- On phones, pulling down on the list does the same.
- Syncing is blocked while any conflict is unresolved.

### 7.4.1 Conflict screen

Use current keeps the current version and deletes the older copy. Use older makes the older version current (the same as `argus promote`) and deletes the copy. Syncing resumes when every conflict is resolved.

```
+- shop.example  (conflict) --------------------------
| Current version      updated 21-11-2026 10:02
|   Username  me@example.com
|   Password  ********    [ Show ]
|
| Older version        updated 21-11-2026 09:40
|   Username  me@example.com
|   Password  ********    [ Show ]
|
|                    [ Use current ]   [ Use older ]
+-------------------------------------------------------
```

### 7.4.2 Passwords to change

Shown after a device is removed, under the Needs rotation section. Saving a new password clears the flag, and Done clears it without changing the password.

```
+- Passwords to change -------------------------------
| After a device was removed, change these passwords.
|
| github.com (octocat)             [ Generate ]  [ Done ]
| accounts.google.com (me@...)     [ Generate ]  [ Done ]
|
| 2 of 3 left
+-------------------------------------------------------
```

Argus cannot change passwords on other websites. The user changes them on the site.

## 7.5 macOS shortcuts

Cmd-N new entry. Cmd-F search. Cmd-L lock.

## 7.6 Accessibility and localisation

Accessibility:

- Every control has a VoiceOver label. A revealed secret is announced once, not repeatedly.
- Text follows Dynamic Type on iOS and the system text size on macOS.
- Full keyboard access on macOS, including the sidebar, the list and the popups.
- Status is never shown by colour alone. The sync button also uses a symbol.
- Contrast is at least WCAG 2.1 AA. Reduce Motion is respected for the sync button animation.

Localisation:

- English only in v1. All user-facing strings are in resource files, so a translation can be added later. Vietnamese is planned for the next version (see `09-next-version.md`).
- Dates use DD-MM-YYYY and times use HH:mm, in device time, in every language. This overrides locale date conventions.
- The CLI picker works with the arrow keys and with `j` and `k` in every language.
