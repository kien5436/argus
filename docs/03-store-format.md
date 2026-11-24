# 3. Store format

## 3.1 Conventions

- Text is UTF-8. Times are RFC 3339 in UTC.
- **id**: 128 random bits from the OS secure random source, written as lowercase base32 (RFC 4648 alphabet, no padding, 26 characters).
- **b64u**: base64url without padding.
- **recipient key**: a 32-byte X25519 public key encoded with bech32m (BIP-350), human-readable part `argus`.
- **hash**: SHA-256, lowercase hex unless noted.
- **Canonical JSON**: RFC 8785 (JCS). Any JSON that is hashed or signed is first canonicalised.
- **Domain prefix**: every signature and the device fingerprint hash cover a fixed ASCII prefix followed by a newline (byte 0x0A). For example, the devices signature covers the bytes `argus-devices-v1\n` followed by the canonical JSON. Prefixes are: `argus-entry-v1`, `argus-devices-v1`, `argus-device-v1` (fingerprints), `argus-join-v1`.

## 3.2 Primitives

| Purpose | Choice |
| --- | --- |
| Entry encryption | libsodium-compatible envelope (dryoc): XSalsa20-Poly1305 `secretbox` under a random file key, the file key sealed per recipient with `crypto_box_seal` (X25519) |
| Device key protection | Argon2id (`crypto_pwhash`), opslimit = 3, memlimit = 256 MiB (64 MiB fallback) |
| Signatures | Ed25519 (`crypto_sign`) |
| Hashes | SHA-256 |
| Canonical JSON | RFC 8785 |

## 3.3 Repository layout

The store is the git repository itself. Its checkout lives in the data folder as `.argus/`. Every file sits directly in the store root; there are no subdirectories.

```
.argus/
  .gitattributes          contains: *.arg binary, *.json -text
  store.json
  devices.json
  devices.sig
  pending-<device-id>.json
  <entry-id>.arg
```

- Entries sit directly in the store root, one file each, alongside `store.json`, `devices.json`, `devices.sig` and the pending join requests. Nothing else goes in the root.
- `store.json` is `{"format":1,"storeId":"<id>","created":"<time>"}`. The store id identifies this store.
- A client that sees a `format` higher than it supports MUST NOT read or write the store. It tells the user to update.
- Unknown files are ignored and left untouched.
- Entries use the `.arg` suffix. Files produced by `enc` (next version) also use `.arg`; they are not entries and are never placed in the store root (`.argus/`).

## 3.4 Entry file

Each `<entry-id>.arg` is an encrypted envelope addressed to every device in the newest verified device list. Its plaintext is one JSON object, padded as described below. The envelope holds one file key: the payload is encrypted with that key, and the key itself is sealed once per recipient. Adding a recipient rewrites only the sealed keys and their count, never the payload.

```json
{
  "v": 1,
  "id": "<entry-id>",
  "type": "credential",
  "rev": 3,
  "created": "2026-11-19T09:00:00Z",
  "updated": "2026-11-19T10:30:00Z",
  "data": {
    "url": "https://accounts.google.com",
    "username": "me@example.com",
    "password": "...",
    "note": "PIN 1234"
  },
  "sig": { "by": "<device-id>", "v": "<b64u>" }
}
```

### Envelope

The ciphertext file is a self-describing binary envelope. All integers are big-endian.

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 6 | magic, the bytes `41 52 47 55 53 01` (`ARGUS\x01`) |
| 6 | 1 | envelope version, `0x01` |
| 7 | 4 | `plen`, u32: length of the padded plaintext, a multiple of 512 and at most 1,048,576 |
| 11 | 24 | nonce for the payload `secretbox` |
| 35 | `plen` + 16 | ciphertext of the padded plaintext plus the 16-byte Poly1305 tag |
| 35 + `plen` + 16 | 2 | `rcount`, u16: number of recipients |
| 37 + `plen` + 16 | `rcount` × 80 | one `crypto_box_seal` of the file key per recipient, in device-list order |

Encryption: a random 32-byte file key and a random 24-byte nonce are generated from the OS secure random source. The padded plaintext is encrypted with `secretbox` (XSalsa20-Poly1305) under the file key. The file key is sealed to each recipient's X25519 public key with `crypto_box_seal`, 80 bytes per recipient (ephemeral public key, ciphertext, tag). The recipient order follows the device list; a reader finds its sealed key by its own index.

To add a recipient (approve, reconcile repair), the writer seals the existing file key to the new device and appends it, bumping `rcount`. The nonce, payload and file key are unchanged. To remove a recipient (revoke), the writer re-encrypts with a fresh file key to the remaining devices (04 section 4.5).

### Types and data fields

- `credential`: `url`, `username`, `password`, `note`.
- `note`: `name`, `content`. Shown in the UI as "secret note".
- `otp`: `label`, `issuer`, `secret` (base32), `algorithm` (SHA1, SHA256 or SHA512; default SHA1), `digits` (6 to 8), `period` (TOTP) or `counter` (HOTP), and optional `link` (the id of a credential).

### Rules

- `id` MUST equal the file name without `.arg`. A mismatch marks the entry damaged.
- `rev` starts at 1 and increases by 1 on each edit. It records the version an edit was based on. It is never used for conflict ordering.
- `conflictOf` is optional. It holds the id of the entry this file is an older conflicting version of.
- `rotate` is optional. It is set on every entry after a revoke and cleared when the user changes the password or marks the entry done.
- Unknown fields are kept when an entry is rewritten. An unknown `type` is shown as unsupported and never deleted.
- Plaintext is padded with trailing spaces to the next multiple of 512 bytes, to blur sizes. Maximum entry size: 1 MiB.
- Deleting an entry is a `git rm`. Old ciphertext remains in git history.
- Searchable fields, held in memory only: url and username (credential), name (note), label and issuer (otp). Matching rules are in `06-cli.md`.
- URL matching compares host names only: lowercase the host, drop the scheme, `www.` and the path.

### Entry signature

`sig` is an Ed25519 signature by one device over the canonical JSON of the entry without `sig`, prefixed with `argus-entry-v1`. A client accepts an entry only if the signer is in the current verified device list. Sealed-recipient changes leave the payload (and therefore the signed plaintext) unchanged, so signatures stay valid. A revoke re-signs every entry.

## 3.5 Device list

`devices.json` (in the store root, `.argus/devices.json` from the data folder):

```json
{
  "v": 1,
  "storeId": "<id>",
  "version": 2,
  "prev": "<hash of version 1 file bytes>",
  "updated": "2026-11-19T09:00:00Z",
  "devices": [
    {
      "id": "<device-id>",
      "name": "MacBook",
      "enc": "argus1...",
      "sign": "<b64u Ed25519 public key>",
      "gitKey": "<SSH key fingerprint, or GitHub key id; optional>",
      "added": "2026-11-19T09:00:00Z",
      "addedBy": "<device-id>"
    }
  ]
}
```

`enc` is the device's X25519 public key (32 raw bytes) encoded with bech32m (BIP-350), human-readable part `argus` (for example `argus1...`). bech32m is used rather than the original bech32 so a damaged checksum cannot be swapped undetected.

`devices.json` is stored in canonical form, so its file bytes are its canonical bytes. The hash chain and the signature both use these bytes.

`devices.sig` is `{"signer":"<device-id>","sig":"<b64u>"}`. The signature covers the prefix `argus-devices-v1` followed by the canonical bytes of `devices.json`.

### Fingerprint

SHA-256 of the prefix `argus-device-v1` and a newline, then the 32-byte Ed25519 public key, then the 32-byte X25519 public key (the raw 32 bytes encoded by the `argus1...` string). Screens show the first 16 bytes as 8 groups of 4 hex characters. QR codes carry all 32 bytes.

### Anchor

The anchor is the new version number and the first 16 bytes of the SHA-256 of the new `devices.json` file bytes, shown as `v<version>` followed by 8 hex groups of 4 characters, for example `v3 a41c 09fd 62be 71a0 8c13 d5e9 04f7 3b2a`. The new device already knows the store id from the remote, so the anchor does not repeat it. The QR code carries the same string.

### Verification

Run on every pull, before anything new is used:

1. `storeId` equals the pinned store id, and `v` is supported.
2. Walk the history of `devices.json` from version 1 to the newest. Shallow clones are refused.
3. Version 1: one device, `addedBy` equals itself, signed by itself, `prev` empty.
4. Version n+1: `prev` equals the hash of the version n file bytes. The signer is listed in version n, and the signature is valid for the signer's `sign` key from version n. Each device new in n+1 has `addedBy` equal to the signer, and the signer is not one of the new devices.
5. A list with no devices is invalid.
6. Pin the verified `(storeId, version, hash)` in `trust.json`. A lower version is rejected (rollback). Same version, different bytes, is rejected (fork), and the user sees a security alert.
7. Entries are encrypted only to the recipients of the newest verified list.

## 3.6 Local files (never in git)

| Item | Contents | Protected by |
| --- | --- | --- |
| `device.key` | Both private keys, as JSON inside a secretbox envelope | Master password (Argon2id) |
| `trust.json` | Pinned list: store id, version, hash | File permissions |
| `join_state.json` | An unfinished join: device id, time | File permissions |
| `config` | Remote URL, device name, lax time, clipboard time, theme, editor | File permissions |
| Keychain | Git credentials; GitHub App credentials (App ID, installation id, private key) | Keychain, this device only |
| Memory only | Unlocked keys, search index | Process lifetime; zeroed on lock |

Plaintext of `device.key`: `{"v":1,"deviceId":"<id>","encSecret":"<b64u 32 bytes>","signSeed":"<b64u 32 bytes>"}`.

The `device.key` file is a binary envelope. All integers are big-endian.

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 6 | magic, the bytes `41 52 47 55 53 4B 01` (`ARGUSK\x01`) |
| 6 | 1 | version, `0x01` |
| 7 | 16 | random Argon2id salt |
| 23 | 4 | `opslimit`, u32 |
| 27 | 4 | `memlimit`, u32, in bytes |
| 31 | 24 | nonce for the `secretbox` |
| 55 | n + 16 | ciphertext of the plaintext JSON plus the 16-byte tag, under the Argon2id-derived 32-byte key |

The CLI and the app on one Mac share the same `device.key`, in the same data folder.

## 3.7 Commits

- Author: the git identity saved with the remote credential. The user gives a name and email when adding the remote, prefilled from git config on macOS. Everyone who can read the repository sees this identity.
- Messages: every commit is `update`. Messages never contain names or entry details.

## 3.8 Test vectors

Vectors are produced by the reference implementation in `vault-core` and checked against an independent implementation (the C libsodium, via `libsodium-sys-stable`). See `08-testing.md`.

## 3.9 Format migration

- Additive changes keep `format: 1`. Older clients show unknown types as unsupported and keep them.
- A breaking change increments `format`. Older clients refuse the store and tell the user to update.
- A breaking migration is run by `argus migrate` on a trusted device. It copies the store to `store.bak-<format>/` in the data folder, rewrites the entries, commits once as `update`, and pushes. Other devices refuse to sync until they update.
- A failed migration leaves the backup in place and the remote unchanged.
