# 4. Device lifecycle and sync

## 4.1 init (first device)

1. Generate the store id, a device id, and both keypairs. Wrap the private keys with the master password.
2. Write `store.json`, `.gitattributes`, `devices.json` (version 1, signed by this device) and `devices.sig`. Commit as `init`. Add the remote. Push.
3. Pin version 1 in `trust.json`.

The remote MUST be empty. If it has files but no `store.json` at the root, init refuses (exit 1). If it has a store, init joins instead (4.2).

## 4.2 join request (new device)

1. Clone the remote. If `store.json` exists at the root, run in join mode: read the store id, ask for a master password and a device name.
2. Generate keypairs and write `device.key`.
3. Write `pending-<device-id>.json` at the store root:

```json
{
  "v": 1,
  "storeId": "<id>",
  "device": { "id": "<id>", "name": "iPhone", "enc": "argus1...", "sign": "<b64u>" },
  "created": "2026-11-19T09:00:00Z",
  "sig": "<b64u>"
}
```

`sig` is made with the device's signing key over the prefix `argus-join-v1` and the canonical bytes of the object without `sig`.

4. Commit as `update`. Push. Record `join_state.json`.
5. Show the fingerprint (QR and 8 groups) and wait. The device decrypts nothing and trusts no list until 4.4 succeeds.

## 4.3 approve (any trusted device)

1. Pull and verify the device list. List pending requests whose store id and self-signature are valid.
2. The user picks a request and compares the fingerprint with the new device's screen (scan the QR, or compare the 8 groups). Nothing proceeds without this confirmation.
3. Build list version n+1: add the device with `addedBy` set to this device and `prev` set to the hash of version n. Sign it.
4. For each entry, add the new recipient by sealing the existing file key to the new device and appending the sealed key, bumping `rcount` (03 section 3.4). The nonce, payload and file key are unchanged.
5. Delete the pending file. Commit once as `update`, containing `devices.json`, `devices.sig`, every entry change and the removed pending file. Push. If the push is rejected: pull, verify, and redo from step 3 on top of the new state. Device lists are never merged automatically.
6. Show the anchor (see `03-store-format.md`), as 8 hex groups and a QR code.

## 4.4 verify (new device)

1. The user scans or types the anchor.
2. Pull. Find `devices.json` at the anchor's version in history. Its hash must start with the anchor bytes. Verify the chain back to version 1 and each signature. Check that this device's entry carries its own keys. Pin the newest verified version.
3. Decrypt entries, build the search index, delete `join_state.json`.
4. If the anchor does not match: show "approval could not be verified", keep the keys, exit 7.

The fingerprint protects against a fake request (someone with write access to the repository). The anchor protects against a fake list. The hash chain lets one anchor authenticate every earlier version.

## 4.5 revoke (trusted device)

1. Build list version n+1 without the device. Sign it.
2. Decrypt every entry and encrypt it again with a fresh file key to the remaining devices. Re-sign each entry. Set its rotate flag. Sealed-key appends are not enough, because the revoked device may have kept file keys.
3. Commit once as `update`. Push.
4. Remote cleanup:
   - GitHub (v1): Argus removes the device's deploy key with the GitHub API, using a token from the user's own GitHub App (repository `Administration: write`). The App's installation token is created from the App's private key, which is stored in the Keychain of the device that set it up. Other devices show the manual steps. After the revoke, Argus shows the manual steps to rotate the GitHub App's private key.
   - Other hosts (and GitLab): Argus shows the user which credential to remove. The revocation stays marked "remote cleanup pending" until the user confirms.
5. The user is told to change important passwords. Argus lists entries with the rotate flag as a checklist.

A revoked device that pulls and finds itself missing from the list stops syncing, and offers to delete its local data. It cannot be prevented from keeping what it already has.

## 4.6 reconcile

After every pull, a trusted device compares each entry's `rcount` (number of sealed file keys) with the number of devices in the verified list. On a mismatch it repairs the entry: a sealed-key append for a missing recipient, full re-encryption for an extra one. This catches entries written by a device that had not seen the newest list.

## 4.7 concurrent device-list changes

If two trusted devices change the list at the same time, the second re-applies its change on top of the latest verified list and signs again.

## 4.8 sync

- Pull fetches, verifies the device list, verifies and indexes changed entries, then merges. If nothing conflicts, the changes are combined without a prompt: a fast-forward when the history allows it, otherwise a merge commit with the message `update`. It reports counts of new, changed and deleted entries. If an entry changed on both sides, pull stops and asks the user to keep the older or the newer version of that entry (section 4.9), then continues.
- Push sends local commits. If the remote rejects the push, the operation fetches, verifies, and retries up to 3 times, then asks the user whether to try again.
- A failed verification (fork, rollback, bad signature) aborts. Nothing from the failed pull is used, and nothing is reset.
- Changes are committed only just before a push or pull. An interrupted push leaves its commits for the next push.
- A damaged entry (cannot decrypt, id does not match, bad signature) is listed as damaged and never deleted automatically.
- A remote with files but no `store.json` at the root is refused. A shallow clone is refused. If the remote is unreachable because of the network, retry up to 3 times, then ask the user whether to retry later. If the device has been removed from the device list, lock every local session and offer only Delete local data.

### Sync button (apps)

One button. It pulls when this device is behind the remote, pushes when it is ahead, and when both changed it pulls first and then pushes. Sync is blocked while any conflict is unresolved. The CLI `push` and `pull` also refuse while conflicts exist (exit 9).

## 4.9 conflicts

Git reports a conflict when the same entry file changes on both sides.

1. Pull lists each conflicting entry with its older and newer versions. Versions are ordered by git commit order, oldest first. Clock times and `rev` do not decide the order.
2. For each entry the user keeps the older or the newer version. The other version is discarded by that choice.
3. Pull then continues.
4. If the user postpones the choice, the older version is kept as a conflict copy with `conflictOf` set to the entry id. The conflict stays visible, and sync is blocked until every conflict is resolved.
5. An edit that conflicts with a delete keeps the edit.

Resolution of a postponed conflict:

- Apps: "Use current" keeps the current version and deletes the older copy. "Use older" makes the older version current and deletes the copy.
- CLI: `argus promote <n>` lists the conflict copies and makes the chosen one current. The previous current version is deleted, which resolves the conflict.

The device list is never merged this way.

## 4.10 commit messages and author

Every commit message is `update`, except the first commit of a new store, which is `init`.
