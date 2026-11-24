//! T5.5 reconcile tests (spec 04 section 4.6).
use std::fs;
use std::path::{Path, PathBuf};
use vault_core::device_key::Kdf;
use vault_core::git::{Author, Backend, Libgit2Backend};
use vault_core::secrets::MasterPassword;

struct FixedRng(u64);
impl FixedRng {
    fn step(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
    fn fill(&mut self, dest: &mut [u8]) {
        let mut i = 0;
        while i < dest.len() {
            let v = self.step().to_le_bytes();
            let n = (dest.len() - i).min(8);
            dest[i..i + n].copy_from_slice(&v[..n]);
            i += n;
        }
    }
}
impl rand::TryRng for FixedRng {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.step() as u32)
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(self.step())
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        self.fill(dest);
        Ok(())
    }
}
impl rand::TryCryptoRng for FixedRng {}
struct FastKdf;
impl Kdf for FastKdf {
    fn derive(
        &self,
        out: &mut [u8],
        password: &[u8],
        salt: &[u8],
        _o: u64,
        _m: usize,
    ) -> Result<(), vault_core::device_key::Error> {
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        h.update(password);
        h.update(salt);
        let d = h.finalize();
        for (i, b) in out.iter_mut().enumerate() {
            *b = d[i % 32];
        }
        Ok(())
    }
}
fn author() -> Author {
    Author::new("Argus Test", "argus-test@example.com").unwrap()
}
fn pw() -> MasterPassword {
    MasterPassword::new(b"correct horse battery staple".to_vec())
}
fn tmp(s: &str) -> PathBuf {
    let mut d = std::env::temp_dir();
    d.push(format!(
        "argus-t55-{}-{}-{}",
        std::process::id(),
        s,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}
fn bare(p: &Path) {
    std::process::Command::new("git")
        .args(["init", "--bare", "-b", "master"])
        .arg(p)
        .status()
        .unwrap();
}
const NOW: &str = "2026-11-19T09:00:00Z";
const NOW2: &str = "2026-11-19T10:00:00Z";

struct Seed {
    remote: PathBuf,
    work: PathBuf,
    data: PathBuf,
    store_id: String,
    device_id: String,
}
fn seed_first(s: &str) -> Seed {
    let remote = tmp(&format!("{s}-remote"));
    bare(&remote);
    let work = tmp(&format!("{s}-work"));
    let data = tmp(&format!("{s}-data"));
    let backend = Libgit2Backend;
    // Deterministic but distinct per seed name: two seeds in one test must
    // never share a store id or device keys.
    let mut h: u64 = 0xaaaa;
    for b in s.bytes() {
        h = h.wrapping_mul(31).wrapping_add(b as u64);
    }
    let mut rng = FixedRng(h);
    let out = vault_core::init::init(
        &work,
        &data,
        remote.to_str().unwrap(),
        vault_core::git::InitSource::Empty,
        "laptop",
        &pw(),
        &mut rng,
        &FastKdf,
        &backend,
        &author(),
        NOW,
        &mut |_| {},
    )
    .unwrap();
    let (store_id, device_id) = match out {
        vault_core::init::Outcome::Created {
            store_id,
            device_id,
        } => (store_id, device_id),
        _ => panic!("created"),
    };
    Seed {
        remote,
        work,
        data,
        store_id,
        device_id,
    }
}
fn add_join(seed: &Seed, s: &str, name: &str) -> (PathBuf, PathBuf, String) {
    let backend = Libgit2Backend;
    let join_work = tmp(&format!("{s}-joinwork"));
    backend.clone_repo(&seed.remote, &join_work).unwrap();
    let join_data = tmp(&format!("{s}-joindata"));
    let mut rng = FixedRng(0x5300 + s.len() as u64);
    let out = vault_core::join::join(
        &join_work,
        &join_data,
        name,
        &pw(),
        &mut rng,
        &FastKdf,
        &backend,
        &author(),
        NOW,
        &mut |_| {},
    )
    .unwrap();
    let device_id = match out {
        vault_core::join::Outcome::Requested { device_id, .. } => device_id,
    };
    (join_work, join_data, device_id)
}
fn sync_pending_into_approver(seed: &Seed, _join_work: &Path) {
    let st = std::process::Command::new("git")
        .args([
            "-C",
            seed.work.to_str().unwrap(),
            "pull",
            "--ff-only",
            "origin",
            "master",
        ])
        .status()
        .unwrap();
    assert!(st.success());
}
/// Approve `dev` (fingerprint-confirmed) on the seed work dir; returns the
/// new device's data dir for key access.
fn approve_dev(seed: &Seed, s: &str, name: &str) -> (PathBuf, String) {
    let (jw, jd, dev) = add_join(seed, s, name);
    sync_pending_into_approver(seed, &jw);
    let pend = vault_core::approve::list_pending(&seed.work, &seed.store_id).unwrap();
    let fp = pend
        .iter()
        .find(|p| p.device_id == dev)
        .unwrap()
        .fingerprint
        .clone();
    vault_core::approve::approve(
        &seed.work,
        &seed.data,
        &pw(),
        &Libgit2Backend,
        &author(),
        &dev,
        &fp,
        NOW2,
        &mut |_| {},
    )
    .unwrap();
    (jd, dev)
}
/// This device's X25519 keypair from its data dir.
fn own_keys(data_dir: &Path) -> ([u8; 32], [u8; 32]) {
    let raw = fs::read(data_dir.join("device.key")).unwrap();
    let opened = vault_core::device_key::open(&raw, &pw(), &FastKdf).unwrap();
    let sec: [u8; 32] = opened.enc_secret.expose().to_vec().try_into().unwrap();
    (opened.enc_public, sec)
}
fn decrypt(env: &[u8], data_dir: &Path) -> Vec<u8> {
    let (publ, sec) = own_keys(data_dir);
    vault_core::envelope::decrypt(env, &publ, &sec).unwrap()
}

const PT: &[u8] = br#"{"v":1,"type":"note","id":"aaaaaaaaaaaaaaaaaaaaaaaaaa","rev":1,"updated":"2026-11-19T09:00:00Z","name":"n","content":"c"}"#;
fn pt(id: &str) -> Vec<u8> {
    format!(
        "{{\"v\":1,\"type\":\"note\",\"id\":\"{id}\",\"rev\":1,\"updated\":\"{NOW}\",\"name\":\"n\",\"content\":\"c\"}}"
    )
    .into_bytes()
}

#[test]
fn t55_01_missing_recipient_is_appended_payload_unchanged() {
    let seed = seed_first("t5501");
    let (b_data, _b_dev) = approve_dev(&seed, "t5501", "iphone");
    // Stale entry: sealed to A only while the verified list is [A, B].
    let (a_pub, _a_sec) = own_keys(&seed.data);
    let env = vault_core::envelope::encrypt(PT, &[a_pub]).unwrap();
    // Nonce + payload region: header nonce starts at 11, plen pads to 512.
    let before_payload = env[11..35 + 512 + 16].to_vec();
    fs::write(seed.work.join("aaaaaaaaaaaaaaaaaaaaaaaaaa.arg"), &env).unwrap();

    let out = vault_core::reconcile::reconcile(
        &seed.work,
        &seed.data,
        &pw(),
        &FastKdf,
        &Libgit2Backend,
        &author(),
    )
    .unwrap();
    assert_eq!(
        out.repaired,
        vec!["aaaaaaaaaaaaaaaaaaaaaaaaaa.arg".to_string()]
    );
    assert!(out.failed.is_empty());

    let after = fs::read(seed.work.join("aaaaaaaaaaaaaaaaaaaaaaaaaa.arg")).unwrap();
    // Payload (nonce + ciphertext) untouched: exactly one 80-byte sealed key
    // appended past the rcount field.
    assert_eq!(after.len(), env.len() + 80);
    assert_eq!(&after[11..35 + 512 + 16], &before_payload[..]);
    // Same file key: A decrypts the same padded plaintext as before.
    let dec_before =
        vault_core::envelope::decrypt(&env, &own_keys(&seed.data).0, &own_keys(&seed.data).1)
            .unwrap();
    let (a_pub2, a_sec2) = own_keys(&seed.data);
    assert_eq!(
        vault_core::envelope::decrypt(&after, &a_pub2, &a_sec2).unwrap(),
        dec_before
    );
    // B can now decrypt the same plaintext.
    assert_eq!(decrypt(&after, &b_data), dec_before);
    // Committed with the message `update`.
    let hist = Libgit2Backend.history(&seed.work).unwrap();
    assert_eq!(hist[0].message, "update");
}

#[test]
fn t55_02_extra_recipient_is_fully_reencrypted() {
    use vault_core::signatures::SigningKey;
    let seed = seed_first("t5502");
    let (b_data, b_dev) = approve_dev(&seed, "t5502", "iphone");
    // Entry sealed to [A, B] while both are members.
    let (a_pub, a_sec) = own_keys(&seed.data);
    let (b_pub, b_sec) = own_keys(&b_data);
    let id = "bbbbbbbbbbbbbbbbbbbbbbbbbb";
    let env = vault_core::envelope::encrypt(&pt(id), &[a_pub, b_pub]).unwrap();
    let before_payload = env[11..35 + 512 + 16].to_vec();
    fs::write(seed.work.join(format!("{id}.arg")), &env).unwrap();
    Libgit2Backend
        .commit(&seed.work, &author(), "update")
        .unwrap();
    // B leaves: list v3 without B, signed by A, pinned (revoke-lite through
    // production APIs; full revoke is T7.5).
    let raw = fs::read_to_string(seed.work.join("devices.json")).unwrap();
    let v2 = vault_core::device_list::parse_device_list(&raw).unwrap();
    let prev = v2.hash_hex().unwrap();
    let key_raw = fs::read(seed.data.join("device.key")).unwrap();
    let opened = vault_core::device_key::open(&key_raw, &pw(), &FastKdf).unwrap();
    let seed32: [u8; 32] = opened.sign_seed.expose().to_vec().try_into().unwrap();
    let signing = SigningKey::from_seed(seed32);
    let v3 = vault_core::device_list::DeviceList {
        store_id: v2.store_id.clone(),
        version: 3,
        prev,
        updated: NOW2.to_owned(),
        devices: v2.devices.into_iter().filter(|d| d.id != b_dev).collect(),
    };
    let v3_bytes = v3.canonical_json().unwrap();
    let v3_hash = v3.hash_hex().unwrap();
    let v3_sig = v3.sign(&seed.device_id, &signing).unwrap();
    fs::write(seed.work.join("devices.json"), &v3_bytes).unwrap();
    fs::write(
        seed.work.join("devices.sig"),
        v3_sig.to_canonical_json().unwrap(),
    )
    .unwrap();
    vault_core::trust::check_and_pin(&seed.data, &seed.store_id, 3, &v3_hash).unwrap();
    Libgit2Backend
        .commit(&seed.work, &author(), "update")
        .unwrap();

    let out = vault_core::reconcile::reconcile(
        &seed.work,
        &seed.data,
        &pw(),
        &FastKdf,
        &Libgit2Backend,
        &author(),
    )
    .unwrap();
    assert_eq!(out.repaired, vec![format!("{id}.arg")]);
    assert!(out.failed.is_empty());

    let after = fs::read(seed.work.join(format!("{id}.arg"))).unwrap();
    // Fresh file key and nonce: the payload region changed, and exactly one
    // sealed key remains.
    assert_eq!(after.len(), 35 + 512 + 16 + 2 + 80);
    assert_ne!(&after[11..35 + 512 + 16], &before_payload[..]);
    // Same plaintext for A; the removed device can no longer decrypt.
    let dec = vault_core::envelope::decrypt(&after, &a_pub, &a_sec).unwrap();
    assert!(dec.starts_with(&pt(id)[..]));
    assert!(vault_core::envelope::decrypt(&after, &b_pub, &b_sec).is_err());
}

#[test]
fn t55_03_foreign_seal_is_treated_as_extra() {
    let seed = seed_first("t5503");
    let (b_data, _b_dev) = approve_dev(&seed, "t5503", "iphone");
    let (a_pub, a_sec) = own_keys(&seed.data);
    let (b_pub, _b_sec) = own_keys(&b_data);
    // Outsider X, built through the production device-key API.
    let x_raw = vault_core::device_key::create(&pw(), &mut FixedRng(0x99), &FastKdf).unwrap();
    let x_opened = vault_core::device_key::open(&x_raw, &pw(), &FastKdf).unwrap();
    let x_sec: [u8; 32] = x_opened.enc_secret.expose().to_vec().try_into().unwrap();
    // Entry for [A, B] plus a seal for X: rcount 3 over 2 devices.
    let id = "cccccccccccccccccccccccccc";
    let env = vault_core::envelope::encrypt(&pt(id), &[a_pub, b_pub]).unwrap();
    let env =
        vault_core::envelope::add_recipient(&env, &x_opened.enc_public, &a_pub, &a_sec).unwrap();
    assert!(vault_core::envelope::decrypt(&env, &x_opened.enc_public, &x_sec).is_ok());
    fs::write(seed.work.join(format!("{id}.arg")), &env).unwrap();

    let out = vault_core::reconcile::reconcile(
        &seed.work,
        &seed.data,
        &pw(),
        &FastKdf,
        &Libgit2Backend,
        &author(),
    )
    .unwrap();
    assert_eq!(out.repaired, vec![format!("{id}.arg")]);
    assert!(out.failed.is_empty());

    let after = fs::read(seed.work.join(format!("{id}.arg"))).unwrap();
    assert_eq!(after.len(), 35 + 512 + 16 + 2 + 2 * 80);
    // A and B read the same plaintext; the outsider seal is gone.
    let dec = vault_core::envelope::decrypt(&after, &a_pub, &a_sec).unwrap();
    assert!(dec.starts_with(&pt(id)[..]));
    assert!(
        vault_core::envelope::decrypt(&after, &b_pub, &own_keys(&b_data).1)
            .unwrap()
            .starts_with(&pt(id)[..])
    );
    assert!(vault_core::envelope::decrypt(&after, &x_opened.enc_public, &x_sec).is_err());
}

#[test]
fn t55_04_repaired_entries_share_one_commit() {
    let seed = seed_first("t5504");
    let (_b_data, _b_dev) = approve_dev(&seed, "t5504", "iphone");
    let (a_pub, _a_sec) = own_keys(&seed.data);
    for id in ["dddddddddddddddddddddddddd", "eeeeeeeeeeeeeeeeeeeeeeeeee"] {
        let env = vault_core::envelope::encrypt(&pt(id), &[a_pub]).unwrap();
        fs::write(seed.work.join(format!("{id}.arg")), &env).unwrap();
    }
    let before = Libgit2Backend.history(&seed.work).unwrap().len();

    let out = vault_core::reconcile::reconcile(
        &seed.work,
        &seed.data,
        &pw(),
        &FastKdf,
        &Libgit2Backend,
        &author(),
    )
    .unwrap();
    assert_eq!(out.repaired.len(), 2);
    assert!(out.failed.is_empty());
    let hist = Libgit2Backend.history(&seed.work).unwrap();
    assert_eq!(hist.len(), before + 1);
    assert_eq!(hist[0].message, "update");
}

#[test]
fn t55_05_repair_failure_leaves_entry_unchanged_and_reported() {
    let seed = seed_first("t5505");
    let (_b_data, _b_dev) = approve_dev(&seed, "t5505", "iphone");
    let (a_pub, _a_sec) = own_keys(&seed.data);
    // One good stale entry.
    let good_id = "ffffffffffffffffffffffffff";
    let good_env = vault_core::envelope::encrypt(&pt(good_id), &[a_pub]).unwrap();
    fs::write(seed.work.join(format!("{good_id}.arg")), &good_env).unwrap();
    // Sealed to an outsider only: this device cannot open it.
    let x_raw = vault_core::device_key::create(&pw(), &mut FixedRng(0x77), &FastKdf).unwrap();
    let x_opened = vault_core::device_key::open(&x_raw, &pw(), &FastKdf).unwrap();
    let bad_id = "gggggggggggggggggggggggggg";
    let bad_env = vault_core::envelope::encrypt(&pt(bad_id), &[x_opened.enc_public]).unwrap();
    fs::write(seed.work.join(format!("{bad_id}.arg")), &bad_env).unwrap();
    // Structurally damaged envelope.
    let hurt_id = "hhhhhhhhhhhhhhhhhhhhhhhhhh";
    let mut hurt_env = vault_core::envelope::encrypt(&pt(hurt_id), &[a_pub]).unwrap();
    hurt_env[0] ^= 0xff;
    fs::write(seed.work.join(format!("{hurt_id}.arg")), &hurt_env).unwrap();
    let before = Libgit2Backend.history(&seed.work).unwrap().len();

    let out = vault_core::reconcile::reconcile(
        &seed.work,
        &seed.data,
        &pw(),
        &FastKdf,
        &Libgit2Backend,
        &author(),
    )
    .unwrap();
    assert_eq!(out.repaired, vec![format!("{good_id}.arg")]);
    assert_eq!(out.failed.len(), 2);
    assert!(out
        .failed
        .iter()
        .any(|f| f.file == format!("{bad_id}.arg") && f.reason == "decrypt"));
    assert!(out
        .failed
        .iter()
        .any(|f| f.file == format!("{hurt_id}.arg") && f.reason == "damaged"));
    // Failed entries are byte-identical; the good repair still committed once.
    assert_eq!(
        fs::read(seed.work.join(format!("{bad_id}.arg"))).unwrap(),
        bad_env
    );
    assert_eq!(
        fs::read(seed.work.join(format!("{hurt_id}.arg"))).unwrap(),
        hurt_env
    );
    let hist = Libgit2Backend.history(&seed.work).unwrap();
    assert_eq!(hist.len(), before + 1);
    assert_eq!(hist[0].message, "update");
}

#[test]
fn t55_07_error_displays_carry_no_secrets() {
    use vault_core::reconcile::Error;
    let cases = [
        (
            Error::Invalid("store"),
            "invalid reconcile: store".to_string(),
        ),
        (
            Error::VerificationFailed("pin"),
            "VerificationFailed(pin)".to_string(),
        ),
        (
            Error::DeviceKey(vault_core::device_key::Error::WrongPassword),
            "device key failed".to_string(),
        ),
        (
            Error::Trust(vault_core::trust::Error::Corrupt),
            "trust pin failed".to_string(),
        ),
        (
            Error::Git("commit failed"),
            "git failed: commit failed".to_string(),
        ),
        (
            Error::Io("read devices"),
            "reconcile io error: read devices".to_string(),
        ),
    ];
    for (e, want) in cases {
        assert_eq!(format!("{e}"), want);
    }
}

#[test]
fn t55_08_wrong_password_is_a_hard_error() {
    let seed = seed_first("t5508");
    let bad = MasterPassword::new(b"wrong password".to_vec());
    let err = vault_core::reconcile::reconcile(
        &seed.work,
        &seed.data,
        &bad,
        &FastKdf,
        &Libgit2Backend,
        &author(),
    )
    .unwrap_err();
    assert!(matches!(err, vault_core::reconcile::Error::DeviceKey(_)));
}

#[test]
fn t55_09_pin_for_another_store_is_refused() {
    let a = seed_first("t5509a");
    let b = seed_first("t5509b");
    // B's pin names B's store, but the checkout is A's store.
    let err = vault_core::reconcile::reconcile(
        &a.work,
        &b.data,
        &pw(),
        &FastKdf,
        &Libgit2Backend,
        &author(),
    )
    .unwrap_err();
    assert_eq!(
        err,
        vault_core::reconcile::Error::VerificationFailed("storeId")
    );
}

#[test]
fn t55_10_list_newer_than_pin_is_refused() {
    let seed = seed_first("t5510");
    // Rewrite devices.json with a new timestamp: the hash no longer matches
    // the pin, before any signature check runs.
    let raw = fs::read_to_string(seed.work.join("devices.json")).unwrap();
    let mut list = vault_core::device_list::parse_device_list(&raw).unwrap();
    list.updated = NOW2.to_owned();
    fs::write(
        seed.work.join("devices.json"),
        list.canonical_json().unwrap(),
    )
    .unwrap();
    let err = vault_core::reconcile::reconcile(
        &seed.work,
        &seed.data,
        &pw(),
        &FastKdf,
        &Libgit2Backend,
        &author(),
    )
    .unwrap_err();
    assert_eq!(err, vault_core::reconcile::Error::VerificationFailed("pin"));
}

#[test]
fn t55_11_tampered_signature_is_refused() {
    let seed = seed_first("t5511");
    let raw = fs::read_to_string(seed.work.join("devices.sig")).unwrap();
    let mut sig: serde_json::Value = serde_json::from_str(&raw).unwrap();
    // Flip the last base64url character to another valid one.
    let s = sig.get("sig").and_then(|v| v.as_str()).unwrap().to_owned();
    let mut chars: Vec<char> = s.chars().collect();
    let last = chars.len() - 1;
    chars[last] = if chars[last] == 'A' { 'B' } else { 'A' };
    sig["sig"] = serde_json::Value::String(chars.into_iter().collect());
    fs::write(seed.work.join("devices.sig"), sig.to_string()).unwrap();
    let err = vault_core::reconcile::reconcile(
        &seed.work,
        &seed.data,
        &pw(),
        &FastKdf,
        &Libgit2Backend,
        &author(),
    )
    .unwrap_err();
    assert_eq!(
        err,
        vault_core::reconcile::Error::VerificationFailed("badSignature")
    );
}

#[test]
fn t55_12_device_missing_from_list_is_refused() {
    let seed = seed_first("t5512");
    // Outsider C holds a copy of the pin but is not a member.
    let c_data = tmp("t5512-cdata");
    let c_key = vault_core::device_key::create(&pw(), &mut FixedRng(0x31), &FastKdf).unwrap();
    fs::write(c_data.join("device.key"), &c_key).unwrap();
    fs::copy(seed.data.join("trust.json"), c_data.join("trust.json")).unwrap();
    let err = vault_core::reconcile::reconcile(
        &seed.work,
        &c_data,
        &pw(),
        &FastKdf,
        &Libgit2Backend,
        &author(),
    )
    .unwrap_err();
    assert_eq!(
        err,
        vault_core::reconcile::Error::VerificationFailed("signer")
    );
}

#[test]
fn t55_13_unreadable_entry_is_reported() {
    let seed = seed_first("t5513");
    let (_b_data, _b_dev) = approve_dev(&seed, "t5513", "iphone");
    // A directory where an entry file should be: reading it fails.
    fs::create_dir(seed.work.join("iiiiiiiiiiiiiiiiiiiiiiiiii.arg")).unwrap();
    let out = vault_core::reconcile::reconcile(
        &seed.work,
        &seed.data,
        &pw(),
        &FastKdf,
        &Libgit2Backend,
        &author(),
    )
    .unwrap();
    assert!(out.repaired.is_empty());
    assert_eq!(out.failed.len(), 1);
    assert_eq!(out.failed[0].file, "iiiiiiiiiiiiiiiiiiiiiiiiii.arg");
    assert_eq!(out.failed[0].reason, "io");
}

#[test]
fn t55_14_extra_but_unopenable_entry_is_reported_unchanged() {
    let seed = seed_first("t5514");
    // Single-device list (n = 1); entry sealed to two outsiders (rcount 2).
    let x_raw = vault_core::device_key::create(&pw(), &mut FixedRng(0x71), &FastKdf).unwrap();
    let x = vault_core::device_key::open(&x_raw, &pw(), &FastKdf).unwrap();
    let y_raw = vault_core::device_key::create(&pw(), &mut FixedRng(0x72), &FastKdf).unwrap();
    let y = vault_core::device_key::open(&y_raw, &pw(), &FastKdf).unwrap();
    let id = "jjjjjjjjjjjjjjjjjjjjjjjjjj";
    let env = vault_core::envelope::encrypt(&pt(id), &[x.enc_public, y.enc_public]).unwrap();
    fs::write(seed.work.join(format!("{id}.arg")), &env).unwrap();
    let out = vault_core::reconcile::reconcile(
        &seed.work,
        &seed.data,
        &pw(),
        &FastKdf,
        &Libgit2Backend,
        &author(),
    )
    .unwrap();
    assert!(out.repaired.is_empty());
    assert_eq!(out.failed.len(), 1);
    assert_eq!(out.failed[0].file, format!("{id}.arg"));
    assert_eq!(out.failed[0].reason, "decrypt");
    assert_eq!(fs::read(seed.work.join(format!("{id}.arg"))).unwrap(), env);
}

#[test]
fn t55_15_unwritable_entry_is_a_hard_error() {
    use std::os::unix::fs::PermissionsExt;
    let seed = seed_first("t5515");
    let (_b_data, _b_dev) = approve_dev(&seed, "t5515", "iphone");
    let (a_pub, _a_sec) = own_keys(&seed.data);
    let id = "kkkkkkkkkkkkkkkkkkkkkkkkkk";
    let path = seed.work.join(format!("{id}.arg"));
    let env = vault_core::envelope::encrypt(&pt(id), &[a_pub]).unwrap();
    fs::write(&path, &env).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();
    let err = vault_core::reconcile::reconcile(
        &seed.work,
        &seed.data,
        &pw(),
        &FastKdf,
        &Libgit2Backend,
        &author(),
    )
    .unwrap_err();
    assert_eq!(err, vault_core::reconcile::Error::Io("write entry"));
}

struct FailCommit {
    fail_with: Option<vault_core::git::Error>,
}
impl Backend for FailCommit {
    fn init(&self, p: &Path) -> Result<(), vault_core::git::Error> {
        Libgit2Backend.init(p)
    }
    fn commit(&self, _p: &Path, _a: &Author, _m: &str) -> Result<String, vault_core::git::Error> {
        match &self.fail_with {
            Some(vault_core::git::Error::EmptyCommit) => Err(vault_core::git::Error::EmptyCommit),
            Some(_) => Err(vault_core::git::Error::Git("boom")),
            None => unreachable!("fail_with is always set in these tests"),
        }
    }
    fn history(
        &self,
        p: &Path,
    ) -> Result<Vec<vault_core::git::CommitInfo>, vault_core::git::Error> {
        Libgit2Backend.history(p)
    }
    fn is_repo(&self, p: &Path) -> bool {
        Libgit2Backend.is_repo(p)
    }
    fn clone_repo(&self, s: &Path, d: &Path) -> Result<(), vault_core::git::Error> {
        Libgit2Backend.clone_repo(s, d)
    }
    fn clone_shallow(&self, s: &Path, d: &Path) -> Result<(), vault_core::git::Error> {
        Libgit2Backend.clone_shallow(s, d)
    }
    fn add_remote(&self, p: &Path, n: &str, u: &str) -> Result<(), vault_core::git::Error> {
        Libgit2Backend.add_remote(p, n, u)
    }
    fn fetch(&self, p: &Path, r: &str) -> Result<(), vault_core::git::Error> {
        Libgit2Backend.fetch(p, r)
    }
    fn push(&self, p: &Path, r: &str) -> Result<(), vault_core::git::Error> {
        Libgit2Backend.push(p, r)
    }
    fn is_shallow(&self, p: &Path) -> bool {
        Libgit2Backend.is_shallow(p)
    }
    fn file_at(&self, p: &Path, c: &str, f: &str) -> Result<Vec<u8>, vault_core::git::Error> {
        Libgit2Backend.file_at(p, c, f)
    }
    fn fast_forward(&self, p: &Path, r: &str) -> Result<(), vault_core::git::Error> {
        Libgit2Backend.fast_forward(p, r)
    }
}

#[test]
fn t55_16_commit_failure_is_a_hard_error() {
    let seed = seed_first("t5516");
    let (_b_data, _b_dev) = approve_dev(&seed, "t5516", "iphone");
    let (a_pub, _a_sec) = own_keys(&seed.data);
    let id = "mmmmmmmmmmmmmmmmmmmmmmmmmm";
    let env = vault_core::envelope::encrypt(&pt(id), &[a_pub]).unwrap();
    fs::write(seed.work.join(format!("{id}.arg")), &env).unwrap();
    let backend = FailCommit {
        fail_with: Some(vault_core::git::Error::Git("boom")),
    };
    let err = vault_core::reconcile::reconcile(
        &seed.work,
        &seed.data,
        &pw(),
        &FastKdf,
        &backend,
        &author(),
    )
    .unwrap_err();
    assert_eq!(err, vault_core::reconcile::Error::Git("commit failed"));
}

#[test]
fn t55_17_empty_commit_is_swallowed() {
    let seed = seed_first("t5517");
    let (_b_data, _b_dev) = approve_dev(&seed, "t5517", "iphone");
    let (a_pub, _a_sec) = own_keys(&seed.data);
    let id = "nnnnnnnnnnnnnnnnnnnnnnnnnn";
    let env = vault_core::envelope::encrypt(&pt(id), &[a_pub]).unwrap();
    fs::write(seed.work.join(format!("{id}.arg")), &env).unwrap();
    let backend = FailCommit {
        fail_with: Some(vault_core::git::Error::EmptyCommit),
    };
    let out = vault_core::reconcile::reconcile(
        &seed.work,
        &seed.data,
        &pw(),
        &FastKdf,
        &backend,
        &author(),
    )
    .unwrap();
    assert_eq!(out.repaired, vec![format!("{id}.arg")]);
    assert!(out.failed.is_empty());
}
#[test]
fn t55_06_no_mismatch_no_commit() {
    let seed = seed_first("t5506");
    // Single device, entry already to the full verified set.
    let (a_pub, _a_sec) = own_keys(&seed.data);
    let id = "aaaaaaaaaaaaaaaaaaaaaaaaaa";
    let env = vault_core::envelope::encrypt(&pt(id), &[a_pub]).unwrap();
    fs::write(seed.work.join(format!("{id}.arg")), &env).unwrap();
    let before = Libgit2Backend.history(&seed.work).unwrap().len();

    let out = vault_core::reconcile::reconcile(
        &seed.work,
        &seed.data,
        &pw(),
        &FastKdf,
        &Libgit2Backend,
        &author(),
    )
    .unwrap();
    assert!(out.repaired.is_empty());
    assert!(out.failed.is_empty());
    assert_eq!(fs::read(seed.work.join(format!("{id}.arg"))).unwrap(), env);
    assert_eq!(Libgit2Backend.history(&seed.work).unwrap().len(), before);
}
