//! T5.3 approve tests (spec 04 section 4.3).
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
        "argus-t53-{}-{}-{}",
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
    let mut rng = FixedRng(0xaaaa);
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
    // Fast-forward the approver to the remote (which now holds the pending
    // commit). Manual file copies would diverge; a real pull keeps history
    // linear so the later approve push succeeds.
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

#[test]
fn t53_01_listing_returns_only_valid_requests() {
    let seed = seed_first("t5301");
    let (jw, _jd, dev) = add_join(&seed, "t5301", "iphone");
    sync_pending_into_approver(&seed, &jw);
    // Corrupt file must be ignored.
    fs::write(
        seed.work.join("pending-aaaaaaaaaaaaaaaaaaaaaaaaaa.json"),
        b"not json",
    )
    .unwrap();
    // Wrong store id must be ignored.
    fs::write(seed.work.join("pending-bbbbbbbbbbbbbbbbbbbbbbbbbb.json"), serde_json::json!({"v":1,"storeId":"cccccccccccccccccccccccccc","device":{"id":"bbbbbbbbbbbbbbbbbbbbbbbbbb","name":"x","enc":"argus1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq","sign":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},"created":NOW,"sig":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}).to_string()).unwrap();
    let list = vault_core::approve::list_pending(&seed.work, &seed.store_id).unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].device_id, dev);
}

#[test]
fn t53_02_approve_without_fingerprint_is_refused() {
    let seed = seed_first("t5302");
    let (jw, _jd, dev) = add_join(&seed, "t5302", "iphone");
    sync_pending_into_approver(&seed, &jw);
    let err = vault_core::approve::approve(
        &seed.work,
        &seed.data,
        &pw(),
        &Libgit2Backend,
        &author(),
        &dev,
        "",
        NOW2,
        &mut |_| {},
    )
    .unwrap_err();
    assert_eq!(err, vault_core::approve::Error::FingerprintRequired);
}

#[test]
fn t53_03_approve_with_mismatched_fingerprint_is_refused() {
    let seed = seed_first("t5303");
    let (jw, _jd, dev) = add_join(&seed, "t5303", "iphone");
    sync_pending_into_approver(&seed, &jw);
    let err = vault_core::approve::approve(
        &seed.work,
        &seed.data,
        &pw(),
        &Libgit2Backend,
        &author(),
        &dev,
        "0000 0000 0000 0000 0000 0000 0000 0000",
        NOW2,
        &mut |_| {},
    )
    .unwrap_err();
    assert_eq!(err, vault_core::approve::Error::FingerprintMismatch);
}

#[test]
fn t53_04_new_list_is_version_n_plus_1_with_prev_and_addedby() {
    let seed = seed_first("t5304");
    let (jw, _jd, dev) = add_join(&seed, "t5304", "iphone");
    sync_pending_into_approver(&seed, &jw);
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
    let raw = fs::read_to_string(seed.work.join("devices.json")).unwrap();
    let list = vault_core::device_list::parse_device_list(&raw).unwrap();
    assert_eq!(list.version, 2);
    assert_eq!(list.devices.len(), 2);
    let added = list.devices.iter().find(|d| d.id == dev).unwrap();
    assert_eq!(added.added_by, seed.device_id);
    assert!(!list.prev.is_empty());
}

#[test]
fn t53_05_after_approval_new_device_decrypts_entries() {
    let seed = seed_first("t5305");
    // Create an entry encrypted to the current verified list.
    let pin_raw = fs::read_to_string(seed.work.join("devices.json")).unwrap();
    let chain = vec![vault_core::device_list::ChainEntry {
        list_bytes: pin_raw.clone(),
        sig_bytes: fs::read_to_string(seed.work.join("devices.sig")).unwrap(),
    }];
    let verified =
        vault_core::recipients::VerifiedList::verify(&chain, &seed.store_id, false).unwrap();
    // Minimal entry plaintext: reuse entry module via envelope only; write envelope bytes as entry file.
    let pt = br#"{"v":1,"type":"note","id":"aaaaaaaaaaaaaaaaaaaaaaaaaa","rev":1,"updated":"2026-11-19T09:00:00Z","name":"n","content":"c"}"#;
    let env = verified.encrypt(pt).unwrap();
    fs::write(seed.work.join("aaaaaaaaaaaaaaaaaaaaaaaaaa.arg"), &env).unwrap();
    Libgit2Backend
        .commit(&seed.work, &author(), "update")
        .unwrap();
    Libgit2Backend.push(&seed.work, "origin").unwrap();
    let (jw, jd, dev) = add_join(&seed, "t5305", "iphone");
    // Approver sees the pending file.
    sync_pending_into_approver(&seed, &jw);
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
    // New device pulls: clone remote and decrypt.
    let backend = Libgit2Backend;
    let check = tmp("t5305-check");
    let _ = fs::remove_dir_all(&check);
    backend.clone_repo(&seed.remote, &check).unwrap();
    let enc_bytes = fs::read(check.join("aaaaaaaaaaaaaaaaaaaaaaaaaa.arg")).unwrap();
    // Open new device keys.
    let key_bytes = fs::read(jd.join("device.key")).unwrap();
    // FastKdf is test-only; use production open with same KDF.
    let opened = vault_core::device_key::open(&key_bytes, &pw(), &FastKdf).unwrap();
    let enc_secret: [u8; 32] = opened.enc_secret.expose().to_vec().try_into().unwrap();
    let dec = vault_core::envelope::decrypt(&enc_bytes, &opened.enc_public, &enc_secret).unwrap();
    assert!(dec.starts_with(br#"{"v":1"#));
}

#[test]
fn t53_06_pending_file_removed_in_same_commit() {
    let seed = seed_first("t5306");
    let (jw, _jd, dev) = add_join(&seed, "t5306", "iphone");
    sync_pending_into_approver(&seed, &jw);
    assert!(seed.work.join(format!("pending-{dev}.json")).is_file());
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
    assert!(!seed.work.join(format!("pending-{dev}.json")).exists());
    let hist = Libgit2Backend.history(&seed.work).unwrap();
    assert_eq!(hist[0].message, "update");
}

#[test]
fn t53_07_rejected_push_triggers_redo() {
    use std::cell::RefCell;
    struct RejectOnce<B: Backend> {
        inner: B,
        n: RefCell<u32>,
    }
    impl<B: Backend> Backend for RejectOnce<B> {
        fn init(&self, p: &Path) -> Result<(), vault_core::git::Error> {
            self.inner.init(p)
        }
        fn commit(&self, p: &Path, a: &Author, m: &str) -> Result<String, vault_core::git::Error> {
            self.inner.commit(p, a, m)
        }
        fn history(
            &self,
            p: &Path,
        ) -> Result<Vec<vault_core::git::CommitInfo>, vault_core::git::Error> {
            self.inner.history(p)
        }
        fn is_repo(&self, p: &Path) -> bool {
            self.inner.is_repo(p)
        }
        fn clone_repo(&self, s: &Path, d: &Path) -> Result<(), vault_core::git::Error> {
            self.inner.clone_repo(s, d)
        }
        fn clone_shallow(&self, s: &Path, d: &Path) -> Result<(), vault_core::git::Error> {
            self.inner.clone_shallow(s, d)
        }
        fn add_remote(&self, p: &Path, n: &str, u: &str) -> Result<(), vault_core::git::Error> {
            self.inner.add_remote(p, n, u)
        }
        fn fetch(&self, p: &Path, r: &str) -> Result<(), vault_core::git::Error> {
            self.inner.fetch(p, r)
        }
        fn push(&self, p: &Path, r: &str) -> Result<(), vault_core::git::Error> {
            let mut n = self.n.borrow_mut();
            *n += 1;
            if *n == 1 {
                return Err(vault_core::git::Error::Rejected);
            }
            self.inner.push(p, r)
        }
        fn is_shallow(&self, p: &Path) -> bool {
            self.inner.is_shallow(p)
        }
        fn file_at(&self, p: &Path, c: &str, f: &str) -> Result<Vec<u8>, vault_core::git::Error> {
            self.inner.file_at(p, c, f)
        }
        fn fast_forward(&self, p: &Path, r: &str) -> Result<(), vault_core::git::Error> {
            self.inner.fast_forward(p, r)
        }
    }
    let seed = seed_first("t5307");
    let (jw, _jd, dev) = add_join(&seed, "t5307", "iphone");
    sync_pending_into_approver(&seed, &jw);
    let pend = vault_core::approve::list_pending(&seed.work, &seed.store_id).unwrap();
    let fp = pend
        .iter()
        .find(|p| p.device_id == dev)
        .unwrap()
        .fingerprint
        .clone();
    let b = RejectOnce {
        inner: Libgit2Backend,
        n: RefCell::new(0),
    };
    let out = vault_core::approve::approve(
        &seed.work,
        &seed.data,
        &pw(),
        &b,
        &author(),
        &dev,
        &fp,
        NOW2,
        &mut |_| {},
    )
    .unwrap();
    assert_eq!(out.version, 2);
    assert_eq!(*b.n.borrow(), 2);
}

#[test]
fn t53_08_anchor_matches_new_device_view() {
    let seed = seed_first("t5308");
    let (jw, _jd, dev) = add_join(&seed, "t5308", "iphone");
    sync_pending_into_approver(&seed, &jw);
    let pend = vault_core::approve::list_pending(&seed.work, &seed.store_id).unwrap();
    let fp = pend
        .iter()
        .find(|p| p.device_id == dev)
        .unwrap()
        .fingerprint
        .clone();
    let out = vault_core::approve::approve(
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
    let file_bytes = fs::read(seed.work.join("devices.json")).unwrap();
    let expected = vault_core::identity::anchor_display(out.version, &file_bytes);
    assert_eq!(out.anchor, expected);
}

#[test]
fn t53_09_payload_and_file_key_unchanged() {
    let seed = seed_first("t5309");
    let pin_raw = fs::read_to_string(seed.work.join("devices.json")).unwrap();
    let chain = vec![vault_core::device_list::ChainEntry {
        list_bytes: pin_raw.clone(),
        sig_bytes: fs::read_to_string(seed.work.join("devices.sig")).unwrap(),
    }];
    let verified =
        vault_core::recipients::VerifiedList::verify(&chain, &seed.store_id, false).unwrap();
    let pt = br#"{"v":1,"type":"note","id":"bbbbbbbbbbbbbbbbbbbbbbbbbb","rev":1,"updated":"2026-11-19T09:00:00Z","name":"n","content":"c"}"#;
    let env = verified.encrypt(pt).unwrap();
    // Capture nonce+payload region (header 35 bytes .. payload end).
    let before_payload = env[11..35 + 512 + 16].to_vec();
    fs::write(seed.work.join("bbbbbbbbbbbbbbbbbbbbbbbbbb.arg"), &env).unwrap();
    Libgit2Backend
        .commit(&seed.work, &author(), "update")
        .unwrap();
    Libgit2Backend.push(&seed.work, "origin").unwrap();
    let (jw, _jd, dev) = add_join(&seed, "t5309", "iphone");
    sync_pending_into_approver(&seed, &jw);
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
    let after = fs::read(seed.work.join("bbbbbbbbbbbbbbbbbbbbbbbbbb.arg")).unwrap();
    assert_eq!(&after[11..35 + 512 + 16], &before_payload[..]);
}

#[test]
fn t53_10_approving_device_already_in_list_is_refused() {
    let seed = seed_first("t5310");
    let err = vault_core::approve::approve(
        &seed.work,
        &seed.data,
        &pw(),
        &Libgit2Backend,
        &author(),
        &seed.device_id,
        "whatever",
        NOW2,
        &mut |_| {},
    )
    .unwrap_err();
    assert_eq!(err, vault_core::approve::Error::AlreadyMember);
}

#[test]
fn t53_11_approve_commit_message_is_update() {
    let seed = seed_first("t5311");
    let (jw, _jd, dev) = add_join(&seed, "t5311", "iphone");
    sync_pending_into_approver(&seed, &jw);
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
    let hist = Libgit2Backend.history(&seed.work).unwrap();
    assert_eq!(hist[0].message, "update");
}
