//! T5.4 verify anchor tests (spec 04 section 4.4).
use std::fs;
use std::path::{Path, PathBuf};
use vault_core::device_key::Kdf;
use vault_core::git::{Author, Backend, Libgit2Backend, SystemBackend};
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
        "argus-t54-{}-{}-{}",
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
}
fn seed_first<B: Backend>(s: &str, backend: &B) -> Seed {
    let remote = tmp(&format!("{s}-remote"));
    bare(&remote);
    let work = tmp(&format!("{s}-work"));
    let data = tmp(&format!("{s}-data"));
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
        backend,
        &author(),
        NOW,
        &mut |_| {},
    )
    .unwrap();
    let store_id = match out {
        vault_core::init::Outcome::Created { store_id, .. } => store_id,
        _ => panic!("created"),
    };
    Seed {
        remote,
        work,
        data,
        store_id,
    }
}
struct JoinSeed {
    work: PathBuf,
    data: PathBuf,
    device_id: String,
}
fn add_join<B: Backend>(seed: &Seed, s: &str, backend: &B) -> JoinSeed {
    let join_work = tmp(&format!("{s}-joinwork"));
    backend.clone_repo(&seed.remote, &join_work).unwrap();
    let join_data = tmp(&format!("{s}-joindata"));
    let mut rng = FixedRng(0x5300 + s.len() as u64);
    let out = vault_core::join::join(
        &join_work,
        &join_data,
        "iphone",
        &pw(),
        &mut rng,
        &FastKdf,
        backend,
        &author(),
        NOW,
        &mut |_| {},
    )
    .unwrap();
    let device_id = match out {
        vault_core::join::Outcome::Requested { device_id, .. } => device_id,
    };
    JoinSeed {
        work: join_work,
        data: join_data,
        device_id,
    }
}
/// Approve the join; returns the anchor. Plants one entry first so the new
/// device has something to decrypt (T5.4-05).
fn approve_new<B: Backend>(seed: &Seed, js: &JoinSeed, backend: &B) -> String {
    // Plant an entry encrypted to the approver only.
    let key_bytes = fs::read(seed.data.join("device.key")).unwrap();
    let opened = vault_core::device_key::open(&key_bytes, &pw(), &FastKdf).unwrap();
    let pt = b"{\"v\":1,\"type\":\"note\",\"id\":\"aaaaaaaaaaaaaaaaaaaaaaaaaa\",\"name\":\"n\",\"content\":\"c\",\"rev\":1,\"updated\":\"2026-11-19T09:00:00Z\"}                                                        ";
    let env = vault_core::envelope::encrypt(pt, &[opened.enc_public]).unwrap();
    fs::write(seed.work.join("aaaaaaaaaaaaaaaaaaaaaaaaaa.arg"), env).unwrap();
    // Bring the approver up to date with the pending commit.
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
    let pending = vault_core::approve::list_pending(&seed.work, &seed.store_id).unwrap();
    let p = pending
        .iter()
        .find(|p| p.device_id == js.device_id)
        .unwrap();
    let out = vault_core::approve::approve(
        &seed.work,
        &seed.data,
        &pw(),
        backend,
        &author(),
        &js.device_id,
        &p.fingerprint,
        NOW2,
        &mut |_| {},
    )
    .unwrap();
    out.anchor
}

macro_rules! both_backends {
    ($s:expr, $f:ident) => {
        $f(&Libgit2Backend, &format!("{}-git2", $s));
        $f(&SystemBackend, &format!("{}-sys", $s));
    };
}

#[test]
fn t54_01_matching_anchor_verifies_pins_and_cleans_up() {
    both_backends!("t5401", t54_01_inner);
}
fn t54_01_inner<B: Backend>(backend: &B, s: &str) {
    let seed = seed_first(s, backend);
    let js = add_join(&seed, s, backend);
    let anchor = approve_new(&seed, &js, backend);
    // The join checkout is stale on purpose: verify must pull itself.
    let out = vault_core::verify::verify(
        &js.work,
        &js.data,
        &pw(),
        &FastKdf,
        backend,
        &anchor,
        &mut |_| {},
    )
    .unwrap();
    assert_eq!(out.version, 2);
    assert!(!js.data.join("join_state.json").exists());
    let pin = vault_core::trust::load(&js.data).unwrap().unwrap();
    assert_eq!(pin.store_id, seed.store_id);
    assert_eq!(pin.version, 2);
    assert_eq!(pin.hash, out.hash);
}

#[test]
fn t54_02_mismatching_anchor_fails_and_keeps_keys() {
    both_backends!("t5402", t54_02_inner);
}
fn t54_02_inner<B: Backend>(backend: &B, s: &str) {
    let seed = seed_first(s, backend);
    let js = add_join(&seed, s, backend);
    let anchor = approve_new(&seed, &js, backend);
    let mut bad = anchor.clone();
    let last = bad.pop().unwrap();
    bad.push(if last == '0' { '1' } else { '0' });
    let err = vault_core::verify::verify(
        &js.work,
        &js.data,
        &pw(),
        &FastKdf,
        backend,
        &bad,
        &mut |_| {},
    )
    .unwrap_err();
    assert!(
        matches!(err, vault_core::verify::Error::VerificationFailed(_)),
        "unexpected {err:?}"
    );
    assert!(js.data.join("device.key").exists());
    assert!(js.data.join("join_state.json").exists());
}

#[test]
fn t54_03_anchor_for_version_not_in_history_fails() {
    both_backends!("t5403", t54_03_inner);
}
fn t54_03_inner<B: Backend>(backend: &B, s: &str) {
    let seed = seed_first(s, backend);
    let js = add_join(&seed, s, backend);
    let anchor = approve_new(&seed, &js, backend);
    // Same shape, version 9 which does not exist.
    let cut = anchor.find(' ').unwrap();
    let fake = format!("v9{}", &anchor[cut..]);
    let err = vault_core::verify::verify(
        &js.work,
        &js.data,
        &pw(),
        &FastKdf,
        backend,
        &fake,
        &mut |_| {},
    )
    .unwrap_err();
    assert!(
        matches!(err, vault_core::verify::Error::VerificationFailed(_)),
        "unexpected {err:?}"
    );
}

#[test]
fn t54_04_anchor_parse_ignores_case_and_spaces() {
    both_backends!("t5404", t54_04_inner);
}
fn t54_04_inner<B: Backend>(backend: &B, s: &str) {
    let seed = seed_first(s, backend);
    let js = add_join(&seed, s, backend);
    let anchor = approve_new(&seed, &js, backend);
    let noisy = anchor.to_uppercase().replace(' ', "  ");
    vault_core::verify::verify(
        &js.work,
        &js.data,
        &pw(),
        &FastKdf,
        backend,
        &noisy,
        &mut |_| {},
    )
    .unwrap();
}

#[test]
fn t54_05_after_verify_new_device_decrypts_entries() {
    both_backends!("t5405", t54_05_inner);
}
fn t54_05_inner<B: Backend>(backend: &B, s: &str) {
    let seed = seed_first(s, backend);
    let js = add_join(&seed, s, backend);
    let anchor = approve_new(&seed, &js, backend);
    vault_core::verify::verify(
        &js.work,
        &js.data,
        &pw(),
        &FastKdf,
        backend,
        &anchor,
        &mut |_| {},
    )
    .unwrap();
    let key_bytes = fs::read(js.data.join("device.key")).unwrap();
    let opened = vault_core::device_key::open(&key_bytes, &pw(), &FastKdf).unwrap();
    let secret: [u8; 32] = opened.enc_secret.expose().try_into().unwrap();
    let env = fs::read(js.work.join("aaaaaaaaaaaaaaaaaaaaaaaaaa.arg")).unwrap();
    let pt = vault_core::envelope::decrypt(&env, &opened.enc_public, &secret).unwrap();
    assert!(pt.starts_with(b"{\"v\":1,\"type\":\"note\""));
}

#[test]
fn t54_06_verify_without_pending_join_is_refused() {
    both_backends!("t5406", t54_06_inner);
}
fn t54_06_inner<B: Backend>(backend: &B, s: &str) {
    let seed = seed_first(s, backend);
    let err = vault_core::verify::verify(
        &seed.work,
        &seed.data,
        &pw(),
        &FastKdf,
        backend,
        "v1 aaaa bbbb cccc dddd eeee ffff 1111 2222",
        &mut |_| {},
    )
    .unwrap_err();
    assert_eq!(err, vault_core::verify::Error::NoPendingJoin);
}

#[test]
fn t54_07_store_id_mismatch_is_refused() {
    both_backends!("t5407", t54_07_inner);
}
fn t54_07_inner<B: Backend>(backend: &B, s: &str) {
    let seed = seed_first(s, backend);
    let js = add_join(&seed, s, backend);
    let anchor = approve_new(&seed, &js, backend);
    // Tamper the join state so it names a different store.
    let raw = fs::read(js.data.join("join_state.json")).unwrap();
    let mut state: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    state["storeId"] = serde_json::Value::from("cccccccccccccccccccccccccc");
    fs::write(js.data.join("join_state.json"), state.to_string()).unwrap();
    let err = vault_core::verify::verify(
        &js.work,
        &js.data,
        &pw(),
        &FastKdf,
        backend,
        &anchor,
        &mut |_| {},
    )
    .unwrap_err();
    assert_eq!(err, vault_core::verify::Error::StoreIdMismatch);
}

#[test]
fn t54_08_garbage_anchor_text_is_invalid() {
    both_backends!("t5408", t54_08_inner);
}
fn t54_08_inner<B: Backend>(backend: &B, s: &str) {
    let seed = seed_first(s, backend);
    let js = add_join(&seed, s, backend);
    let _ = approve_new(&seed, &js, backend);
    let err = vault_core::verify::verify(
        &js.work,
        &js.data,
        &pw(),
        &FastKdf,
        backend,
        "not an anchor",
        &mut |_| {},
    )
    .unwrap_err();
    assert_eq!(err, vault_core::verify::Error::Invalid("anchor"));
}

#[test]
fn t54_09_undecryptable_entry_fails_verification() {
    both_backends!("t5409", t54_09_inner);
}
fn t54_09_inner<B: Backend>(backend: &B, s: &str) {
    let seed = seed_first(s, backend);
    let js = add_join(&seed, s, backend);
    let anchor = approve_new(&seed, &js, backend);
    // A junk entry the new device cannot open (untracked, survives pull).
    fs::write(js.work.join("zzzzzzzzzzzzzzzzzzzzzzzzzz.arg"), b"junk").unwrap();
    let err = vault_core::verify::verify(
        &js.work,
        &js.data,
        &pw(),
        &FastKdf,
        backend,
        &anchor,
        &mut |_| {},
    )
    .unwrap_err();
    assert_eq!(err, vault_core::verify::Error::VerificationFailed("entry"));
}

#[test]
fn t54_10_swapped_device_key_fails_membership() {
    both_backends!("t5410", t54_10_inner);
}
fn t54_10_inner<B: Backend>(backend: &B, s: &str) {
    let seed = seed_first(s, backend);
    let js = add_join(&seed, s, backend);
    let anchor = approve_new(&seed, &js, backend);
    // Replace device.key with a different device's keys (same password):
    // the list entry no longer carries this device's keys.
    let mut rng = FixedRng(0x9999);
    let other = vault_core::device_key::create(&pw(), &mut rng, &FastKdf).unwrap();
    fs::write(js.data.join("device.key"), other).unwrap();
    let err = vault_core::verify::verify(
        &js.work,
        &js.data,
        &pw(),
        &FastKdf,
        backend,
        &anchor,
        &mut |_| {},
    )
    .unwrap_err();
    assert_eq!(err, vault_core::verify::Error::VerificationFailed("member"));
}

#[test]
fn t54_11_error_display_carries_no_secrets() {
    use vault_core::verify::Error;
    let cases = [
        (Error::NoPendingJoin, "no pending join request"),
        (Error::StoreIdMismatch, "store id mismatch"),
        (Error::Invalid("anchor"), "invalid verify: anchor"),
        (
            Error::VerificationFailed("anchor"),
            "VerificationFailed(anchor)",
        ),
        (
            Error::RemoteUnreachable { attempts: 3 },
            "remote unreachable after 3 attempts",
        ),
        (Error::RemoteRejected, "remote rejected the request"),
        (
            Error::DeviceKey(vault_core::device_key::Error::WrongPassword),
            "device key failed",
        ),
        (
            Error::Trust(vault_core::trust::Error::Rollback),
            "trust pin failed",
        ),
        (Error::Git("x"), "git failed: x"),
        (Error::Io("y"), "verify io error: y"),
    ];
    for (e, text) in cases {
        assert_eq!(format!("{e}"), text);
    }
}
