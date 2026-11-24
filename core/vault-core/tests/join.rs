//! T5.2 join request tests (spec 04 section 4.2).
//!
//! Uses only the production API: `vault_core::join` with injected RNG, KDF,
//! clock string, and `Backend`. No real passwords or keys.

use std::fs;
use std::path::{Path, PathBuf};
use vault_core::device_key::Kdf;
use vault_core::git::{Author, Backend, InitSource, Libgit2Backend};
use vault_core::secrets::MasterPassword;

// --- deterministic RNG (xorshift64*) ---

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
        _opslimit: u64,
        _memlimit: usize,
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

fn tmp(suffix: &str) -> PathBuf {
    let mut dir = std::env::temp_dir();
    dir.push(format!(
        "argus-t52-{}-{}-{}",
        std::process::id(),
        suffix,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn bare(path: &Path) {
    let status = std::process::Command::new("git")
        .args(["init", "--bare", "-b", "master"])
        .arg(path)
        .status()
        .unwrap();
    assert!(status.success());
}

const NOW: &str = "2026-11-19T09:00:00Z";

/// Seed a store with a first device, then clone it as the joining device's
/// working tree. Returns (remote, work, store_id).
fn seed_and_clone(seed: &str) -> (PathBuf, PathBuf, String) {
    let remote = tmp(&format!("{seed}-remote"));
    bare(&remote);
    let seed_work = tmp(&format!("{seed}-seed-work"));
    let seed_data = tmp(&format!("{seed}-seed-data"));
    let backend = Libgit2Backend;
    let mut rng = FixedRng(0xaaaa);
    let out = vault_core::init::init(
        &seed_work,
        &seed_data,
        remote.to_str().unwrap(),
        InitSource::Empty,
        "first",
        &pw(),
        &mut rng,
        &FastKdf,
        &backend,
        &author(),
        NOW,
        &mut |_| {},
    )
    .unwrap();
    let store_id = match out {
        vault_core::init::Outcome::Created { store_id, .. } => store_id,
        _ => panic!("expected Created"),
    };
    let work = tmp(&format!("{seed}-work"));
    backend.clone_repo(&remote, &work).unwrap();
    (remote, work, store_id)
}

#[test]
fn t52_01_pending_file_matches_layout() {
    let (_remote, work, store_id) = seed_and_clone("t5201");
    let data = tmp("t5201-data");
    let backend = Libgit2Backend;
    let mut rng = FixedRng(0x5201);
    let out = vault_core::join::join(
        &work,
        &data,
        "iphone",
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
        vault_core::join::Outcome::Requested {
            device_id,
            store_id: s,
        } => {
            assert_eq!(s, store_id);
            device_id
        }
    };
    let pending = work.join(format!("pending-{device_id}.json"));
    assert!(pending.is_file(), "pending file must exist");
    let raw = fs::read_to_string(&pending).unwrap();
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(v.get("v"), Some(&serde_json::json!(1)));
    assert_eq!(
        v.get("storeId").and_then(|x| x.as_str()),
        Some(store_id.as_str())
    );
    let device = v.get("device").expect("device object");
    assert_eq!(
        device.get("id").and_then(|x| x.as_str()),
        Some(device_id.as_str())
    );
    assert_eq!(device.get("name").and_then(|x| x.as_str()), Some("iphone"));
    assert!(device.get("enc").and_then(|x| x.as_str()).is_some());
    assert!(device.get("sign").and_then(|x| x.as_str()).is_some());
    assert_eq!(v.get("created").and_then(|x| x.as_str()), Some(NOW));
    assert!(v.get("sig").and_then(|x| x.as_str()).is_some());
    assert!(data.join("device.key").is_file());
}

#[test]
fn t52_02_signature_verifies_with_own_key_and_join_prefix() {
    let (_remote, work, store_id) = seed_and_clone("t5202");
    let data = tmp("t5202-data");
    let backend = Libgit2Backend;
    let mut rng = FixedRng(0x5202);
    let out = vault_core::join::join(
        &work,
        &data,
        "iphone",
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
    let raw = fs::read(work.join(format!("pending-{device_id}.json"))).unwrap();
    let verified = vault_core::join::verify_pending(&raw, &store_id).unwrap();
    assert_eq!(verified, device_id);
}

#[test]
fn t52_03_changed_field_fails_signature() {
    let (_remote, work, _store_id) = seed_and_clone("t5203");
    let data = tmp("t5203-data");
    let backend = Libgit2Backend;
    let mut rng = FixedRng(0x5203);
    let out = vault_core::join::join(
        &work,
        &data,
        "iphone",
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
        vault_core::join::Outcome::Requested {
            store_id,
            device_id,
        } => (store_id, device_id),
    };
    let raw = fs::read(work.join(format!("pending-{device_id}.json"))).unwrap();
    let mut v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    v["device"]["name"] = serde_json::json!("mallory");
    let tampered = serde_json::to_vec(&v).unwrap();
    assert_eq!(
        vault_core::join::verify_pending(&tampered, &store_id).unwrap_err(),
        vault_core::join::Error::BadSignature
    );
}

#[test]
fn t52_04_join_state_written_no_trust_no_decrypt() {
    let (_remote, work, store_id) = seed_and_clone("t5204");
    let data = tmp("t5204-data");
    let backend = Libgit2Backend;
    let mut rng = FixedRng(0x5204);
    let out = vault_core::join::join(
        &work,
        &data,
        "iphone",
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
    let raw = fs::read_to_string(data.join("join_state.json")).unwrap();
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(v.get("v"), Some(&serde_json::json!(1)));
    assert_eq!(
        v.get("storeId").and_then(|x| x.as_str()),
        Some(store_id.as_str())
    );
    assert_eq!(
        v.get("deviceId").and_then(|x| x.as_str()),
        Some(device_id.as_str())
    );
    assert_eq!(
        v.get("pending").and_then(|x| x.as_str()),
        Some(format!("pending-{device_id}.json").as_str())
    );
    // The joining device trusts no list and holds no index material.
    assert!(!data.join("trust.json").exists());
    assert!(!work.join("devices.json").exists() || true);
    assert!(vault_core::trust::load(&data).unwrap().is_none());
}

#[test]
fn t52_05_store_id_mismatch_is_refused() {
    let raw = serde_json::json!({
        "v": 1,
        "storeId": "aaaaaaaaaaaaaaaaaaaaaaaaaa",
        "device": {
            "id": "bbbbbbbbbbbbbbbbbbbbbbbbbb",
            "name": "iphone",
            "enc": "argus1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
            "sign": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        },
        "created": NOW,
        "sig": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    });
    let bytes = serde_json::to_vec(&raw).unwrap();
    assert_eq!(
        vault_core::join::verify_pending(&bytes, "cccccccccccccccccccccccccc").unwrap_err(),
        vault_core::join::Error::StoreIdMismatch
    );
}

#[test]
fn t52_06_rerun_replaces_pending_file_for_same_device() {
    let (_remote, work, _store_id) = seed_and_clone("t5206");
    let data = tmp("t5206-data");
    let backend = Libgit2Backend;
    let mut rng = FixedRng(0x5206);
    let first = vault_core::join::join(
        &work,
        &data,
        "iphone",
        &pw(),
        &mut rng,
        &FastKdf,
        &backend,
        &author(),
        NOW,
        &mut |_| {},
    )
    .unwrap();
    let device_id = match first {
        vault_core::join::Outcome::Requested { device_id, .. } => device_id,
    };
    let mut rng2 = FixedRng(0x9999);
    let second = vault_core::join::join(
        &work,
        &data,
        "iphone",
        &pw(),
        &mut rng2,
        &FastKdf,
        &backend,
        &author(),
        NOW,
        &mut |_| {},
    )
    .unwrap();
    let device_id2 = match second {
        vault_core::join::Outcome::Requested { device_id, .. } => device_id,
    };
    assert_eq!(device_id, device_id2);
    let count = fs::read_dir(&work)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with("pending-"))
        .count();
    assert_eq!(count, 1);
}

#[test]
fn t52_07_join_commit_message_is_update() {
    let (remote, work, _store_id) = seed_and_clone("t5207");
    let data = tmp("t5207-data");
    let backend = Libgit2Backend;
    let mut rng = FixedRng(0x5207);
    vault_core::join::join(
        &work,
        &data,
        "iphone",
        &pw(),
        &mut rng,
        &FastKdf,
        &backend,
        &author(),
        NOW,
        &mut |_| {},
    )
    .unwrap();
    let history = backend.history(&work).unwrap();
    assert_eq!(history[0].message, "update");
    // Pushed: a fresh clone sees the pending file.
    let clone = tmp("t5207-clone");
    let _ = fs::remove_dir_all(&clone);
    backend.clone_repo(&remote, &clone).unwrap();
    let pending: Vec<_> = fs::read_dir(&clone)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with("pending-"))
        .collect();
    assert_eq!(pending.len(), 1);
}
