//! T5.1 init tests (spec 04 sections 4.1, 4.2).
//!
//! Uses only the production API: `vault_core::init` with injected RNG, KDF,
//! clock string, and `Backend`. No real passwords or keys.

use std::cell::RefCell;
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

/// Backend wrapper that fails `push` with a retryable error `fail` times.
struct FlakyPush<B: Backend> {
    inner: B,
    remaining: RefCell<u32>,
    attempts: RefCell<u32>,
}

impl<B: Backend> Backend for FlakyPush<B> {
    fn init(&self, path: &Path) -> Result<(), vault_core::git::Error> {
        self.inner.init(path)
    }
    fn commit(
        &self,
        path: &Path,
        author: &Author,
        message: &str,
    ) -> Result<String, vault_core::git::Error> {
        self.inner.commit(path, author, message)
    }
    fn history(
        &self,
        path: &Path,
    ) -> Result<Vec<vault_core::git::CommitInfo>, vault_core::git::Error> {
        self.inner.history(path)
    }
    fn is_repo(&self, path: &Path) -> bool {
        self.inner.is_repo(path)
    }
    fn clone_repo(&self, src: &Path, dst: &Path) -> Result<(), vault_core::git::Error> {
        self.inner.clone_repo(src, dst)
    }
    fn clone_shallow(&self, src: &Path, dst: &Path) -> Result<(), vault_core::git::Error> {
        self.inner.clone_shallow(src, dst)
    }
    fn add_remote(&self, path: &Path, name: &str, url: &str) -> Result<(), vault_core::git::Error> {
        self.inner.add_remote(path, name, url)
    }
    fn fetch(&self, path: &Path, remote: &str) -> Result<(), vault_core::git::Error> {
        self.inner.fetch(path, remote)
    }
    fn push(&self, path: &Path, remote: &str) -> Result<(), vault_core::git::Error> {
        *self.attempts.borrow_mut() += 1;
        if *self.remaining.borrow() > 0 {
            *self.remaining.borrow_mut() -= 1;
            return Err(vault_core::git::Error::Git("boom"));
        }
        self.inner.push(path, remote)
    }
    fn is_shallow(&self, path: &Path) -> bool {
        self.inner.is_shallow(path)
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
        "argus-t51-{}-{}-{}",
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

#[test]
fn t51_01_empty_remote_creates_store_list_sig_committed_pushed() {
    let remote = tmp("remote");
    bare(&remote);
    let work = tmp("work");
    let data = tmp("data");
    let backend = Libgit2Backend;
    let mut rng = FixedRng(0x1234_5678_9abc_def1);
    let out = vault_core::init::init(
        &work,
        &data,
        remote.to_str().unwrap(),
        InitSource::Empty,
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
    let vault_core::init::Outcome::Created { store_id, .. } = out else {
        panic!("expected Created");
    };
    assert!(work.join("store.json").is_file());
    assert!(work.join("devices.json").is_file());
    assert!(work.join("devices.sig").is_file());
    assert!(data.join("device.key").is_file());
    // T5.1-02 is asserted in its own test via trust.json; also check here.
    let pin = vault_core::trust::load(&data).unwrap().unwrap();
    assert_eq!(pin.store_id, store_id);
    assert_eq!(pin.version, 1);
    // Committed and pushed: fresh clone sees the same store id.
    let clone = tmp("clone");
    let _ = fs::remove_dir_all(&clone);
    backend.clone_repo(&remote, &clone).unwrap();
    let info = vault_core::store::open(&clone).unwrap();
    assert_eq!(info.store_id, store_id);
    let history = backend.history(&work).unwrap();
    assert_eq!(history.len(), 1);
}

#[test]
fn t51_02_trust_pins_version_1_after_init() {
    let remote = tmp("remote2");
    bare(&remote);
    let work = tmp("work2");
    let data = tmp("data2");
    let backend = Libgit2Backend;
    let mut rng = FixedRng(0x2222);
    vault_core::init::init(
        &work,
        &data,
        remote.to_str().unwrap(),
        InitSource::Empty,
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
    let pin = vault_core::trust::load(&data).unwrap().expect("pin");
    assert_eq!(pin.version, 1);
    assert_eq!(pin.hash.len(), 64);
}

#[test]
fn t51_03_remote_with_files_but_no_store_json_is_refused() {
    // Caller classified a remote dir with files but no store.json.
    let dir = tmp("probe3");
    fs::write(dir.join("README.md"), "hello").unwrap();
    let state = vault_core::git::classify_init_source(&dir).unwrap_err();
    assert_eq!(state, vault_core::git::Error::RemoteHasFilesWithoutStore);
    // The mapper converts that refusal to the init error (T5.1-03).
    let mapped = vault_core::init::check_remote_source(Err(state)).unwrap_err();
    assert_eq!(mapped, vault_core::init::Error::RemoteHasFilesWithoutStore);
    assert_eq!(
        vault_core::init::check_remote_source(Ok(vault_core::git::InitSource::Empty)).unwrap(),
        vault_core::git::InitSource::Empty
    );
}

#[test]
fn t51_04_remote_with_store_switches_to_join_mode() {
    let remote = tmp("remote4");
    bare(&remote);
    // Seed the remote with a store via a first init.
    let seed_work = tmp("seed4");
    let seed_data = tmp("seeddata4");
    let backend = Libgit2Backend;
    let mut rng = FixedRng(0x4444);
    vault_core::init::init(
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
    // A second device sees HasStore and gets joinRequired.
    let work = tmp("work4");
    let data = tmp("data4");
    let mut rng2 = FixedRng(0x4445);
    let out = vault_core::init::init(
        &work,
        &data,
        remote.to_str().unwrap(),
        InitSource::HasStore,
        "second",
        &pw(),
        &mut rng2,
        &FastKdf,
        &backend,
        &author(),
        NOW,
        &mut |_| {},
    )
    .unwrap();
    assert_eq!(out, vault_core::init::Outcome::JoinRequired);
    // Nothing created for the joining device yet.
    assert!(!work.join("store.json").exists());
    assert!(!data.join("device.key").exists());
}

#[test]
fn t51_05_init_on_initialised_data_folder_is_refused() {
    let remote = tmp("remote5");
    bare(&remote);
    let work = tmp("work5");
    let data = tmp("data5");
    let backend = Libgit2Backend;
    let mut rng = FixedRng(0x5555);
    vault_core::init::init(
        &work,
        &data,
        remote.to_str().unwrap(),
        InitSource::Empty,
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
    let mut rng2 = FixedRng(0x5556);
    let err = vault_core::init::init(
        &work,
        &data,
        remote.to_str().unwrap(),
        InitSource::Empty,
        "laptop",
        &pw(),
        &mut rng2,
        &FastKdf,
        &backend,
        &author(),
        NOW,
        &mut |_| {},
    )
    .unwrap_err();
    assert_eq!(err, vault_core::init::Error::AlreadyInitialised);
}

#[test]
fn t51_06_network_failure_during_push_is_retried() {
    let remote = tmp("remote6");
    bare(&remote);
    let work = tmp("work6");
    let data = tmp("data6");
    let backend = FlakyPush {
        inner: Libgit2Backend,
        remaining: RefCell::new(10),
        attempts: RefCell::new(0),
    };
    let mut rng = FixedRng(0x6666);
    let mut backoffs = 0u32;
    let err = vault_core::init::init(
        &work,
        &data,
        remote.to_str().unwrap(),
        InitSource::Empty,
        "laptop",
        &pw(),
        &mut rng,
        &FastKdf,
        &backend,
        &author(),
        NOW,
        &mut |_| backoffs += 1,
    )
    .unwrap_err();
    assert_eq!(
        err,
        vault_core::init::Error::RemoteUnreachable { attempts: 3 }
    );
    assert_eq!(*backend.attempts.borrow(), 3);
    assert_eq!(backoffs, 2);
    // Success on attempt 2 stops retrying.
    let remote_b = tmp("remote6b");
    bare(&remote_b);
    let work_b = tmp("work6b");
    let data_b = tmp("data6b");
    let backend_b = FlakyPush {
        inner: Libgit2Backend,
        remaining: RefCell::new(1),
        attempts: RefCell::new(0),
    };
    let mut rng_b = FixedRng(0x6667);
    vault_core::init::init(
        &work_b,
        &data_b,
        remote_b.to_str().unwrap(),
        InitSource::Empty,
        "laptop",
        &pw(),
        &mut rng_b,
        &FastKdf,
        &backend_b,
        &author(),
        NOW,
        &mut |_| {},
    )
    .unwrap();
    assert_eq!(*backend_b.attempts.borrow(), 2);
}

#[test]
fn t51_07_first_commit_message_is_init() {
    let remote = tmp("remote7");
    bare(&remote);
    let work = tmp("work7");
    let data = tmp("data7");
    let backend = Libgit2Backend;
    let mut rng = FixedRng(0x7777);
    vault_core::init::init(
        &work,
        &data,
        remote.to_str().unwrap(),
        InitSource::Empty,
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
    let history = backend.history(&work).unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].message, "init");
    assert_eq!(history[0].author_name, "Argus Test");
}
