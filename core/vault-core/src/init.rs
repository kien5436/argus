//! First-device init (spec 04 sections 4.1, 4.2).
//!
//! Creates a new store on an empty remote: store layout, device list
//! version 1 plus `devices.sig`, `device.key`, and the trust pin. Commits
//! once as `init`, adds the remote, and pushes with the core retry policy
//! (T3.4: up to 3 attempts, then `RemoteUnreachable`).
//!
//! When the remote already holds a store the caller passes
//! [`InitSource::HasStore`] and gets [`Outcome::JoinRequired`]: nothing is
//! created, and the caller continues with the join flow (T5.2). A remote
//! with files but no `store.json` never reaches this module: the caller
//! maps [`git::Error::RemoteHasFilesWithoutStore`] through
//! [`check_remote_source`], which converts it to [`Error`].

use crate::device_key::Kdf;
use crate::device_list::{DeviceEntry, DeviceList};
use crate::encodings::{b64u_encode, generate_id};
use crate::git::{self, Author, Backend, InitSource};
use crate::net_retry::{self, Attempt};
use crate::secrets::MasterPassword;
use crate::signatures::SigningKey;
use std::fmt;
use std::path::Path;

/// What `init` decided (spec 04 sections 4.1, 4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// A new store was created, committed as `init`, and pushed.
    Created { store_id: String, device_id: String },
    /// The remote already holds a store: continue with join mode (T5.2).
    JoinRequired,
}

/// Init failure. Static reasons only: never secrets or key text.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    AlreadyInitialised,
    RemoteHasFilesWithoutStore,
    Invalid(&'static str),
    RemoteUnreachable { attempts: u32 },
    RemoteRejected,
    DeviceKey(crate::device_key::Error),
    Store(crate::store::Error),
    DeviceList(crate::device_list::Error),
    Trust(crate::trust::Error),
    Git(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::AlreadyInitialised => write!(f, "already initialised"),
            Error::RemoteHasFilesWithoutStore => write!(f, "remote has files but no store.json"),
            Error::Invalid(reason) => write!(f, "invalid init: {reason}"),
            Error::RemoteUnreachable { attempts } => {
                write!(f, "remote unreachable after {attempts} attempts")
            }
            Error::RemoteRejected => write!(f, "remote rejected the request"),
            Error::DeviceKey(_) => write!(f, "device key failed"),
            Error::Store(_) => write!(f, "store failed"),
            Error::DeviceList(_) => write!(f, "device list failed"),
            Error::Trust(_) => write!(f, "trust pin failed"),
            Error::Git(reason) => write!(f, "git failed: {reason}"),
        }
    }
}

impl std::error::Error for Error {}

/// Map the remote classification (or its failure) to the init error type.
///
/// A remote with files but no `store.json` is refused (T5.1-03); empty and
/// store remotes pass through for [`init`].
pub fn check_remote_source(source: Result<InitSource, git::Error>) -> Result<InitSource, Error> {
    source.map_err(|e| match e {
        git::Error::RemoteHasFilesWithoutStore => Error::RemoteHasFilesWithoutStore,
        git::Error::Rejected => Error::RemoteRejected,
        git::Error::Shallow => Error::Invalid("shallow"),
        _ => Error::Git("remote check failed"),
    })
}

/// Create a new store on an empty remote (spec 04 section 4.1).
///
/// `remote_state` is the caller-classified remote: `Empty` creates the
/// store, `HasStore` returns [`Outcome::JoinRequired`] without touching
/// disk. `now` is an RFC 3339 timestamp (injected so tests never sleep).
/// `on_backoff` records each retryable push failure (production sleeps).
#[allow(clippy::too_many_arguments)]
pub fn init(
    work_dir: &Path,
    data_dir: &Path,
    remote_url: &str,
    remote_state: InitSource,
    device_name: &str,
    password: &MasterPassword,
    rng: &mut impl rand::CryptoRng,
    kdf: &impl Kdf,
    backend: &impl Backend,
    author: &Author,
    now: &str,
    on_backoff: &mut impl FnMut(u32),
) -> Result<Outcome, Error> {
    if data_dir.join("device.key").exists()
        || data_dir.join("trust.json").exists()
        || work_dir.join("store.json").exists()
    {
        return Err(Error::AlreadyInitialised);
    }
    match remote_state {
        InitSource::HasStore => return Ok(Outcome::JoinRequired),
        InitSource::Empty => {}
    }
    if device_name.is_empty() || device_name.chars().any(|c| c.is_control()) {
        return Err(Error::Invalid("name"));
    }
    if now.is_empty() {
        return Err(Error::Invalid("created"));
    }

    let store_id = generate_id(&mut *rng);
    let key_bytes =
        crate::device_key::create(password, &mut *rng, kdf).map_err(Error::DeviceKey)?;
    let opened = crate::device_key::open(&key_bytes, password, kdf).map_err(Error::DeviceKey)?;
    let device_id = opened.device_id.clone();
    let sign_seed: [u8; 32] = opened
        .sign_seed
        .expose()
        .try_into()
        .map_err(|_| Error::DeviceKey(crate::device_key::Error::Corrupt("seed")))?;
    let signing = SigningKey::from_seed(sign_seed);
    let sign_b64u = b64u_encode(&signing.verifying_key().to_bytes());
    let enc_str = encode_recipient(&opened.enc_public);

    let list = DeviceList {
        store_id: store_id.clone(),
        version: 1,
        prev: String::new(),
        updated: now.to_string(),
        devices: vec![DeviceEntry {
            id: device_id.clone(),
            name: device_name.to_string(),
            enc: enc_str,
            sign: sign_b64u,
            git_key: None,
            added: now.to_string(),
            added_by: device_id.clone(),
        }],
    };
    let list_bytes = list.canonical_json().map_err(Error::DeviceList)?;
    let hash = list.hash_hex().map_err(Error::DeviceList)?;
    let sig = list.sign(&device_id, &signing).map_err(Error::DeviceList)?;
    let sig_bytes = sig.to_canonical_json().map_err(Error::DeviceList)?;

    // Write the working tree, then the data folder, then commit and push.
    std::fs::create_dir_all(work_dir)
        .map_err(|_| Error::Store(crate::store::Error::Io("mkdir")))?;
    crate::store::init(work_dir, &store_id, now).map_err(Error::Store)?;
    std::fs::write(work_dir.join("devices.json"), list_bytes.as_bytes())
        .map_err(|_| Error::Store(crate::store::Error::Io("write devices")))?;
    std::fs::write(work_dir.join("devices.sig"), sig_bytes.as_bytes())
        .map_err(|_| Error::Store(crate::store::Error::Io("write devices.sig")))?;
    crate::data_dir::ensure_dir(data_dir)
        .map_err(|_| Error::DeviceKey(crate::device_key::Error::Io("data dir")))?;
    crate::data_dir::write_file(&data_dir.join("device.key"), &key_bytes)
        .map_err(|_| Error::DeviceKey(crate::device_key::Error::Io("write device.key")))?;
    crate::trust::check_and_pin(data_dir, &store_id, 1, &hash).map_err(Error::Trust)?;

    backend
        .init(work_dir)
        .map_err(|_| Error::Git("init failed"))?;
    // Roll back the trust pin when git fails so a retry starts clean.
    let commit_result = (|| {
        backend
            .add_remote(work_dir, "origin", remote_url)
            .map_err(|_| Error::Git("add remote failed"))?;
        backend
            .commit(work_dir, author, "init")
            .map_err(|_| Error::Git("commit failed"))?;
        push_with_retry(work_dir, backend, on_backoff)?;
        Ok(())
    })();
    if commit_result.is_err() {
        let _ = std::fs::remove_file(data_dir.join("trust.json"));
    }
    commit_result?;

    Ok(Outcome::Created {
        store_id,
        device_id,
    })
}

fn push_with_retry(
    work_dir: &Path,
    backend: &impl Backend,
    on_backoff: &mut impl FnMut(u32),
) -> Result<(), Error> {
    net_retry::retry(
        || match backend.push(work_dir, "origin") {
            Ok(()) => Ok(()),
            Err(git::Error::Rejected) => Err(Attempt::Rejected),
            Err(_) => Err(Attempt::Unreachable),
        },
        on_backoff,
    )
    .map_err(|e| match e {
        net_retry::Error::RemoteUnreachable { attempts } => Error::RemoteUnreachable { attempts },
        net_retry::Error::RemoteRejected => Error::RemoteRejected,
    })
}

/// Encode 32 raw X25519 bytes as an `argus1...` bech32m recipient.
fn encode_recipient(bytes: &[u8; 32]) -> String {
    use bech32::Hrp;
    let hrp = Hrp::parse("argus").expect("argus is a valid HRP");
    bech32::encode::<bech32::Bech32m>(hrp, bytes).expect("32 bytes always encode")
}
