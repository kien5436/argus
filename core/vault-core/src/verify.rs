//! Verify the anchor (spec 04 section 4.4).
//!
//! The new device pulls, finds `devices.json` at the anchor's version in
//! history, verifies the chain back to version 1, checks its own entry
//! carries its keys, pins the newest verified version, trial-decrypts the
//! entries and deletes `join_state.json`. A mismatching anchor fails with
//! `VerificationFailed`; the keys are kept.

use crate::device_key::Kdf;
use crate::encodings::b64u_encode;
use crate::git::{self, Backend};
use crate::identity::parse_anchor;
use crate::net_retry::{self, Attempt};
use crate::secrets::MasterPassword;
use crate::signatures::SigningKey;
use std::fmt;
use std::path::Path;

/// What `verify` pinned (spec 04 section 4.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub version: u64,
    pub hash: String,
}

/// Verify failure. Static reasons only: never secrets or key text.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    NoPendingJoin,
    StoreIdMismatch,
    Invalid(&'static str),
    VerificationFailed(&'static str),
    RemoteUnreachable { attempts: u32 },
    RemoteRejected,
    DeviceKey(crate::device_key::Error),
    Trust(crate::trust::Error),
    Git(&'static str),
    Io(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NoPendingJoin => write!(f, "no pending join request"),
            Error::StoreIdMismatch => write!(f, "store id mismatch"),
            Error::Invalid(r) => write!(f, "invalid verify: {r}"),
            Error::VerificationFailed(r) => write!(f, "VerificationFailed({r})"),
            Error::RemoteUnreachable { attempts } => {
                write!(f, "remote unreachable after {attempts} attempts")
            }
            Error::RemoteRejected => write!(f, "remote rejected the request"),
            Error::DeviceKey(_) => write!(f, "device key failed"),
            Error::Trust(_) => write!(f, "trust pin failed"),
            Error::Git(r) => write!(f, "git failed: {r}"),
            Error::Io(r) => write!(f, "verify io error: {r}"),
        }
    }
}

impl std::error::Error for Error {}

/// Verify the anchor typed or scanned by the user (spec 04 section 4.4).
///
/// `password` and `kdf` open this device's `device.key`; the keys check the
/// device's own list entry and trial-decrypt every entry. `on_backoff`
/// records each retryable fetch failure (production sleeps).
pub fn verify(
    work_dir: &Path,
    data_dir: &Path,
    password: &MasterPassword,
    kdf: &impl Kdf,
    backend: &impl Backend,
    anchor_text: &str,
    on_backoff: &mut impl FnMut(u32),
) -> Result<Outcome, Error> {
    let state_raw =
        std::fs::read(data_dir.join("join_state.json")).map_err(|_| Error::NoPendingJoin)?;
    let state: serde_json::Value =
        serde_json::from_slice(&state_raw).map_err(|_| Error::NoPendingJoin)?;
    let (Some(state_store), Some(device_id)) = (
        state.get("storeId").and_then(|v| v.as_str()),
        state.get("deviceId").and_then(|v| v.as_str()),
    ) else {
        return Err(Error::NoPendingJoin);
    };
    let store = crate::store::open(work_dir).map_err(|_| Error::Invalid("store"))?;
    if state_store != store.store_id {
        return Err(Error::StoreIdMismatch);
    }
    let anchor = parse_anchor(anchor_text).map_err(|_| Error::Invalid("anchor"))?;
    git::check_not_shallow(work_dir).map_err(|_| Error::VerificationFailed("shallow"))?;

    // Pull: fetch, then fast-forward the checkout to the fetched tip.
    net_retry::retry(
        || match backend.fetch(work_dir, "origin") {
            Ok(()) => Ok(()),
            Err(git::Error::Rejected) => Err(Attempt::Rejected),
            Err(_) => Err(Attempt::Unreachable),
        },
        on_backoff,
    )
    .map_err(|e| match e {
        net_retry::Error::RemoteUnreachable { attempts } => Error::RemoteUnreachable { attempts },
        net_retry::Error::RemoteRejected => Error::RemoteRejected,
    })?;
    backend
        .fast_forward(work_dir, "FETCH_HEAD")
        .map_err(|_| Error::Git("fast-forward failed"))?;

    // Collect the device-list history, newest first, skipping commits that
    // did not change the list (join and entry commits).
    let history = backend
        .history(work_dir)
        .map_err(|_| Error::Git("history failed"))?;
    let mut pairs: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    for c in &history {
        let list = match backend.file_at(work_dir, &c.id, "devices.json") {
            Ok(b) => b,
            Err(_) => break,
        };
        let sig = match backend.file_at(work_dir, &c.id, "devices.sig") {
            Ok(b) => b,
            Err(_) => break,
        };
        if pairs.last().is_some_and(|(prev, _)| *prev == list) {
            continue;
        }
        pairs.push((list, sig));
    }
    pairs.reverse();
    let mut chain = Vec::with_capacity(pairs.len());
    for (list, sig) in &pairs {
        let list_bytes = String::from_utf8(list.clone())
            .map_err(|_| Error::VerificationFailed("notCanonical"))?;
        let sig_bytes = String::from_utf8(sig.clone())
            .map_err(|_| Error::VerificationFailed("notCanonical"))?;
        chain.push(crate::device_list::ChainEntry {
            list_bytes,
            sig_bytes,
        });
    }
    let (newest_version, newest_hash) =
        crate::device_list::verify_chain(&chain, &store.store_id, false).map_err(|e| match e {
            crate::device_list::Error::Invalid(r) => Error::VerificationFailed(r),
            crate::device_list::Error::BadSignature => Error::VerificationFailed("badSignature"),
        })?;

    // The anchor names a version in history; its file hash must start with
    // the anchor bytes.
    let anchored = chain
        .iter()
        .find(|e| {
            serde_json::from_str::<serde_json::Value>(&e.list_bytes)
                .ok()
                .and_then(|v| v.get("version")?.as_u64())
                == Some(anchor.version)
        })
        .ok_or(Error::VerificationFailed("anchorVersion"))?;
    let digest = sha2::Sha256::digest(anchored.list_bytes.as_bytes());
    use sha2::Digest;
    if digest[..16] != anchor.prefix {
        return Err(Error::VerificationFailed("anchor"));
    }

    // This device's entry must carry its own keys.
    let key_bytes =
        std::fs::read(data_dir.join("device.key")).map_err(|_| Error::Io("read device.key"))?;
    let opened = crate::device_key::open(&key_bytes, password, kdf).map_err(Error::DeviceKey)?;
    let seed: [u8; 32] = opened
        .sign_seed
        .expose()
        .try_into()
        .map_err(|_| Error::DeviceKey(crate::device_key::Error::Corrupt("seed")))?;
    let own_sign = b64u_encode(&SigningKey::from_seed(seed).verifying_key().to_bytes());
    let own_enc = encode_recipient(&opened.enc_public);
    let newest: crate::device_list::DeviceList =
        crate::device_list::parse_device_list(&chain.last().expect("chain nonempty").list_bytes)
            .map_err(|_| Error::VerificationFailed("schema"))?;
    let mine = newest
        .devices
        .iter()
        .find(|d| d.id == device_id)
        .ok_or(Error::VerificationFailed("member"))?;
    if mine.enc != own_enc || mine.sign != own_sign {
        return Err(Error::VerificationFailed("member"));
    }

    // Trial-decrypt every entry: after approval each one must open.
    let secret: [u8; 32] = opened
        .enc_secret
        .expose()
        .try_into()
        .map_err(|_| Error::DeviceKey(crate::device_key::Error::Corrupt("enc")))?;
    let mut arg_files: Vec<String> = Vec::new();
    for e in std::fs::read_dir(work_dir)
        .map_err(|_| Error::Io("read dir"))?
        .flatten()
    {
        let n = e.file_name().to_string_lossy().into_owned();
        if n.ends_with(".arg") {
            arg_files.push(n);
        }
    }
    for n in &arg_files {
        let bytes = std::fs::read(work_dir.join(n)).map_err(|_| Error::Io("read entry"))?;
        crate::envelope::decrypt(&bytes, &opened.enc_public, &secret)
            .map_err(|_| Error::VerificationFailed("entry"))?;
    }

    crate::trust::check_and_pin(data_dir, &store.store_id, newest_version, &newest_hash)
        .map_err(Error::Trust)?;
    std::fs::remove_file(data_dir.join("join_state.json"))
        .map_err(|_| Error::Io("remove join state"))?;
    Ok(Outcome {
        version: newest_version,
        hash: newest_hash,
    })
}

/// Encode 32 raw X25519 bytes as an `argus1...` bech32m recipient.
fn encode_recipient(bytes: &[u8; 32]) -> String {
    use bech32::Hrp;
    let hrp = Hrp::parse("argus").expect("argus is a valid HRP");
    bech32::encode::<bech32::Bech32m>(hrp, bytes).expect("32 bytes always encode")
}
