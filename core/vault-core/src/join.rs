//! Join request (spec 04 section 4.2).
//!
//! The caller has already cloned the remote: `work_dir` holds the store
//! checkout, including `store.json`. Join reads the store id, generates
//! keypairs into `device.key`, writes `pending-<device-id>.json` signed with
//! the `argus-join-v1` prefix, commits once as `update`, pushes with the
//! core retry policy (T3.4), and records `join_state.json`.
//!
//! The device decrypts nothing and pins no trust until verify (T5.4).

use crate::canonical_json::canonicalize;
use crate::device_key::Kdf;
use crate::encodings::{b64u_decode, b64u_encode};
use crate::git::{self, Author, Backend};
use crate::net_retry::{self, Attempt};
use crate::secrets::MasterPassword;
use crate::signatures::{self, Domain, Signature, SigningKey, VerifyingKey};
use std::fmt;
use std::path::Path;

/// What `join` decided (spec 04 section 4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The pending request was committed as `update` and pushed.
    Requested { store_id: String, device_id: String },
}

/// Join failure. Static reasons only: never secrets or key text.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    AlreadyInitialised,
    NotAStore,
    StoreIdMismatch,
    Invalid(&'static str),
    BadSignature,
    RemoteUnreachable { attempts: u32 },
    RemoteRejected,
    DeviceKey(crate::device_key::Error),
    Store(crate::store::Error),
    Git(&'static str),
    Io(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::AlreadyInitialised => write!(f, "already initialised"),
            Error::NotAStore => write!(f, "not a store"),
            Error::StoreIdMismatch => write!(f, "store id mismatch"),
            Error::Invalid(reason) => write!(f, "invalid join: {reason}"),
            Error::BadSignature => write!(f, "bad join signature"),
            Error::RemoteUnreachable { attempts } => {
                write!(f, "remote unreachable after {attempts} attempts")
            }
            Error::RemoteRejected => write!(f, "remote rejected the request"),
            Error::DeviceKey(_) => write!(f, "device key failed"),
            Error::Store(_) => write!(f, "store failed"),
            Error::Git(reason) => write!(f, "git failed: {reason}"),
            Error::Io(reason) => write!(f, "join io error: {reason}"),
        }
    }
}

impl std::error::Error for Error {}

/// Request to join the store checked out at `work_dir` (spec 04 section 4.2).
///
/// `now` is an RFC 3339 timestamp (injected so tests never sleep).
/// `on_backoff` records each retryable push failure (production sleeps).
/// Re-running with the same `data_dir` and password replaces the pending
/// file for the same device instead of duplicating it (T5.2-06).
#[allow(clippy::too_many_arguments)]
pub fn join(
    work_dir: &Path,
    data_dir: &Path,
    device_name: &str,
    password: &MasterPassword,
    rng: &mut impl rand::CryptoRng,
    kdf: &impl Kdf,
    backend: &impl Backend,
    author: &Author,
    now: &str,
    on_backoff: &mut impl FnMut(u32),
) -> Result<Outcome, Error> {
    if data_dir.join("trust.json").exists() {
        return Err(Error::AlreadyInitialised);
    }
    let store = crate::store::open(work_dir).map_err(|e| match e {
        crate::store::Error::NotAStore => Error::NotAStore,
        crate::store::Error::FormatUnsupported(_) => Error::Invalid("format"),
        crate::store::Error::Invalid(r) => Error::Invalid(r),
        e => Error::Store(e),
    })?;
    if device_name.is_empty() || device_name.chars().any(|c| c.is_control()) {
        return Err(Error::Invalid("name"));
    }
    if now.is_empty() {
        return Err(Error::Invalid("created"));
    }

    // Re-run support (T5.2-06): an existing device.key is reopened so the
    // same device id — and the same pending file name — is reused.
    let key_path = data_dir.join("device.key");
    if !key_path.exists() {
        let key_bytes =
            crate::device_key::create(password, &mut *rng, kdf).map_err(Error::DeviceKey)?;
        crate::data_dir::ensure_dir(data_dir)
            .map_err(|_| Error::DeviceKey(crate::device_key::Error::Io("data dir")))?;
        crate::data_dir::write_file(&key_path, &key_bytes)
            .map_err(|_| Error::DeviceKey(crate::device_key::Error::Io("write device.key")))?;
    }
    let key_bytes = std::fs::read(&key_path).map_err(|_| Error::Io("read device.key"))?;
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

    let unsigned = serde_json::json!({
        "v": 1,
        "storeId": store.store_id,
        "device": {
            "id": device_id,
            "name": device_name,
            "enc": enc_str,
            "sign": sign_b64u,
        },
        "created": now,
    });
    let unsigned_canonical =
        canonicalize(&serde_json::to_string(&unsigned).map_err(|_| Error::Invalid("pending"))?)
            .map_err(|_| Error::Invalid("pending"))?;
    let sig = signatures::sign(&signing, Domain::Join, unsigned_canonical.as_bytes());
    let mut with_sig = unsigned;
    with_sig
        .as_object_mut()
        .ok_or(Error::Invalid("pending"))?
        .insert(
            "sig".to_string(),
            serde_json::Value::String(b64u_encode(&sig.to_bytes())),
        );
    let pending_canonical =
        canonicalize(&serde_json::to_string(&with_sig).map_err(|_| Error::Invalid("pending"))?)
            .map_err(|_| Error::Invalid("pending"))?;
    let pending_name = format!("pending-{device_id}.json");
    // Replace any stale pending file for this device; never duplicate.
    for stale in stale_pending_files(work_dir, &device_id) {
        if stale != pending_name {
            let _ = std::fs::remove_file(work_dir.join(&stale));
        }
    }
    std::fs::write(work_dir.join(&pending_name), pending_canonical.as_bytes())
        .map_err(|_| Error::Io("write pending"))?;

    let commit_result = backend.commit(work_dir, author, "update");
    match commit_result {
        Ok(_) => {
            push_with_retry(work_dir, backend, on_backoff)?;
        }
        // Identical re-run: the pending bytes are unchanged, so there is
        // nothing to commit. The request is already on the remote (or will
        // be pushed below with the state rewrite); just record the state.
        Err(git::Error::EmptyCommit) => {}
        Err(_) => return Err(Error::Git("commit failed")),
    }

    let state = serde_json::json!({
        "v": 1,
        "storeId": store.store_id,
        "deviceId": device_id,
        "pending": pending_name,
        "created": now,
    });
    let state_canonical =
        canonicalize(&serde_json::to_string(&state).map_err(|_| Error::Invalid("join state"))?)
            .map_err(|_| Error::Invalid("join state"))?;
    std::fs::write(data_dir.join("join_state.json"), state_canonical.as_bytes())
        .map_err(|_| Error::Io("write join_state"))?;

    Ok(Outcome::Requested {
        store_id: store.store_id,
        device_id,
    })
}

/// Verify a pending request's self-signature (spec 04 section 4.2).
///
/// Returns the device id when the `argus-join-v1` signature over the
/// canonical bytes without `sig` verifies with the device's own key.
pub fn verify_pending(bytes: &[u8], expected_store_id: &str) -> Result<String, Error> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| Error::Invalid("pending"))?;
    let obj = value.as_object().ok_or(Error::Invalid("pending"))?;
    if obj.get("v") != Some(&serde_json::json!(1)) {
        return Err(Error::Invalid("pending"));
    }
    let store_id = obj
        .get("storeId")
        .and_then(|v| v.as_str())
        .ok_or(Error::Invalid("pending"))?;
    if store_id != expected_store_id {
        return Err(Error::StoreIdMismatch);
    }
    let device = obj
        .get("device")
        .and_then(|v| v.as_object())
        .ok_or(Error::Invalid("pending"))?;
    let device_id = device
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or(Error::Invalid("pending"))?;
    let sign_b64u = device
        .get("sign")
        .and_then(|v| v.as_str())
        .ok_or(Error::Invalid("pending"))?;
    let sig_b64u = obj
        .get("sig")
        .and_then(|v| v.as_str())
        .ok_or(Error::Invalid("pending"))?;
    let mut unsigned = value.clone();
    unsigned
        .as_object_mut()
        .ok_or(Error::Invalid("pending"))?
        .remove("sig");
    let unsigned_canonical =
        canonicalize(&serde_json::to_string(&unsigned).map_err(|_| Error::Invalid("pending"))?)
            .map_err(|_| Error::Invalid("pending"))?;
    let sign_raw = b64u_decode(sign_b64u).map_err(|_| Error::Invalid("sign"))?;
    let sign_bytes: [u8; 32] = sign_raw.try_into().map_err(|_| Error::Invalid("sign"))?;
    let verifying = VerifyingKey::from_bytes(&sign_bytes).map_err(|_| Error::Invalid("sign"))?;
    let sig_raw = b64u_decode(sig_b64u).map_err(|_| Error::BadSignature)?;
    let sig_bytes: [u8; 64] = sig_raw.try_into().map_err(|_| Error::BadSignature)?;
    signatures::verify(
        &verifying,
        Domain::Join,
        unsigned_canonical.as_bytes(),
        &Signature::from_bytes(&sig_bytes),
    )
    .map_err(|_| Error::BadSignature)?;
    Ok(device_id.to_string())
}

fn stale_pending_files(work_dir: &Path, device_id: &str) -> Vec<String> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(work_dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(rest) = name
            .strip_prefix("pending-")
            .and_then(|s| s.strip_suffix(".json"))
        else {
            continue;
        };
        if rest == device_id {
            out.push(name);
        }
    }
    out
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
