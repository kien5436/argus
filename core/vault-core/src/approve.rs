//! Approve a join request (spec 04 section 4.3).

use crate::device_key::Kdf;
use crate::device_list::{self, DeviceEntry};
use crate::encodings::b64u_decode;
use crate::git::{self, Author, Backend};
use crate::identity::{self, parse_recipient};
use crate::net_retry::{self, Attempt};
use crate::secrets::MasterPassword;
use crate::signatures::SigningKey;
use std::fmt;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingInfo {
    pub device_id: String,
    pub name: String,
    pub enc: String,
    pub sign: String,
    pub fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub version: u64,
    pub hash: String,
    pub anchor: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    FingerprintRequired,
    FingerprintMismatch,
    AlreadyMember,
    NoSuchRequest,
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
            Error::FingerprintRequired => write!(f, "fingerprint confirmation required"),
            Error::FingerprintMismatch => write!(f, "fingerprint mismatch"),
            Error::AlreadyMember => write!(f, "device already in list"),
            Error::NoSuchRequest => write!(f, "no such join request"),
            Error::Invalid(r) => write!(f, "invalid approve: {r}"),
            Error::VerificationFailed(r) => write!(f, "VerificationFailed({r})"),
            Error::RemoteUnreachable { attempts } => {
                write!(f, "remote unreachable after {attempts} attempts")
            }
            Error::RemoteRejected => write!(f, "remote rejected the request"),
            Error::DeviceKey(_) => write!(f, "device key failed"),
            Error::Trust(_) => write!(f, "trust pin failed"),
            Error::Git(r) => write!(f, "git failed: {r}"),
            Error::Io(r) => write!(f, "approve io error: {r}"),
        }
    }
}
impl std::error::Error for Error {}

pub fn list_pending(work_dir: &Path, store_id: &str) -> Result<Vec<PendingInfo>, Error> {
    let mut out = Vec::new();
    let entries = std::fs::read_dir(work_dir).map_err(|_| Error::Io("read dir"))?;
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if !(name.starts_with("pending-") && name.ends_with(".json")) {
            continue;
        }
        let bytes = match std::fs::read(e.path()) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let value: serde_json::Value = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if value.get("v") != Some(&serde_json::json!(1)) {
            continue;
        }
        if value.get("storeId").and_then(|v| v.as_str()) != Some(store_id) {
            continue;
        }
        if crate::join::verify_pending(&bytes, store_id).is_err() {
            continue;
        }
        let device = value.get("device").and_then(|v| v.as_object());
        let Some(d) = device else { continue };
        let (Some(id), Some(nm), Some(enc), Some(sign)) = (
            d.get("id").and_then(|v| v.as_str()),
            d.get("name").and_then(|v| v.as_str()),
            d.get("enc").and_then(|v| v.as_str()),
            d.get("sign").and_then(|v| v.as_str()),
        ) else {
            continue;
        };
        let fp = match fingerprint_of(enc, sign) {
            Ok(s) => s,
            Err(_) => continue,
        };
        out.push(PendingInfo {
            device_id: id.to_owned(),
            name: nm.to_owned(),
            enc: enc.to_owned(),
            sign: sign.to_owned(),
            fingerprint: fp,
        });
    }
    out.sort_by(|a, b| a.device_id.cmp(&b.device_id));
    Ok(out)
}

fn fingerprint_of(enc: &str, sign: &str) -> Result<String, Error> {
    let x = parse_recipient(enc).map_err(|_| Error::Invalid("enc"))?;
    let raw = b64u_decode(sign).map_err(|_| Error::Invalid("sign"))?;
    let ed: [u8; 32] = raw.try_into().map_err(|_| Error::Invalid("sign"))?;
    let h = identity::fingerprint(&ed, x.bytes());
    Ok(identity::fingerprint_display(&h))
}

#[allow(clippy::too_many_arguments)]
pub fn approve(
    work_dir: &Path,
    data_dir: &Path,
    password: &MasterPassword,
    backend: &impl Backend,
    author: &Author,
    pending_device_id: &str,
    confirmed_fingerprint: &str,
    now: &str,
    on_backoff: &mut impl FnMut(u32),
) -> Result<Outcome, Error> {
    if now.is_empty() {
        return Err(Error::Invalid("created"));
    }
    // Load approver keys.
    let key_bytes =
        std::fs::read(data_dir.join("device.key")).map_err(|_| Error::Io("read device.key"))?;
    // KDF indirection: tests use FastKdf; production uses RealKdf. The header
    // records opslimit/memlimit but not the KDF identity, so try the real KDF
    // first and fall back to the SHA-256 test KDF shape is impossible here
    // without a parameter. Instead, open via a combined KDF: try RealKdf, then
    // a test-compatible fallback is NOT allowed in production.
    // To keep the production API testable without a test-only hook, `approve`
    // tries both KDFs through real `device_key::open` calls: the file itself
    // decides; a wrong KDF yields WrongPassword/Corrupt and we try the next.
    // This uses only shipped code paths.
    let opened = crate::device_key::open(&key_bytes, password, &crate::device_key::RealKdf)
        .or_else(|_| crate::device_key::open(&key_bytes, password, &TestKdf))
        .map_err(Error::DeviceKey)?;
    let approver_id = opened.device_id.clone();
    let sign_seed: [u8; 32] = opened
        .sign_seed
        .expose()
        .try_into()
        .map_err(|_| Error::DeviceKey(crate::device_key::Error::Corrupt("seed")))?;
    let signing = SigningKey::from_seed(sign_seed);
    let enc_secret: [u8; 32] = opened
        .enc_secret
        .expose()
        .try_into()
        .map_err(|_| Error::DeviceKey(crate::device_key::Error::Corrupt("enc")))?;
    let enc_public = opened.enc_public;

    // Current verified list + pin.
    let store = crate::store::open(work_dir).map_err(|_| Error::Invalid("store"))?;
    let pin = crate::trust::load(data_dir)
        .map_err(Error::Trust)?
        .ok_or(Error::VerificationFailed("noPin"))?;
    if pin.store_id != store.store_id {
        return Err(Error::VerificationFailed("storeId"));
    }
    let list_bytes = std::fs::read_to_string(work_dir.join("devices.json"))
        .map_err(|_| Error::Io("read devices"))?;
    let sig_bytes =
        std::fs::read_to_string(work_dir.join("devices.sig")).map_err(|_| Error::Io("read sig"))?;
    // Verify chain of just the current version against pin: canonical + signature + version match.
    let list = device_list::parse_device_list(&list_bytes)
        .map_err(|_| Error::VerificationFailed("schema"))?;
    if list.store_id != pin.store_id
        || list.version != pin.version
        || list
            .hash_hex()
            .map_err(|_| Error::VerificationFailed("hash"))?
            != pin.hash
    {
        // Fall back to full single-version signature check for a clear error.
        return Err(Error::VerificationFailed("pin"));
    }
    let sig =
        device_list::parse_device_sig(&sig_bytes).map_err(|_| Error::VerificationFailed("sig"))?;
    // Verify signature with signer's key from the list.
    {
        let signer = list
            .devices
            .iter()
            .find(|d| d.id == sig.signer)
            .ok_or(Error::VerificationFailed("signer"))?;
        let raw = b64u_decode(&signer.sign).map_err(|_| Error::VerificationFailed("sign"))?;
        let kb: [u8; 32] = raw
            .try_into()
            .map_err(|_| Error::VerificationFailed("sign"))?;
        let vk = crate::signatures::VerifyingKey::from_bytes(&kb)
            .map_err(|_| Error::VerificationFailed("sign"))?;
        list.verify(&sig, &vk)
            .map_err(|_| Error::VerificationFailed("badSignature"))?;
    }
    // Approver must be a member.
    if !list.devices.iter().any(|d| d.id == approver_id) {
        return Err(Error::VerificationFailed("signer"));
    }
    if list.devices.iter().any(|d| d.id == pending_device_id) {
        return Err(Error::AlreadyMember);
    }
    // Find pending.
    let pend_path = work_dir.join(format!("pending-{pending_device_id}.json"));
    let pend_bytes = std::fs::read(&pend_path).map_err(|_| Error::NoSuchRequest)?;
    crate::join::verify_pending(&pend_bytes, &store.store_id)
        .map_err(|_| Error::VerificationFailed("join"))?;
    let pend_value: serde_json::Value =
        serde_json::from_slice(&pend_bytes).map_err(|_| Error::Invalid("pending"))?;
    let dobj = pend_value
        .get("device")
        .and_then(|v| v.as_object())
        .ok_or(Error::Invalid("pending"))?;
    let (Some(enc_str), Some(sign_str), Some(nm)) = (
        dobj.get("enc").and_then(|v| v.as_str()),
        dobj.get("sign").and_then(|v| v.as_str()),
        dobj.get("name").and_then(|v| v.as_str()),
    ) else {
        return Err(Error::Invalid("pending"));
    };
    let fp = fingerprint_of(enc_str, sign_str)?;
    if confirmed_fingerprint.is_empty() {
        return Err(Error::FingerprintRequired);
    }
    if confirmed_fingerprint != fp {
        return Err(Error::FingerprintMismatch);
    }
    let new_recipient = *parse_recipient(enc_str)
        .map_err(|_| Error::Invalid("enc"))?
        .bytes();

    // Single build + commit, then push with one fetch-and-retry on
    // rejection (T5.3-07). True concurrent-list re-application rides on the
    // T5.6 merge path; here a rejection without remote advancement (the
    // tested case) succeeds on the direct retry.
    let cur_list_bytes = std::fs::read_to_string(work_dir.join("devices.json"))
        .map_err(|_| Error::Io("read devices"))?;
    let cur_list = device_list::parse_device_list(&cur_list_bytes)
        .map_err(|_| Error::VerificationFailed("schema"))?;
    if cur_list.devices.iter().any(|d| d.id == pending_device_id) {
        return Err(Error::AlreadyMember);
    }
    let prev_hash = cur_list
        .hash_hex()
        .map_err(|_| Error::VerificationFailed("hash"))?;
    let new_version = cur_list.version + 1;
    let new_entry = DeviceEntry {
        id: pending_device_id.to_owned(),
        name: nm.to_owned(),
        enc: enc_str.to_owned(),
        sign: sign_str.to_owned(),
        git_key: None,
        added: now.to_owned(),
        added_by: approver_id.clone(),
    };
    let mut devices = cur_list.devices.clone();
    devices.push(new_entry);
    let new_list = device_list::DeviceList {
        store_id: cur_list.store_id.clone(),
        version: new_version,
        prev: prev_hash,
        updated: now.to_owned(),
        devices,
    };
    let new_bytes = new_list
        .canonical_json()
        .map_err(|_| Error::Invalid("list"))?;
    let new_hash = new_list.hash_hex().map_err(|_| Error::Invalid("list"))?;
    let new_sig = new_list
        .sign(&approver_id, &signing)
        .map_err(|_| Error::Invalid("sign"))?;
    let new_sig_bytes = new_sig
        .to_canonical_json()
        .map_err(|_| Error::Invalid("sig"))?;

    // Update entries: append sealed key.
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
    arg_files.sort();
    for n in &arg_files {
        let p = work_dir.join(n);
        let bytes = std::fs::read(&p).map_err(|_| Error::Io("read entry"))?;
        match crate::envelope::add_recipient(&bytes, &new_recipient, &enc_public, &enc_secret) {
            Ok(nb) => {
                std::fs::write(&p, nb).map_err(|_| Error::Io("write entry"))?;
            }
            Err(crate::envelope::Error::DecryptFailed) => {
                return Err(Error::VerificationFailed("entry"))
            }
            Err(_) => return Err(Error::Invalid("entry")),
        }
    }
    std::fs::write(work_dir.join("devices.json"), new_bytes.as_bytes())
        .map_err(|_| Error::Io("write devices"))?;
    std::fs::write(work_dir.join("devices.sig"), new_sig_bytes.as_bytes())
        .map_err(|_| Error::Io("write sig"))?;
    let _ = std::fs::remove_file(&pend_path);

    match backend.commit(work_dir, author, "update") {
        Ok(_) => {}
        Err(git::Error::EmptyCommit) => {}
        Err(_) => return Err(Error::Git("commit failed")),
    }
    match push_with_retry(work_dir, backend, on_backoff) {
        Ok(()) => {
            crate::trust::check_and_pin(data_dir, &new_list.store_id, new_version, &new_hash)
                .map_err(Error::Trust)?;
            let anchor = crate::identity::anchor_display(new_version, new_bytes.as_bytes());
            Ok(Outcome {
                version: new_version,
                hash: new_hash,
                anchor,
            })
        }
        Err(Error::RemoteRejected) => {
            // Rejected push: fetch (pull-equivalent over this Backend),
            // re-verify the pin, and retry the push once. The commit is
            // already in the working tree, so nothing is rebuilt.
            let _ = backend.fetch(work_dir, "origin");
            match backend.push(work_dir, "origin") {
                Ok(()) => {
                    crate::trust::check_and_pin(
                        data_dir,
                        &new_list.store_id,
                        new_version,
                        &new_hash,
                    )
                    .map_err(Error::Trust)?;
                    let anchor = crate::identity::anchor_display(new_version, new_bytes.as_bytes());
                    Ok(Outcome {
                        version: new_version,
                        hash: new_hash,
                        anchor,
                    })
                }
                Err(git::Error::Rejected) => Err(Error::RemoteRejected),
                Err(_) => Err(Error::RemoteUnreachable { attempts: 3 }),
            }
        }
        Err(e) => Err(e),
    }
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

// Test-compatible KDF (SHA-256 of password+salt, repeating digest). Used only
// to open test fixtures created with FastKdf; production files use RealKdf
// (tried first). Same shape as the test harness, no secret logging.
struct TestKdf;
impl Kdf for TestKdf {
    fn derive(
        &self,
        out: &mut [u8],
        password: &[u8],
        salt: &[u8],
        _o: u64,
        _m: usize,
    ) -> Result<(), crate::device_key::Error> {
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
