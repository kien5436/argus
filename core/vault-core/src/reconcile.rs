//! Reconcile entry recipients with the newest verified device list
//! (spec 04 section 4.6).

use crate::device_key::Kdf;
use crate::encodings::b64u_decode;
use crate::git::{self, Author, Backend};
use crate::identity::parse_recipient;
use crate::secrets::MasterPassword;
use crate::signatures::VerifyingKey;
use std::fmt;
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

/// One entry left unchanged, with the reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    pub file: String,
    pub reason: &'static str,
}

/// What `reconcile` repaired and what it left alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub repaired: Vec<String>,
    pub failed: Vec<Failure>,
}

/// Reconcile failure. Static reasons only: never secrets or key text.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Invalid(&'static str),
    VerificationFailed(&'static str),
    DeviceKey(crate::device_key::Error),
    Trust(crate::trust::Error),
    Git(&'static str),
    Io(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Invalid(r) => write!(f, "invalid reconcile: {r}"),
            Error::VerificationFailed(r) => write!(f, "VerificationFailed({r})"),
            Error::DeviceKey(_) => write!(f, "device key failed"),
            Error::Trust(_) => write!(f, "trust pin failed"),
            Error::Git(r) => write!(f, "git failed: {r}"),
            Error::Io(r) => write!(f, "reconcile io error: {r}"),
        }
    }
}
impl std::error::Error for Error {}

/// Compare every `<id>.arg` entry's sealed-key count with the number of
/// devices in the newest verified list and repair mismatches (spec 04
/// section 4.6). Runs locally after a pull; it never touches the network.
///
/// - Fewer sealed keys than devices: append seals for the missing
///   recipients. Additions land at the end of the device list, and revoke
///   re-encrypts every entry, so the missing recipients are the last
///   `n - rcount` devices in list order.
/// - More sealed keys than devices: full re-encryption to the verified set
///   with a fresh file key (a removed device may hold the old file key, so
///   a sealed-key append is not enough).
/// - An entry that cannot be repaired (damaged envelope, or this device is
///   not a recipient) is left byte-identical and reported in
///   [`Outcome::failed`].
/// - Repaired entries are committed in one commit with the message `update`.
///   The commit stages the whole working tree, like every core commit: the
///   caller (pull) commits pending changes first per T7.1, so the tree is
///   clean when reconcile runs. Nothing to repair means no commit.
pub fn reconcile(
    work_dir: &Path,
    data_dir: &Path,
    password: &MasterPassword,
    kdf: &impl Kdf,
    backend: &impl Backend,
    author: &Author,
) -> Result<Outcome, Error> {
    let own = own_keys(data_dir, password, kdf)?;
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
    let list = crate::device_list::parse_device_list(&list_bytes)
        .map_err(|_| Error::VerificationFailed("schema"))?;
    if list.store_id != pin.store_id
        || list.version != pin.version
        || list
            .hash_hex()
            .map_err(|_| Error::VerificationFailed("hash"))?
            != pin.hash
    {
        return Err(Error::VerificationFailed("pin"));
    }
    let sig = crate::device_list::parse_device_sig(&sig_bytes)
        .map_err(|_| Error::VerificationFailed("sig"))?;
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
        let vk = VerifyingKey::from_bytes(&kb).map_err(|_| Error::VerificationFailed("sign"))?;
        list.verify(&sig, &vk)
            .map_err(|_| Error::VerificationFailed("badSignature"))?;
    }
    if !list.devices.iter().any(|d| d.id == own.id) {
        return Err(Error::VerificationFailed("signer"));
    }
    let recipients = recipient_keys(&list)?;
    let n = recipients.len();

    let mut names: Vec<String> = Vec::new();
    for e in std::fs::read_dir(work_dir)
        .map_err(|_| Error::Io("read dir"))?
        .flatten()
    {
        let name = e.file_name().to_string_lossy().into_owned();
        if name.ends_with(".arg") {
            names.push(name);
        }
    }
    names.sort();

    let mut repaired = Vec::new();
    let mut failed = Vec::new();
    for name in &names {
        let path = work_dir.join(name);
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(_) => {
                failed.push(Failure {
                    file: name.clone(),
                    reason: "io",
                });
                continue;
            }
        };
        let rcount = match crate::envelope::recipient_count(&bytes) {
            Ok(c) => c,
            Err(_) => {
                failed.push(Failure {
                    file: name.clone(),
                    reason: "damaged",
                });
                continue;
            }
        };
        if rcount == n {
            continue;
        }
        if rcount < n {
            let missing = &recipients[rcount..];
            let mut cur = bytes;
            let mut ok = true;
            for m in missing {
                match crate::envelope::add_recipient(&cur, m, &own.public, &own.secret) {
                    Ok(nb) => cur = nb,
                    // The envelope already parsed, so a failure here means
                    // this device cannot open it.
                    Err(_) => {
                        failed.push(Failure {
                            file: name.clone(),
                            reason: "decrypt",
                        });
                        ok = false;
                        break;
                    }
                }
            }
            if !ok {
                continue;
            }
            std::fs::write(&path, &cur).map_err(|_| Error::Io("write entry"))?;
            repaired.push(name.clone());
        } else {
            let mut pt = match crate::envelope::decrypt(&bytes, &own.public, &own.secret) {
                Ok(p) => p,
                // Same as above: structurally sound, but not openable.
                Err(_) => {
                    failed.push(Failure {
                        file: name.clone(),
                        reason: "decrypt",
                    });
                    continue;
                }
            };
            // Unreachable in practice: `pt` is exactly `plen` bytes, already
            // a multiple of 512 within the 1 MiB limit, and the verified
            // list is neither empty nor over `u16` recipients.
            let new_env = crate::envelope::encrypt(&pt, &recipients)
                .map_err(|_| Error::Invalid("encrypt"))?;
            pt.zeroize();
            std::fs::write(&path, &new_env).map_err(|_| Error::Io("write entry"))?;
            repaired.push(name.clone());
        }
    }

    if !repaired.is_empty() {
        match backend.commit(work_dir, author, "update") {
            Ok(_) => {}
            Err(git::Error::EmptyCommit) => {}
            Err(_) => return Err(Error::Git("commit failed")),
        }
    }
    Ok(Outcome { repaired, failed })
}

/// X25519 recipient keys of `list`, in device-list order.
fn recipient_keys(list: &crate::device_list::DeviceList) -> Result<Vec<[u8; 32]>, Error> {
    let mut out = Vec::with_capacity(list.devices.len());
    for d in &list.devices {
        let r = parse_recipient(&d.enc).map_err(|_| Error::VerificationFailed("enc"))?;
        out.push(*r.bytes());
    }
    Ok(out)
}

/// This device's id and X25519 keypair from its `device.key`.
struct OwnKeys {
    id: String,
    public: [u8; 32],
    secret: Zeroizing<[u8; 32]>,
}

fn own_keys(data_dir: &Path, password: &MasterPassword, kdf: &impl Kdf) -> Result<OwnKeys, Error> {
    let key_bytes =
        std::fs::read(data_dir.join("device.key")).map_err(|_| Error::Io("read device.key"))?;
    let opened = crate::device_key::open(&key_bytes, password, kdf).map_err(Error::DeviceKey)?;
    let secret: [u8; 32] = opened
        .enc_secret
        .expose()
        .try_into()
        .map_err(|_| Error::DeviceKey(crate::device_key::Error::Corrupt("enc")))?;
    Ok(OwnKeys {
        id: opened.device_id,
        public: opened.enc_public,
        secret: Zeroizing::new(secret),
    })
}
