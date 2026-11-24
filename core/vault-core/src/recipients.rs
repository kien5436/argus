//! Recipient set and encrypt guard (spec 03 section 3.5 rule 7).
//!
//! Entries are encrypted only to the recipients of the newest verified
//! device list. A [`VerifiedList`] can only be built by verifying a
//! `devices.json` history, so there is no path that encrypts to an
//! unverified set. An entry signed by a device outside the current list
//! is refused as a security alert, never as a damaged entry.

use crate::device_list::{self, ChainEntry, DeviceList};
use crate::encodings::b64u_decode;
use crate::entry::Entry;
use crate::identity::parse_recipient;
use crate::signatures::VerifyingKey;
use std::fmt;

/// Guard failure. Static reasons only: never key text.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// The device-list history did not verify, or an entry signature is bad.
    VerificationFailed(&'static str),
    /// An entry signer outside the current verified list (security alert).
    UnknownSigner,
    /// Envelope refusal when encrypting (empty set, oversize, too many).
    Encrypt(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::VerificationFailed(reason) => {
                write!(f, "VerificationFailed({reason})")
            }
            Error::UnknownSigner => {
                write!(f, "security alert: entry signer is not a trusted device")
            }
            Error::Encrypt(reason) => write!(f, "encrypt refused: {reason}"),
        }
    }
}

impl std::error::Error for Error {}

/// A newest verified device list. Only [`verify`] builds one.
#[derive(Debug, Clone)]
pub struct VerifiedList {
    list: DeviceList,
    version: u64,
    hash: String,
    recipients: Vec<[u8; 32]>,
}

impl VerifiedList {
    /// Verify `chain` against `pinned_store_id` and pin the newest version.
    pub fn verify(
        chain: &[ChainEntry],
        pinned_store_id: &str,
        shallow: bool,
    ) -> Result<Self, Error> {
        let (_version, hash) =
            device_list::verify_chain(chain, pinned_store_id, shallow).map_err(map_chain_err)?;
        let newest = chain.last().ok_or(Error::VerificationFailed("emptyList"))?;
        let list = device_list::parse_device_list(&newest.list_bytes).map_err(map_chain_err)?;
        let mut recipients = Vec::with_capacity(list.devices.len());
        for d in &list.devices {
            let r = parse_recipient(&d.enc).map_err(|_| Error::VerificationFailed("enc"))?;
            recipients.push(*r.bytes());
        }
        Ok(VerifiedList {
            version: list.version,
            list,
            hash,
            recipients,
        })
    }

    /// The verified list itself.
    pub fn device_list(&self) -> &DeviceList {
        &self.list
    }

    /// Newest verified version.
    pub fn version(&self) -> u64 {
        self.version
    }

    /// Hash of the newest verified file bytes.
    pub fn hash(&self) -> &str {
        &self.hash
    }

    /// X25519 recipient keys in device-list order.
    pub fn recipient_keys(&self) -> &[[u8; 32]] {
        &self.recipients
    }

    /// Encrypt `plaintext` to the verified recipient set.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        // Only `TooLarge` is reachable: the verified list is never empty
        // (rule 5) and never exceeds `u16` recipients in practice.
        crate::envelope::encrypt(plaintext, &self.recipients).map_err(|e| match e {
            crate::envelope::Error::TooLarge => Error::Encrypt("tooLarge"),
            _ => Error::Encrypt("refused"),
        })
    }

    /// Verify `entry` against the current verified list.
    ///
    /// A signer outside the list is a security alert ([`Error::UnknownSigner`]),
    /// never a damaged entry. A bad signature is [`Error::VerificationFailed`].
    pub fn verify_entry(&self, entry: &Entry) -> Result<(), Error> {
        let mut keys: Vec<(String, VerifyingKey)> = Vec::with_capacity(self.list.devices.len());
        for d in &self.list.devices {
            let raw = b64u_decode(&d.sign).map_err(|_| Error::VerificationFailed("sign"))?;
            let bytes: [u8; 32] = raw
                .try_into()
                .map_err(|_| Error::VerificationFailed("sign"))?;
            let key =
                VerifyingKey::from_bytes(&bytes).map_err(|_| Error::VerificationFailed("sign"))?;
            keys.push((d.id.clone(), key));
        }
        let refs: Vec<(&str, &VerifyingKey)> =
            keys.iter().map(|(id, k)| (id.as_str(), k)).collect();
        entry.verify(&refs).map_err(|e| match e {
            crate::entry::Error::Invalid("signer") => Error::UnknownSigner,
            _ => Error::VerificationFailed("badSignature"),
        })
    }
}

fn map_chain_err(e: device_list::Error) -> Error {
    match e {
        device_list::Error::Invalid(reason) => Error::VerificationFailed(reason),
        device_list::Error::BadSignature => Error::VerificationFailed("badSignature"),
    }
}
