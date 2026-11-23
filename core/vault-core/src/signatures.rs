//! Domain-separated Ed25519 signatures (spec 03 sections 3.1 and 3.4).
//!
//! Every signature covers `prefix || canonical bytes`, where the prefix is
//! an ASCII string ending in a newline. Verification is strict: malleable
//! `S` values are rejected.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::fmt;

/// A signature domain. Each maps to the exact prefix in spec 03 section 3.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Domain {
    Devices,
    Entry,
    Join,
    Device,
}

impl Domain {
    /// The domain-separation prefix, ASCII ending in `0x0A`.
    pub fn prefix(self) -> &'static [u8] {
        match self {
            Domain::Devices => b"argus-devices-v1\n",
            Domain::Entry => b"argus-entry-v1\n",
            Domain::Join => b"argus-join-v1\n",
            Domain::Device => b"argus-device-v1\n",
        }
    }
}

/// A verification failure. Carries no message or key text.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    BadSignature,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::BadSignature => write!(f, "bad signature"),
        }
    }
}

impl std::error::Error for Error {}

/// Sign canonical `message` under `domain`.
pub fn sign(signing_key: &SigningKey, domain: Domain, message: &[u8]) -> Signature {
    let mut prefixed = Vec::with_capacity(domain.prefix().len() + message.len());
    prefixed.extend_from_slice(domain.prefix());
    prefixed.extend_from_slice(message);
    signing_key.sign(&prefixed)
}

/// Verify `signature` over canonical `message` under `domain`.
pub fn verify(
    verifying_key: &VerifyingKey,
    domain: Domain,
    message: &[u8],
    signature: &Signature,
) -> Result<(), Error> {
    let mut prefixed = Vec::with_capacity(domain.prefix().len() + message.len());
    prefixed.extend_from_slice(domain.prefix());
    prefixed.extend_from_slice(message);
    verifying_key
        .verify_strict(&prefixed, signature)
        .map_err(|_| Error::BadSignature)
}
