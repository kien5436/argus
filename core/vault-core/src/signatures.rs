//! Domain-separated Ed25519 signatures (spec 03 sections 3.1 and 3.4).
//!
//! Every signature covers `prefix || canonical bytes`, where the prefix is
//! an ASCII string ending in a newline. Signing and verification go through
//! dryoc's `crypto_sign` (libsodium-compatible Ed25519). Verification is
//! strict: malleable `S` values are rejected.

use dryoc::classic::crypto_sign::{
    crypto_sign_detached, crypto_sign_seed_keypair, crypto_sign_verify_detached,
};
use std::fmt;
use zeroize::Zeroize;

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

/// An Ed25519 signing key: the 32-byte seed. Zeroed on drop.
///
/// Build from a short-lived copy of the seed; zeroise the source copy after
/// this call. Never keep raw seed material in a long-lived structure.
pub struct SigningKey([u8; 32]);

impl SigningKey {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        SigningKey(seed)
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        let (pk, _) = crypto_sign_seed_keypair(&self.0);
        VerifyingKey(pk)
    }
}

impl Drop for SigningKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// An Ed25519 public key: the 32 raw bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifyingKey([u8; 32]);

impl VerifyingKey {
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Error> {
        Ok(VerifyingKey(*bytes))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

/// An Ed25519 signature: the 64 raw bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature([u8; 64]);

impl Signature {
    pub fn from_bytes(bytes: &[u8; 64]) -> Self {
        Signature(*bytes)
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        self.0
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
    let (_, mut sk) = crypto_sign_seed_keypair(&signing_key.0);
    let mut prefixed = Vec::with_capacity(domain.prefix().len() + message.len());
    prefixed.extend_from_slice(domain.prefix());
    prefixed.extend_from_slice(message);
    let mut sig = [0u8; 64];
    crypto_sign_detached(&mut sig, &prefixed, &sk).expect("signing a valid key must succeed");
    sk.zeroize();
    Signature(sig)
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
    crypto_sign_verify_detached(&signature.0, &prefixed, &verifying_key.0)
        .map_err(|_| Error::BadSignature)
}
