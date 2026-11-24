//! Recipients, fingerprints and anchors (spec 03 section 3.5).
//!
//! `argus1...` recipients parse and print as bech32m (BIP-350). A fingerprint
//! is the SHA-256 of `argus-device-v1\n` plus both public keys, shown as 8
//! groups of 4 hex characters. An anchor is `v<version>` plus 8 groups
//! from the file hash; parsing ignores case and spaces.

use bech32::primitives::decode::CheckedHrpstring;
use bech32::{Bech32m, Hrp};
use std::fmt;

/// An `argus1...` X25519 recipient: the 32 raw public-key bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Recipient([u8; 32]);

impl Recipient {
    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for Recipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hrp = Hrp::parse("argus").map_err(|_| fmt::Error)?;
        let s = bech32::encode::<Bech32m>(hrp, &self.0).map_err(|_| fmt::Error)?;
        f.write_str(&s)
    }
}

/// Parse an `argus1...` recipient, checking prefix and checksum.
pub fn parse_recipient(s: &str) -> Result<Recipient, Error> {
    if !s.starts_with("argus1") {
        return Err(Error::InvalidRecipient);
    }
    let checked = CheckedHrpstring::new::<Bech32m>(s).map_err(|_| Error::InvalidRecipient)?;
    if checked.hrp().as_str() != "argus" {
        return Err(Error::InvalidRecipient);
    }
    let bytes: Vec<u8> = checked.byte_iter().collect();
    let key: [u8; 32] = bytes.try_into().map_err(|_| Error::InvalidRecipient)?;
    Ok(Recipient(key))
}

/// An identity-format failure. Carries no key text.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    InvalidRecipient,
    InvalidAnchor,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidRecipient => write!(f, "invalid recipient"),
            Error::InvalidAnchor => write!(f, "invalid anchor"),
        }
    }
}

impl std::error::Error for Error {}

/// SHA-256 of `argus-device-v1\n`, the Ed25519 key, then the X25519 key.
pub fn fingerprint(ed25519: &[u8; 32], x25519: &[u8; 32]) -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"argus-device-v1\n");
    hasher.update(ed25519);
    hasher.update(x25519);
    hasher.finalize().into()
}

/// First 16 bytes of a fingerprint hash as 8 groups of 4 hex characters.
pub fn fingerprint_display(hash: &[u8]) -> String {
    groups(&hash[..16])
}

/// A parsed anchor: device-list version plus the first 16 file-hash bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Anchor {
    pub version: u64,
    pub prefix: [u8; 16],
}

/// `v<version>` plus 8 groups from the SHA-256 of `file_bytes`.
pub fn anchor_display(version: u64, file_bytes: &[u8]) -> String {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(file_bytes);
    format!("v{version} {}", groups(&digest[..16]))
}

/// Parse an anchor, ignoring case and spaces. Version 0 is rejected.
pub fn parse_anchor(s: &str) -> Result<Anchor, Error> {
    let compact: String = s.chars().filter(|c| *c != ' ').collect();
    let lower = compact.to_ascii_lowercase();
    let rest = lower.strip_prefix('v').ok_or(Error::InvalidAnchor)?;
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return Err(Error::InvalidAnchor);
    }
    let version: u64 = digits.parse().map_err(|_| Error::InvalidAnchor)?;
    if version == 0 {
        return Err(Error::InvalidAnchor);
    }
    let hex = &rest[digits.len()..];
    if hex.len() != 32 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::InvalidAnchor);
    }
    let mut prefix = [0u8; 16];
    for i in 0..16 {
        prefix[i] =
            u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).map_err(|_| Error::InvalidAnchor)?;
    }
    Ok(Anchor { version, prefix })
}

fn groups(bytes: &[u8]) -> String {
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    hex.as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap_or("????"))
        .collect::<Vec<_>>()
        .join(" ")
}
