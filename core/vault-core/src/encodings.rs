//! Encodings and ids (spec 03 section 3.1).
//!
//! SHA-256 hex, base64url without padding, and 26-character base32 entry
//! ids from 128 random bits.

use rand::Rng;
use sha2::{Digest, Sha256};
use std::fmt;

/// An encoding failure. Carries no input text.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    InvalidBase64,
    InvalidId,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidBase64 => write!(f, "invalid base64url"),
            Error::InvalidId => write!(f, "invalid id"),
        }
    }
}

impl std::error::Error for Error {}

/// SHA-256 of `data` as lowercase hex.
pub fn sha256_hex(data: &[u8]) -> String {
    data_encoding::HEXLOWER.encode(&Sha256::digest(data))
}

/// base64url without padding.
pub fn b64u_encode(data: &[u8]) -> String {
    data_encoding::BASE64URL_NOPAD.encode(data)
}

/// Decode base64url without padding.
pub fn b64u_decode(input: &str) -> Result<Vec<u8>, Error> {
    data_encoding::BASE64URL_NOPAD
        .decode(input.as_bytes())
        .map_err(|_| Error::InvalidBase64)
}

/// A new random entry id: 26 lowercase base32 characters from 128 bits.
pub fn generate_id(rng: &mut impl Rng) -> String {
    let mut bytes = [0u8; 16];
    rng.fill_bytes(&mut bytes);
    encode_id(&bytes)
}

/// Check an entry id without decoding secrets from it.
pub fn validate_id(id: &str) -> Result<(), Error> {
    decode_id(id).map(|_| ())
}

fn encode_id(bytes: &[u8; 16]) -> String {
    data_encoding::BASE32_NOPAD
        .encode(bytes)
        .to_ascii_lowercase()
}

fn decode_id(id: &str) -> Result<[u8; 16], Error> {
    if id.len() != 26 || !id.bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7')) {
        return Err(Error::InvalidId);
    }
    let bytes = data_encoding::BASE32_NOPAD
        .decode(id.to_ascii_uppercase().as_bytes())
        .map_err(|_| Error::InvalidId)?;
    bytes.try_into().map_err(|_| Error::InvalidId)
}
