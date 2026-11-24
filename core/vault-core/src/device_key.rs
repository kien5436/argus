//! device.key create and open (spec 02; spec 03 section 3.6).
//!
//! Both device keypairs live in one Argon2id-encrypted envelope. The header
//! records the cost parameters actually used: opslimit 3 and 256 MiB, or on
//! allocation failure opslimit 3 and 64 MiB.

use dryoc::classic::crypto_box::crypto_box_seed_keypair;
use dryoc::classic::crypto_pwhash::{crypto_pwhash, PasswordHashAlgorithm};
use dryoc::classic::crypto_secretbox::{crypto_secretbox_easy, crypto_secretbox_open_easy};
use dryoc::constants::{CRYPTO_PWHASH_SALTBYTES, CRYPTO_SECRETBOX_MACBYTES};
use dryoc::keypair::{PublicKey, SecretKey};
use dryoc::types::{ByteArray, MutByteArray, NewByteArray};
use rand::Rng;
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, Zeroizing};

use crate::encodings;
use crate::secrets::{MasterPassword, PrivateKey};

/// Magic `ARGUSK`.
const MAGIC: [u8; 6] = *b"ARGUSK";
/// Envelope version.
const VERSION: u8 = 0x01;
/// Argon2id opslimit, kept at 3 even on fallback.
pub const OPSLIMIT: u64 = 3;
/// Preferred Argon2id memory: 256 MiB.
pub const MEMLIMIT_FULL: usize = 256 * 1024 * 1024;
/// Fallback Argon2id memory: 64 MiB.
pub const MEMLIMIT_FALLBACK: usize = 64 * 1024 * 1024;
/// Nonce length for the payload secretbox.
const NONCE_LEN: usize = 24;
/// Header: magic(6) + version(1) + salt(16) + opslimit(4) + memlimit(4) + nonce(24).
const HEADER_LEN: usize = 6 + 1 + CRYPTO_PWHASH_SALTBYTES + 4 + 4 + NONCE_LEN;

/// device.key failure. Carries no secret text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The password is wrong (header parses, authentication fails).
    WrongPassword,
    /// The file is structurally invalid (bad magic, version, or lengths).
    Corrupt(&'static str),
    /// The master password is empty.
    EmptyPassword,
    /// The master password is not valid text.
    InvalidPassword,
    /// Key derivation failed, including at fallback parameters.
    Kdf,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::WrongPassword => write!(f, "wrong password"),
            Error::Corrupt(reason) => write!(f, "damaged device key: {reason}"),
            Error::EmptyPassword => write!(f, "empty master password"),
            Error::InvalidPassword => write!(f, "invalid master password"),
            Error::Kdf => write!(f, "key derivation failed"),
        }
    }
}

impl std::error::Error for Error {}

/// Key derivation boundary (test seam for fallback and speed).
pub trait Kdf {
    fn derive(
        &self,
        out: &mut [u8],
        password: &[u8],
        salt: &[u8],
        opslimit: u64,
        memlimit: usize,
    ) -> Result<(), Error>;
}

/// Production Argon2id derivation via dryoc.
pub struct RealKdf;

impl Kdf for RealKdf {
    fn derive(
        &self,
        out: &mut [u8],
        password: &[u8],
        salt: &[u8],
        opslimit: u64,
        memlimit: usize,
    ) -> Result<(), Error> {
        crypto_pwhash(
            out,
            password,
            salt,
            opslimit,
            memlimit,
            PasswordHashAlgorithm::Argon2id13,
        )
        .map_err(|_| Error::Kdf)
    }
}

/// An unlocked device identity.
#[derive(Debug)]
pub struct DeviceKeys {
    pub device_id: String,
    pub enc_public: [u8; 32],
    pub enc_secret: PrivateKey,
    pub sign_seed: PrivateKey,
}

/// NFC-normalized password bytes; empty is refused.
fn normalized(password: &MasterPassword) -> Result<Vec<u8>, Error> {
    let s = std::str::from_utf8(password.expose()).map_err(|_| Error::InvalidPassword)?;
    let n: String = s.nfc().collect();
    if n.is_empty() {
        return Err(Error::EmptyPassword);
    }
    Ok(n.into_bytes())
}

fn derive_with_fallback(
    kdf: &impl Kdf,
    password: &[u8],
    salt: &[u8],
    opslimit: &mut u64,
    memlimit: &mut usize,
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let mut key = Zeroizing::new([0u8; 32]);
    if kdf
        .derive(&mut key[..], password, salt, OPSLIMIT, MEMLIMIT_FULL)
        .is_ok()
    {
        *opslimit = OPSLIMIT;
        *memlimit = MEMLIMIT_FULL;
        return Ok(key);
    }
    kdf.derive(&mut key[..], password, salt, OPSLIMIT, MEMLIMIT_FALLBACK)
        .map(|_| {
            *opslimit = OPSLIMIT;
            *memlimit = MEMLIMIT_FALLBACK;
            key
        })
        .map_err(|_| Error::Kdf)
}

/// Generate fresh keypairs and seal them under `password`.
pub fn create(
    password: &MasterPassword,
    rng: &mut impl Rng,
    kdf: &impl Kdf,
) -> Result<Vec<u8>, Error> {
    let pw = normalized(password)?;
    let device_id = encodings::generate_id(&mut *rng);
    let mut enc_seed = [0u8; 32];
    rng.fill_bytes(&mut enc_seed);
    let mut sign_seed = [0u8; 32];
    rng.fill_bytes(&mut sign_seed);
    let (_enc_pk, enc_sk) = crypto_box_seed_keypair(&enc_seed);
    enc_seed.zeroize();

    let plaintext = serde_json::to_vec(&serde_json::json!({
        "v": 1,
        "deviceId": device_id,
        "encSecret": encodings::b64u_encode(enc_sk.as_slice()),
        "signSeed": encodings::b64u_encode(&sign_seed),
    }))
    .map_err(|_| Error::Corrupt("plaintext"))?;

    let mut salt = [0u8; CRYPTO_PWHASH_SALTBYTES];
    rng.fill_bytes(&mut salt);
    let mut opslimit = OPSLIMIT;
    let mut memlimit = MEMLIMIT_FULL;
    let key = derive_with_fallback(kdf, &pw, &salt, &mut opslimit, &mut memlimit)?;
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);

    let mut payload = vec![0u8; plaintext.len() + CRYPTO_SECRETBOX_MACBYTES];
    crypto_secretbox_easy(&mut payload, &plaintext, &nonce, &key).map_err(|_| Error::Kdf)?;

    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.extend_from_slice(&MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&(opslimit as u32).to_be_bytes());
    out.extend_from_slice(&(memlimit as u32).to_be_bytes());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&payload);
    Ok(out)
}

/// Open `device.key` with `password`.
pub fn open(bytes: &[u8], password: &MasterPassword, kdf: &impl Kdf) -> Result<DeviceKeys, Error> {
    if bytes.len() < HEADER_LEN + CRYPTO_SECRETBOX_MACBYTES {
        return Err(Error::Corrupt("truncated"));
    }
    if bytes[..6] != MAGIC {
        return Err(Error::Corrupt("magic"));
    }
    if bytes[6] != VERSION {
        return Err(Error::Corrupt("version"));
    }
    let salt: &[u8] = &bytes[7..7 + CRYPTO_PWHASH_SALTBYTES];
    let opslimit = u32::from_be_bytes(bytes[23..27].try_into().unwrap()) as u64;
    let memlimit = u32::from_be_bytes(bytes[27..31].try_into().unwrap()) as usize;
    if opslimit != OPSLIMIT || (memlimit != MEMLIMIT_FULL && memlimit != MEMLIMIT_FALLBACK) {
        return Err(Error::Corrupt("params"));
    }
    let nonce: [u8; NONCE_LEN] = bytes[31..HEADER_LEN].try_into().unwrap();
    let ciphertext = &bytes[HEADER_LEN..];

    let pw = normalized(password)?;
    let mut key = Zeroizing::new([0u8; 32]);
    kdf.derive(&mut key[..], &pw, salt, opslimit, memlimit)
        .map_err(|_| Error::Kdf)?;
    let mut plaintext = vec![0u8; ciphertext.len() - CRYPTO_SECRETBOX_MACBYTES];
    crypto_secretbox_open_easy(&mut plaintext, ciphertext, &nonce, &key)
        .map_err(|_| Error::WrongPassword)?;

    let v: serde_json::Value =
        serde_json::from_slice(&plaintext).map_err(|_| Error::WrongPassword)?;
    let obj = v.as_object().ok_or(Error::WrongPassword)?;
    if obj.len() != 4 || obj.get("v") != Some(&serde_json::json!(1)) {
        return Err(Error::WrongPassword);
    }
    let device_id = obj
        .get("deviceId")
        .and_then(|x| x.as_str())
        .ok_or(Error::WrongPassword)?;
    encodings::validate_id(device_id).map_err(|_| Error::WrongPassword)?;
    let enc_secret_raw = encodings::b64u_decode(
        obj.get("encSecret")
            .and_then(|x| x.as_str())
            .ok_or(Error::WrongPassword)?,
    )
    .map_err(|_| Error::WrongPassword)?;
    let sign_seed_raw = encodings::b64u_decode(
        obj.get("signSeed")
            .and_then(|x| x.as_str())
            .ok_or(Error::WrongPassword)?,
    )
    .map_err(|_| Error::WrongPassword)?;
    let enc_secret_bytes: [u8; 32] = enc_secret_raw
        .try_into()
        .map_err(|_| Error::WrongPassword)?;
    let sign_seed_bytes: [u8; 32] = sign_seed_raw.try_into().map_err(|_| Error::WrongPassword)?;

    let mut sk = SecretKey::new_byte_array();
    sk.as_mut_array().copy_from_slice(&enc_secret_bytes);
    let kp = dryoc::keypair::KeyPair::<PublicKey, SecretKey>::from_secret_key(sk);
    Ok(DeviceKeys {
        device_id: device_id.to_string(),
        enc_public: *kp.public_key.as_array(),
        enc_secret: PrivateKey::new(enc_secret_bytes.to_vec()),
        sign_seed: PrivateKey::new(sign_seed_bytes.to_vec()),
    })
}
