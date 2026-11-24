//! Entry envelope (spec 03 section 3.4).
//!
//! Binary envelope holding a secretbox payload under a random file key,
//! the file key sealed once per recipient with `crypto_box_seal`.
//!
//! Padding: the plaintext is padded with trailing spaces to a multiple of
//! 512 bytes before encryption. [`decrypt`] returns the padded plaintext;
//! the entry layer parses it as JSON, which ignores trailing whitespace
//! (all entry payloads end with `}` so no data is lost).

use dryoc::classic::crypto_box::{crypto_box_seal, crypto_box_seal_open};
use dryoc::classic::crypto_secretbox::{
    crypto_secretbox_easy, crypto_secretbox_keygen, crypto_secretbox_open_easy,
};
use dryoc::constants::{CRYPTO_BOX_MACBYTES, CRYPTO_BOX_PUBLICKEYBYTES, CRYPTO_SECRETBOX_MACBYTES};
use rand::{rng, Rng};
use std::fmt;
use zeroize::Zeroize;
use zeroize::Zeroizing;

/// Magic `ARGUS\x01`.
const MAGIC: [u8; 6] = [0x41, 0x52, 0x47, 0x55, 0x53, 0x01];
/// Envelope version.
const VERSION: u8 = 0x01;
/// Nonce length for the payload secretbox.
const NONCE_LEN: usize = 24;
/// Padding quantum and maximum padded length.
pub const PAD_QUANTUM: usize = 512;
pub const MAX_PLEN: usize = 1_048_576;
/// One sealed file key: ephemeral public key + box overhead + 32-byte key.
const SEALED_LEN: usize = CRYPTO_BOX_PUBLICKEYBYTES + CRYPTO_BOX_MACBYTES + 32;
/// Fixed header: magic(6) + version(1) + plen(4) + nonce(24).
const HEADER_LEN: usize = 35;

/// Envelope errors. No secret text is carried.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// Structurally invalid (bad magic, version, lengths, truncation).
    /// Callers in T6.4 surface this as a damaged entry.
    Damaged(&'static str),
    /// Authentication failed (wrong identity or tampered payload).
    DecryptFailed,
    /// Padded plaintext exceeds the 1 MiB format limit.
    TooLarge,
    /// No recipients: encrypting to an empty set is refused.
    NoRecipients,
    /// More recipients than the `u16` `rcount` field can hold.
    TooManyRecipients,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Damaged(reason) => write!(f, "damaged entry: {reason}"),
            Error::DecryptFailed => write!(f, "decryption failed"),
            Error::TooLarge => write!(f, "entry exceeds 1 MiB"),
            Error::NoRecipients => write!(f, "no recipients"),
            Error::TooManyRecipients => write!(f, "too many recipients"),
        }
    }
}

impl std::error::Error for Error {}

/// Padded length for `len` plaintext bytes.
fn padded_len(len: usize) -> usize {
    if len == 0 {
        return 0;
    }
    len.div_ceil(PAD_QUANTUM) * PAD_QUANTUM
}

/// Encrypt `plaintext` to `recipients` (32-byte X25519 public keys).
///
/// Refuses an empty recipient set, more recipients than the `u16` `rcount`
/// field can hold, and plaintext whose padded length exceeds 1 MiB. The entry
/// layer (T6.1) also refuses oversize writes; this is a defence in depth.
pub fn encrypt(plaintext: &[u8], recipients: &[[u8; 32]]) -> Result<Vec<u8>, Error> {
    if recipients.is_empty() {
        return Err(Error::NoRecipients);
    }
    if recipients.len() > u16::MAX as usize {
        return Err(Error::TooManyRecipients);
    }
    let plen = padded_len(plaintext.len());
    if plen > MAX_PLEN {
        return Err(Error::TooLarge);
    }
    let mut padded = vec![b' '; plen];
    padded[..plaintext.len()].copy_from_slice(plaintext);

    let mut file_key = crypto_secretbox_keygen();
    let mut nonce = [0u8; NONCE_LEN];
    rng().fill_bytes(&mut nonce);

    let mut payload = vec![0u8; plen + CRYPTO_SECRETBOX_MACBYTES];
    crypto_secretbox_easy(&mut payload, &padded, &nonce, &file_key)
        .expect("secretbox encrypt must succeed");

    let mut out =
        Vec::with_capacity(HEADER_LEN + payload.len() + 2 + recipients.len() * SEALED_LEN);
    out.extend_from_slice(&MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&(plen as u32).to_be_bytes());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&payload);
    out.extend_from_slice(&(recipients.len() as u16).to_be_bytes());
    for pk in recipients {
        let mut sealed = [0u8; SEALED_LEN];
        crypto_box_seal(&mut sealed, &file_key, pk).expect("seal must succeed");
        out.extend_from_slice(&sealed);
    }
    padded.zeroize();
    file_key.zeroize();
    Ok(out)
}

/// Number of sealed file keys (`rcount`) in `bytes`.
///
/// Lets callers compare the recipient set size with the verified device
/// list (spec 04 section 4.6) without decrypting.
pub fn recipient_count(bytes: &[u8]) -> Result<usize, Error> {
    Ok(parse(bytes)?.rcount)
}

/// Parsed header offsets.
struct Header {
    plen: usize,
    rcount: usize,
    payload_end: usize,
}

fn parse(bytes: &[u8]) -> Result<Header, Error> {
    if bytes.len() < HEADER_LEN + CRYPTO_SECRETBOX_MACBYTES + 2 {
        return Err(Error::Damaged("truncated"));
    }
    if bytes[..6] != MAGIC {
        return Err(Error::Damaged("magic"));
    }
    if bytes[6] != VERSION {
        return Err(Error::Damaged("version"));
    }
    let plen = u32::from_be_bytes(bytes[7..11].try_into().unwrap()) as usize;
    if !plen.is_multiple_of(PAD_QUANTUM) || plen > MAX_PLEN {
        return Err(Error::Damaged("plen"));
    }
    let payload_end = HEADER_LEN + plen + CRYPTO_SECRETBOX_MACBYTES;
    if bytes.len() < payload_end + 2 {
        return Err(Error::Damaged("truncated"));
    }
    let rcount =
        u16::from_be_bytes(bytes[payload_end..payload_end + 2].try_into().unwrap()) as usize;
    if bytes.len() != payload_end + 2 + rcount * SEALED_LEN {
        return Err(Error::Damaged("rcount"));
    }
    Ok(Header {
        plen,
        rcount,
        payload_end,
    })
}

/// Open the file key sealed in `bytes` with (`my_public`, `my_secret`).
fn open_file_key(
    bytes: &[u8],
    h: &Header,
    my_public: &[u8; 32],
    my_secret: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let mut base = h.payload_end + 2;
    for _ in 0..h.rcount {
        let sealed: &[u8; SEALED_LEN] = bytes[base..base + SEALED_LEN]
            .try_into()
            .map_err(|_| Error::Damaged("rcount"))?;
        let mut file_key = Zeroizing::new([0u8; 32]);
        if crypto_box_seal_open(&mut file_key[..], sealed, my_public, my_secret).is_ok() {
            return Ok(file_key);
        }
        base += SEALED_LEN;
    }
    Err(Error::DecryptFailed)
}

/// Decrypt `bytes` with (`my_public`, `my_secret`), returning the padded plaintext.
///
/// Callers hold keys in `PrivateKey` and copy the 32 bytes out only for the
/// duration of this call; zeroise the copy afterwards. Never keep raw key
/// material in a long-lived structure.
pub fn decrypt(bytes: &[u8], my_public: &[u8; 32], my_secret: &[u8; 32]) -> Result<Vec<u8>, Error> {
    let h = parse(bytes)?;
    let file_key = open_file_key(bytes, &h, my_public, my_secret)?;
    let nonce: [u8; NONCE_LEN] = bytes[11..HEADER_LEN].try_into().unwrap();
    let ciphertext = &bytes[HEADER_LEN..h.payload_end];
    let mut padded = vec![0u8; h.plen];
    crypto_secretbox_open_easy(&mut padded, ciphertext, &nonce, &file_key)
        .map_err(|_| Error::DecryptFailed)?;
    Ok(padded)
}

/// Append a sealed file key for `new_recipient` without touching nonce,
/// payload or file key. The caller must be an existing recipient holding
/// (`my_public`, `my_secret`).
pub fn add_recipient(
    bytes: &[u8],
    new_recipient: &[u8; 32],
    my_public: &[u8; 32],
    my_secret: &[u8; 32],
) -> Result<Vec<u8>, Error> {
    let h = parse(bytes)?;
    let file_key = open_file_key(bytes, &h, my_public, my_secret)?;
    let mut sealed = [0u8; SEALED_LEN];
    crypto_box_seal(&mut sealed, &file_key[..], new_recipient)
        .map_err(|_| Error::Damaged("seal"))?;
    let new_rcount = h.rcount.checked_add(1).ok_or(Error::Damaged("rcount"))?;
    if new_rcount > u16::MAX as usize {
        return Err(Error::Damaged("rcount"));
    }
    let mut out = Vec::with_capacity(bytes.len() + SEALED_LEN);
    out.extend_from_slice(&bytes[..h.payload_end]);
    out.extend_from_slice(&(new_rcount as u16).to_be_bytes());
    out.extend_from_slice(&bytes[h.payload_end + 2..]);
    out.extend_from_slice(&sealed);
    Ok(out)
}
