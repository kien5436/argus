//! Pinned device-list version in `trust.json` (spec 03 section 3.5 rule 6).
//!
//! Stores `(storeId, version, hash)` in the data folder. A lower version is
//! rejected (rollback); the same version with different bytes is rejected
//! (fork) with a security alert. A corrupt file refuses sync and asks the
//! user instead of silently resetting.

use crate::encodings::validate_id;
use std::fmt;
use std::path::Path;

/// Pinned device-list version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustPin {
    pub store_id: String,
    pub version: u64,
    pub hash: String,
}

/// Pin failure. Never carries secrets or key text.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Rollback,
    Fork,
    Corrupt,
    StoreMismatch,
    Invalid(&'static str),
    Io(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Rollback => write!(f, "device list rollback rejected"),
            Error::Fork => write!(f, "security alert: device list fork rejected"),
            Error::Corrupt => write!(f, "trust file is corrupt; user decision required"),
            Error::StoreMismatch => write!(f, "trust pin is for a different store"),
            Error::Invalid(reason) => write!(f, "invalid trust pin: {reason}"),
            Error::Io(reason) => write!(f, "trust file io error: {reason}"),
        }
    }
}

impl std::error::Error for Error {}

fn path_of(dir: &Path) -> std::path::PathBuf {
    dir.join("trust.json")
}

fn validate(store_id: &str, version: u64, hash: &str) -> Result<(), Error> {
    validate_id(store_id).map_err(|_| Error::Invalid("storeId"))?;
    if version == 0 {
        return Err(Error::Invalid("version"));
    }
    if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::Invalid("hash"));
    }
    Ok(())
}

/// Load the pinned version, or `None` when no pin exists yet.
pub fn load(dir: &Path) -> Result<Option<TrustPin>, Error> {
    let path = path_of(dir);
    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(Error::Io("read trust")),
    };
    parse(&raw).map(Some).map_err(|_| Error::Corrupt)
}

fn parse(raw: &str) -> Result<TrustPin, Error> {
    let value: serde_json::Value =
        serde_json::from_str(raw).map_err(|_| Error::Invalid("schema"))?;
    let obj = value.as_object().ok_or(Error::Invalid("schema"))?;
    let store_id = obj
        .get("storeId")
        .and_then(|v| v.as_str())
        .ok_or(Error::Invalid("storeId"))?;
    let version = obj
        .get("version")
        .and_then(|v| v.as_u64())
        .ok_or(Error::Invalid("version"))?;
    let hash = obj
        .get("hash")
        .and_then(|v| v.as_str())
        .ok_or(Error::Invalid("hash"))?;
    validate(store_id, version, hash)?;
    Ok(TrustPin {
        store_id: store_id.to_owned(),
        version,
        hash: hash.to_owned(),
    })
}

/// Check `(store_id, version, hash)` against the pin and pin it when accepted.
///
/// Rules: no pin yet accepts anything valid; a higher version replaces the
/// pin; the same version with the same hash is accepted; a lower version
/// fails with `Rollback`; the same version with a different hash fails with
/// `Fork`; a pin for another store fails with `StoreMismatch`; a corrupt
/// file fails with `Corrupt` and is left untouched.
pub fn check_and_pin(dir: &Path, store_id: &str, version: u64, hash: &str) -> Result<(), Error> {
    validate(store_id, version, hash)?;
    match load(dir)? {
        None => write_pin(dir, store_id, version, hash),
        Some(pin) => {
            if pin.store_id != store_id {
                return Err(Error::StoreMismatch);
            }
            if version < pin.version {
                return Err(Error::Rollback);
            }
            if version == pin.version {
                if hash == pin.hash {
                    return Ok(());
                }
                return Err(Error::Fork);
            }
            write_pin(dir, store_id, version, hash)
        }
    }
}

fn write_pin(dir: &Path, store_id: &str, version: u64, hash: &str) -> Result<(), Error> {
    std::fs::create_dir_all(dir).map_err(|_| Error::Io("create dir"))?;
    let mut map = serde_json::Map::new();
    map.insert("hash".to_owned(), serde_json::Value::from(hash));
    map.insert("storeId".to_owned(), serde_json::Value::from(store_id));
    map.insert("version".to_owned(), serde_json::Value::from(version));
    let json = serde_json::to_string(&serde_json::Value::Object(map))
        .map_err(|_| Error::Invalid("schema"))?;
    let canonical =
        crate::canonical_json::canonicalize(&json).map_err(|_| Error::Invalid("schema"))?;
    let path = path_of(dir);
    let tmp = dir.join("trust.json.tmp");
    {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(&tmp).map_err(|_| Error::Io("write trust"))?;
        std::io::Write::write_all(&mut file, canonical.as_bytes())
            .map_err(|_| Error::Io("write trust"))?;
        file.sync_all().map_err(|_| Error::Io("sync trust"))?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
            .map_err(|_| Error::Io("chmod trust"))?;
    }
    std::fs::rename(&tmp, &path).map_err(|_| Error::Io("replace trust"))?;
    Ok(())
}
