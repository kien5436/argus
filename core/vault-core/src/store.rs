//! Store layout and store.json (spec 03 section 3.3).
//!
//! The store root holds only files, never subdirectories: `store.json`,
//! `.gitattributes`, `devices.json`, `devices.sig`, `pending-<id>.json` and
//! `<id>.arg` entries. Anything else is ignored and left untouched.

use crate::encodings::validate_id;
use std::fmt;
use std::path::Path;

/// Supported store format (spec 03 section 3.3).
pub const SUPPORTED_FORMAT: u64 = 1;

/// Exact bytes of `.gitattributes` in a new store.
pub const GITATTRIBUTES: &str = "*.arg binary\n*.json -text\n";

/// Store identity read from `store.json`.
#[derive(Debug, PartialEq, Eq)]
pub struct StoreInfo {
    pub format: u64,
    pub store_id: String,
    pub created: String,
}

/// Store layout failure. Never carries file contents.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    NotAStore,
    FormatUnsupported(u64),
    Invalid(&'static str),
    Io(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotAStore => write!(f, "not a store"),
            Error::FormatUnsupported(v) => write!(f, "unsupported store format {v}"),
            Error::Invalid(reason) => write!(f, "invalid store: {reason}"),
            Error::Io(reason) => write!(f, "store io error: {reason}"),
        }
    }
}

impl std::error::Error for Error {}

/// Create a new store layout in `dir`: `store.json` plus `.gitattributes`.
/// `store_id` must be a valid 26-character id; `created` an RFC 3339 time
/// (stored verbatim, but built with `serde_json` so it can never break the
/// JSON structure).
pub fn init(dir: &Path, store_id: &str, created: &str) -> Result<StoreInfo, Error> {
    validate_id(store_id).map_err(|_| Error::Invalid("storeId"))?;
    if created.is_empty() {
        return Err(Error::Invalid("created"));
    }
    let body = serde_json::to_vec(&serde_json::json!({
        "format": SUPPORTED_FORMAT,
        "storeId": store_id,
        "created": created,
    }))
    .map_err(|_| Error::Invalid("store.json"))?;
    std::fs::write(dir.join("store.json"), body).map_err(|_| Error::Io("write store.json"))?;
    std::fs::write(dir.join(".gitattributes"), GITATTRIBUTES.as_bytes())
        .map_err(|_| Error::Io("write .gitattributes"))?;
    Ok(StoreInfo {
        format: SUPPORTED_FORMAT,
        store_id: store_id.to_string(),
        created: created.to_string(),
    })
}

/// Read and validate `store.json` in `dir`.
pub fn open(dir: &Path) -> Result<StoreInfo, Error> {
    let bytes = std::fs::read(dir.join("store.json")).map_err(|_| Error::NotAStore)?;
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| Error::Invalid("store.json"))?;
    let format = value
        .get("format")
        .and_then(|v| v.as_u64())
        .ok_or(Error::Invalid("format"))?;
    if format != SUPPORTED_FORMAT {
        return Err(Error::FormatUnsupported(format));
    }
    let store_id = value
        .get("storeId")
        .and_then(|v| v.as_str())
        .ok_or(Error::Invalid("storeId"))?;
    validate_id(store_id).map_err(|_| Error::Invalid("storeId"))?;
    let created = value
        .get("created")
        .and_then(|v| v.as_str())
        .ok_or(Error::Invalid("created"))?;
    Ok(StoreInfo {
        format,
        store_id: store_id.to_string(),
        created: created.to_string(),
    })
}

/// True when `name` is not a known store file and must be ignored.
pub fn is_ignored(name: &str) -> bool {
    !is_known(name)
}

fn is_known(name: &str) -> bool {
    match name {
        "store.json" | ".gitattributes" | "devices.json" | "devices.sig" => true,
        _ => {
            if let Some(stem) = name.strip_suffix(".arg") {
                return validate_id(stem).is_ok();
            }
            if let Some(rest) = name
                .strip_prefix("pending-")
                .and_then(|s| s.strip_suffix(".json"))
            {
                return validate_id(rest).is_ok();
            }
            false
        }
    }
}
