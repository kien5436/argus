//! Device list model and `devices.sig` (spec 03 section 3.5).
//!
//! `devices.json` is stored in canonical form; its file bytes are its
//! canonical bytes. `devices.sig` is `{"signer","sig"}` covering the
//! `argus-devices-v1` domain. Adding a device never bumps `version`
//! silently: the caller sets the new version explicitly.

use crate::canonical_json;
use crate::encodings::{b64u_decode, b64u_encode, validate_id};
use crate::identity::parse_recipient;
use crate::signatures::{sign, verify as verify_sig, Domain, Signature, SigningKey, VerifyingKey};
use serde_json::{Map, Value};
use std::fmt;

/// A device-list failure. Static reasons only: never key text.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Invalid(&'static str),
    BadSignature,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Invalid(reason) => write!(f, "invalid device list: {reason}"),
            Error::BadSignature => write!(f, "bad device list signature"),
        }
    }
}

impl std::error::Error for Error {}

/// One device in the list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceEntry {
    pub id: String,
    pub name: String,
    /// `argus1...` bech32m X25519 public key.
    pub enc: String,
    /// b64u Ed25519 public key (32 bytes).
    pub sign: String,
    /// Optional SSH key fingerprint or GitHub key id.
    pub git_key: Option<String>,
    pub added: String,
    pub added_by: String,
}

/// A parsed `devices.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceList {
    pub store_id: String,
    pub version: u64,
    /// Hex hash of the previous version's file bytes; empty for version 1.
    pub prev: String,
    pub updated: String,
    pub devices: Vec<DeviceEntry>,
}

/// A parsed `devices.sig`: `{"signer","sig"}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceSig {
    pub signer: String,
    /// b64u Ed25519 signature (64 bytes).
    pub sig: String,
}

impl DeviceList {
    /// Canonical JSON of this list (the file bytes).
    pub fn canonical_json(&self) -> Result<String, Error> {
        let json = serde_json::to_string(&self.to_value()).map_err(|_| Error::Invalid("schema"))?;
        canonical_json::canonicalize(&json).map_err(|_| Error::Invalid("schema"))
    }

    /// SHA-256 hex of the canonical bytes (the hash chain value).
    pub fn hash_hex(&self) -> Result<String, Error> {
        use sha2::Digest;
        let canonical = self.canonical_json()?;
        let digest = sha2::Sha256::digest(canonical.as_bytes());
        Ok(digest.iter().map(|b| format!("{b:02x}")).collect())
    }

    /// Sign these canonical bytes as `device_id`.
    pub fn sign(&self, device_id: &str, key: &SigningKey) -> Result<DeviceSig, Error> {
        let canonical = self.canonical_json()?;
        let sig = sign(key, Domain::Devices, canonical.as_bytes());
        Ok(DeviceSig {
            signer: device_id.to_owned(),
            sig: b64u_encode(&sig.to_bytes()),
        })
    }

    /// Verify `sig` over these bytes with `key`.
    pub fn verify(&self, sig: &DeviceSig, key: &VerifyingKey) -> Result<(), Error> {
        let raw = b64u_decode(&sig.sig).map_err(|_| Error::Invalid("sig"))?;
        let bytes: [u8; 64] = raw.try_into().map_err(|_| Error::Invalid("sig"))?;
        let canonical = self.canonical_json()?;
        verify_sig(
            key,
            Domain::Devices,
            canonical.as_bytes(),
            &Signature::from_bytes(&bytes),
        )
        .map_err(|_| Error::BadSignature)
    }

    fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("v".to_owned(), Value::from(1));
        map.insert("storeId".to_owned(), Value::from(self.store_id.clone()));
        map.insert("version".to_owned(), Value::from(self.version));
        map.insert("prev".to_owned(), Value::from(self.prev.clone()));
        map.insert("updated".to_owned(), Value::from(self.updated.clone()));
        map.insert(
            "devices".to_owned(),
            Value::Array(self.devices.iter().map(DeviceEntry::to_value).collect()),
        );
        Value::Object(map)
    }
}

impl DeviceEntry {
    fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("added".to_owned(), Value::from(self.added.clone()));
        map.insert("addedBy".to_owned(), Value::from(self.added_by.clone()));
        map.insert("enc".to_owned(), Value::from(self.enc.clone()));
        if let Some(git_key) = &self.git_key {
            map.insert("gitKey".to_owned(), Value::from(git_key.clone()));
        }
        map.insert("id".to_owned(), Value::from(self.id.clone()));
        map.insert("name".to_owned(), Value::from(self.name.clone()));
        map.insert("sign".to_owned(), Value::from(self.sign.clone()));
        Value::Object(map)
    }
}

impl DeviceSig {
    /// Canonical JSON of this signature file.
    pub fn to_canonical_json(&self) -> Result<String, Error> {
        let mut map = Map::new();
        map.insert("sig".to_owned(), Value::from(self.sig.clone()));
        map.insert("signer".to_owned(), Value::from(self.signer.clone()));
        let json =
            serde_json::to_string(&Value::Object(map)).map_err(|_| Error::Invalid("schema"))?;
        canonical_json::canonicalize(&json).map_err(|_| Error::Invalid("schema"))
    }
}

/// Parse and validate `devices.json` bytes.
pub fn parse_device_list(input: &str) -> Result<DeviceList, Error> {
    let value: Value = serde_json::from_str(input).map_err(|_| Error::Invalid("schema"))?;
    let obj = value.as_object().ok_or(Error::Invalid("schema"))?;
    if obj.get("v").and_then(|v| v.as_u64()) != Some(1) {
        return Err(Error::Invalid("v"));
    }
    let store_id = obj
        .get("storeId")
        .and_then(|v| v.as_str())
        .ok_or(Error::Invalid("storeId"))?;
    validate_id(store_id).map_err(|_| Error::Invalid("storeId"))?;
    let version = obj
        .get("version")
        .and_then(|v| v.as_u64())
        .ok_or(Error::Invalid("version"))?;
    if version == 0 {
        return Err(Error::Invalid("version"));
    }
    let prev = obj
        .get("prev")
        .and_then(|v| v.as_str())
        .ok_or(Error::Invalid("prev"))?;
    if !prev.is_empty() && (prev.len() != 64 || !prev.bytes().all(|b| b.is_ascii_hexdigit())) {
        return Err(Error::Invalid("prev"));
    }
    let updated = obj
        .get("updated")
        .and_then(|v| v.as_str())
        .ok_or(Error::Invalid("updated"))?;
    if updated.is_empty() {
        return Err(Error::Invalid("updated"));
    }
    let devices = obj
        .get("devices")
        .and_then(|v| v.as_array())
        .ok_or(Error::Invalid("devices"))?;
    if devices.is_empty() {
        return Err(Error::Invalid("devices"));
    }
    let mut out = Vec::with_capacity(devices.len());
    for d in devices {
        out.push(parse_entry(d)?);
    }
    Ok(DeviceList {
        store_id: store_id.to_owned(),
        version,
        prev: prev.to_owned(),
        updated: updated.to_owned(),
        devices: out,
    })
}

fn parse_entry(value: &Value) -> Result<DeviceEntry, Error> {
    let obj = value.as_object().ok_or(Error::Invalid("device"))?;
    let id = obj
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or(Error::Invalid("id"))?;
    validate_id(id).map_err(|_| Error::Invalid("id"))?;
    let name = obj
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or(Error::Invalid("name"))?;
    if name.is_empty() || name.chars().any(|c| c.is_control()) {
        return Err(Error::Invalid("name"));
    }
    let enc = obj
        .get("enc")
        .and_then(|v| v.as_str())
        .ok_or(Error::Invalid("enc"))?;
    parse_recipient(enc).map_err(|_| Error::Invalid("enc"))?;
    let sign = obj
        .get("sign")
        .and_then(|v| v.as_str())
        .ok_or(Error::Invalid("sign"))?;
    let raw = b64u_decode(sign).map_err(|_| Error::Invalid("sign"))?;
    if raw.len() != 32 {
        return Err(Error::Invalid("sign"));
    }
    let git_key = match obj.get("gitKey") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(_) => return Err(Error::Invalid("gitKey")),
    };
    let added = obj
        .get("added")
        .and_then(|v| v.as_str())
        .ok_or(Error::Invalid("added"))?;
    if added.is_empty() {
        return Err(Error::Invalid("added"));
    }
    let added_by = obj
        .get("addedBy")
        .and_then(|v| v.as_str())
        .ok_or(Error::Invalid("addedBy"))?;
    validate_id(added_by).map_err(|_| Error::Invalid("addedBy"))?;
    Ok(DeviceEntry {
        id: id.to_owned(),
        name: name.to_owned(),
        enc: enc.to_owned(),
        sign: sign.to_owned(),
        git_key,
        added: added.to_owned(),
        added_by: added_by.to_owned(),
    })
}

/// Parse and validate `devices.sig` bytes: exactly `signer` and `sig`.
pub fn parse_device_sig(input: &str) -> Result<DeviceSig, Error> {
    let value: Value = serde_json::from_str(input).map_err(|_| Error::Invalid("schema"))?;
    let obj = value.as_object().ok_or(Error::Invalid("schema"))?;
    let signer = obj
        .get("signer")
        .and_then(|v| v.as_str())
        .ok_or(Error::Invalid("signer"))?;
    validate_id(signer).map_err(|_| Error::Invalid("signer"))?;
    let sig = obj
        .get("sig")
        .and_then(|v| v.as_str())
        .ok_or(Error::Invalid("sig"))?;
    let raw = b64u_decode(sig).map_err(|_| Error::Invalid("sig"))?;
    if raw.len() != 64 {
        return Err(Error::Invalid("sig"));
    }
    Ok(DeviceSig {
        signer: signer.to_owned(),
        sig: sig.to_owned(),
    })
}
