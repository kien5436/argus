//! Entry plaintext format (spec 03 section 3.4).
//!
//! The JSON object stored (padded) in an entry envelope. Unknown fields are
//! preserved on parse so older clients never drop data from newer writers.
//! Padding is trailing spaces to a multiple of 512 bytes; the JSON parser
//! ignores it. Entries larger than 1 MiB are refused on write and on read.

use crate::canonical_json;
use crate::encodings::{b64u_decode, b64u_encode};
use crate::signatures::{sign, verify as verify_sig, Domain, Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::fmt;

/// Maximum padded plaintext: 1 MiB (spec 03 section 3.4).
pub const MAX_BYTES: usize = 1_048_576;
/// Padding quantum in bytes.
pub const PAD_QUANTUM: usize = 512;

/// Padding a within-limit payload can never cross the limit: the maximum is
/// an exact multiple of the quantum.
const _: () = assert!(MAX_BYTES.is_multiple_of(PAD_QUANTUM));

/// An entry-format failure. Static reasons only: never secret text.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Invalid(&'static str),
    TooLarge,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Invalid(reason) => write!(f, "invalid entry: {reason}"),
            Error::TooLarge => write!(f, "entry exceeds 1 MiB"),
        }
    }
}

impl std::error::Error for Error {}

/// OTP hash algorithm. Serialised as `SHA1`, `SHA256` or `SHA512`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Algorithm {
    #[default]
    #[serde(rename = "SHA1")]
    Sha1,
    #[serde(rename = "SHA256")]
    Sha256,
    #[serde(rename = "SHA512")]
    Sha512,
}

/// Typed OTP fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OtpData {
    pub label: String,
    pub issuer: String,
    pub secret: String,
    #[serde(default)]
    pub algorithm: Algorithm,
    pub digits: u8,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub period: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub counter: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub link: Option<String>,
    #[serde(flatten, default, skip_serializing_if = "Map::is_empty")]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CredentialData {
    url: String,
    username: String,
    password: String,
    note: String,
    #[serde(flatten, default, skip_serializing_if = "Map::is_empty")]
    extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct NoteData {
    name: String,
    content: String,
    #[serde(flatten, default, skip_serializing_if = "Map::is_empty")]
    extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Sig {
    by: String,
    #[serde(rename = "v")]
    sig: String,
}

/// The `data` payload plus its type name.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Data {
    Credential(CredentialData),
    Note(NoteData),
    Otp(OtpData),
    Unsupported { type_name: String, data: Value },
}

/// A parsed entry. `Debug` redacts secrets.
#[derive(Clone, PartialEq, Eq)]
pub struct Entry {
    id: String,
    rev: u64,
    created: String,
    updated: String,
    data: Data,
    sig: Option<Sig>,
    conflict_of: Option<String>,
    rotate: bool,
    extra: Map<String, Value>,
}

impl fmt::Debug for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match &self.data {
            Data::Credential(_) => "credential",
            Data::Note(_) => "note",
            Data::Otp(_) => "otp",
            Data::Unsupported { type_name, .. } => type_name.as_str(),
        };
        f.debug_struct("Entry")
            .field("id", &self.id)
            .field("type", &kind)
            .field("rev", &self.rev)
            .field("data", &"[redacted]")
            .finish()
    }
}

impl Entry {
    pub fn new_credential(
        id: &str,
        created: &str,
        url: &str,
        username: &str,
        password: &str,
        note: &str,
    ) -> Entry {
        Entry {
            id: id.to_owned(),
            rev: 1,
            created: created.to_owned(),
            updated: created.to_owned(),
            data: Data::Credential(CredentialData {
                url: url.to_owned(),
                username: username.to_owned(),
                password: password.to_owned(),
                note: note.to_owned(),
                extra: Map::new(),
            }),
            sig: None,
            conflict_of: None,
            rotate: false,
            extra: Map::new(),
        }
    }

    pub fn new_note(id: &str, created: &str, name: &str, content: &str) -> Entry {
        Entry {
            id: id.to_owned(),
            rev: 1,
            created: created.to_owned(),
            updated: created.to_owned(),
            data: Data::Note(NoteData {
                name: name.to_owned(),
                content: content.to_owned(),
                extra: Map::new(),
            }),
            sig: None,
            conflict_of: None,
            rotate: false,
            extra: Map::new(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_otp(
        id: &str,
        created: &str,
        label: &str,
        issuer: &str,
        secret: &str,
        algorithm: Algorithm,
        digits: u8,
        period: Option<u64>,
        counter: Option<u64>,
        link: Option<String>,
    ) -> Result<Entry, Error> {
        check_otp(digits, period, counter)?;
        Ok(Entry {
            id: id.to_owned(),
            rev: 1,
            created: created.to_owned(),
            updated: created.to_owned(),
            data: Data::Otp(OtpData {
                label: label.to_owned(),
                issuer: issuer.to_owned(),
                secret: secret.to_owned(),
                algorithm,
                digits,
                period,
                counter,
                link,
                extra: Map::new(),
            }),
            sig: None,
            conflict_of: None,
            rotate: false,
            extra: Map::new(),
        })
    }

    pub fn rev(&self) -> u64 {
        self.rev
    }

    pub fn updated(&self) -> &str {
        &self.updated
    }

    pub fn conflict_of(&self) -> Option<&str> {
        self.conflict_of.as_deref()
    }

    pub fn rotate(&self) -> bool {
        self.rotate
    }

    pub fn set_conflict_of(&mut self, id: Option<&str>) {
        self.conflict_of = id.map(str::to_owned);
    }

    pub fn set_rotate(&mut self, rotate: bool) {
        self.rotate = rotate;
    }

    /// Record an edit: `rev` plus one and a new timestamp.
    pub fn prepare_edit(&mut self, updated: &str) {
        self.rev += 1;
        self.updated = updated.to_owned();
    }

    pub fn as_credential(&self) -> Result<(&str, &str, &str, &str), Error> {
        match &self.data {
            Data::Credential(c) => Ok((&c.url, &c.username, &c.password, &c.note)),
            _ => Err(Error::Invalid("type")),
        }
    }

    pub fn as_note(&self) -> Result<(&str, &str), Error> {
        match &self.data {
            Data::Note(n) => Ok((&n.name, &n.content)),
            _ => Err(Error::Invalid("type")),
        }
    }

    pub fn as_otp(&self) -> Result<&OtpData, Error> {
        match &self.data {
            Data::Otp(o) => Ok(o),
            _ => Err(Error::Invalid("type")),
        }
    }

    /// Sign this entry as `device_id`, replacing any existing signature.
    ///
    /// Signs the canonical JSON of the entry without `sig` under the
    /// `argus-entry-v1` domain (spec 03 section 3.4).
    pub fn sign(&mut self, device_id: &str, key: &SigningKey) -> Result<(), Error> {
        let canonical = self.canonical_unsigned()?;
        let sig = sign(key, Domain::Entry, canonical.as_bytes());
        self.sig = Some(Sig {
            by: device_id.to_owned(),
            sig: b64u_encode(&sig.to_bytes()),
        });
        Ok(())
    }

    /// Verify this entry's signature against the supplied device list.
    ///
    /// The `sig.by` device must be listed; its key must verify the canonical
    /// unsigned bytes under the `argus-entry-v1` domain.
    pub fn verify(&self, devices: &[(&str, &VerifyingKey)]) -> Result<(), Error> {
        let sig = self.sig.as_ref().ok_or(Error::Invalid("sig"))?;
        let (_, key) = devices
            .iter()
            .find(|(id, _)| *id == sig.by)
            .ok_or(Error::Invalid("signer"))?;
        let raw = b64u_decode(&sig.sig).map_err(|_| Error::Invalid("sig"))?;
        let bytes: [u8; 64] = raw.try_into().map_err(|_| Error::Invalid("sig"))?;
        let canonical = self
            .canonical_unsigned()
            .map_err(|_| Error::Invalid("signature"))?;
        verify_sig(
            key,
            Domain::Entry,
            canonical.as_bytes(),
            &Signature::from_bytes(&bytes),
        )
        .map_err(|_| Error::Invalid("signature"))
    }

    /// Canonical JSON of this entry without `sig`, for hashing and signing.
    fn canonical_unsigned(&self) -> Result<String, Error> {
        let value = self.unsigned_value()?;
        let json = serde_json::to_string(&value).map_err(|_| Error::Invalid("schema"))?;
        canonical_json::canonicalize(&json).map_err(|_| Error::Invalid("schema"))
    }

    /// The entry as a JSON object without `sig`.
    fn unsigned_value(&self) -> Result<Map<String, Value>, Error> {
        let mut value = Map::new();
        value.insert("v".to_owned(), Value::from(1));
        value.insert("id".to_owned(), Value::from(self.id.clone()));
        let (type_name, data) = match &self.data {
            Data::Credential(c) => ("credential", to_data_value(c)?),
            Data::Note(n) => ("note", to_data_value(n)?),
            Data::Otp(o) => ("otp", to_data_value(o)?),
            Data::Unsupported { type_name, data } => (type_name.as_str(), data.clone()),
        };
        value.insert("type".to_owned(), Value::from(type_name));
        value.insert("rev".to_owned(), Value::from(self.rev));
        value.insert("created".to_owned(), Value::from(self.created.clone()));
        value.insert("updated".to_owned(), Value::from(self.updated.clone()));
        value.insert("data".to_owned(), data);
        if let Some(conflict_of) = &self.conflict_of {
            value.insert("conflictOf".to_owned(), Value::from(conflict_of.clone()));
        }
        if self.rotate {
            value.insert("rotate".to_owned(), Value::from(true));
        }
        for (k, v) in &self.extra {
            value.insert(k.clone(), v.clone());
        }
        Ok(value)
    }

    /// Serialise to padded plaintext (trailing spaces, multiple of 512).
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut value = self.unsigned_value()?;
        if let Some(sig) = &self.sig {
            value.insert(
                "sig".to_owned(),
                serde_json::to_value(sig).map_err(|_| Error::Invalid("schema"))?,
            );
        }
        let mut bytes = serde_json::to_vec(&value).map_err(|_| Error::Invalid("schema"))?;
        if bytes.len() > MAX_BYTES {
            return Err(Error::TooLarge);
        }
        // Padding cannot cross MAX_BYTES: it is a multiple of PAD_QUANTUM.
        let plen = bytes.len().div_ceil(PAD_QUANTUM) * PAD_QUANTUM;
        bytes.resize(plen, b' ');
        Ok(bytes)
    }

    /// Parse padded plaintext. Trailing spaces are ignored by the JSON parser.
    pub fn decode(bytes: &[u8]) -> Result<Entry, Error> {
        if bytes.len() > MAX_BYTES {
            return Err(Error::TooLarge);
        }
        let root: Value = serde_json::from_slice(bytes).map_err(|_| Error::Invalid("json"))?;
        let obj = root.as_object().ok_or(Error::Invalid("json"))?;
        if obj.get("v") != Some(&Value::from(1)) {
            return Err(Error::Invalid("v"));
        }
        let id = obj
            .get("id")
            .and_then(Value::as_str)
            .ok_or(Error::Invalid("schema"))?;
        let type_name = obj
            .get("type")
            .and_then(Value::as_str)
            .ok_or(Error::Invalid("schema"))?;
        let rev = obj
            .get("rev")
            .and_then(Value::as_u64)
            .ok_or(Error::Invalid("schema"))?;
        let created = obj
            .get("created")
            .and_then(Value::as_str)
            .ok_or(Error::Invalid("schema"))?;
        let updated = obj
            .get("updated")
            .and_then(Value::as_str)
            .ok_or(Error::Invalid("schema"))?;
        let data_value = obj.get("data").ok_or(Error::Invalid("schema"))?;
        let data = match type_name {
            "credential" => {
                let c: CredentialData = serde_json::from_value(data_value.clone())
                    .map_err(|_| Error::Invalid("schema"))?;
                Data::Credential(c)
            }
            "note" => {
                let n: NoteData = serde_json::from_value(data_value.clone())
                    .map_err(|_| Error::Invalid("schema"))?;
                Data::Note(n)
            }
            "otp" => {
                let o: OtpData = serde_json::from_value(data_value.clone())
                    .map_err(|_| Error::Invalid("algorithm"))?;
                check_otp(o.digits, o.period, o.counter)?;
                Data::Otp(o)
            }
            other => Data::Unsupported {
                type_name: other.to_owned(),
                data: data_value.clone(),
            },
        };
        let sig = match obj.get("sig") {
            None => None,
            Some(v) => {
                Some(serde_json::from_value(v.clone()).map_err(|_| Error::Invalid("schema"))?)
            }
        };
        let conflict_of = obj
            .get("conflictOf")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let rotate = obj.get("rotate").and_then(Value::as_bool).unwrap_or(false);
        let mut extra = Map::new();
        for (k, v) in obj {
            match k.as_str() {
                "v" | "id" | "type" | "rev" | "created" | "updated" | "data" | "sig"
                | "conflictOf" | "rotate" => {}
                _ => {
                    extra.insert(k.clone(), v.clone());
                }
            }
        }
        Ok(Entry {
            id: id.to_owned(),
            rev,
            created: created.to_owned(),
            updated: updated.to_owned(),
            data,
            sig,
            conflict_of,
            rotate,
            extra,
        })
    }
}

fn to_data_value<T: Serialize>(v: &T) -> Result<Value, Error> {
    serde_json::to_value(v).map_err(|_| Error::Invalid("schema"))
}

fn check_otp(digits: u8, period: Option<u64>, counter: Option<u64>) -> Result<(), Error> {
    if !(6..=8).contains(&digits) {
        return Err(Error::Invalid("digits"));
    }
    if period.is_some() && counter.is_some() {
        return Err(Error::Invalid("period/counter"));
    }
    Ok(())
}
