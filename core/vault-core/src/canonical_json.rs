//! Canonical JSON (RFC 8785).
//!
//! [`canonicalize`] parses with `serde_json`, rejecting duplicate keys,
//! floats and `-0`, then re-serialises the value. `serde_json::Map`
//! iterates in byte order, which matches UTF-16 code-unit order, and the
//! serializer uses the RFC 8785 escapes.

use serde::de::{Error as DeError, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::fmt;

/// Token `serde_json` uses to deliver arbitrary-precision numbers.
const NUMBER_TOKEN: &str = "$serde_json::private::Number";

/// A canonicalisation failure. Carries no input text.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    DuplicateKey,
    Float,
    NegativeZero,
    InvalidJson,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::DuplicateKey => write!(f, "duplicate object key"),
            Error::Float => write!(f, "floats are not allowed"),
            Error::NegativeZero => write!(f, "negative zero is not allowed"),
            Error::InvalidJson => write!(f, "invalid JSON"),
        }
    }
}

impl std::error::Error for Error {}

/// Parse `input` as Argus JSON and return its RFC 8785 canonical form.
///
/// Rejects duplicate keys, floats, leading zeros and `-0`.
pub fn canonicalize(input: &str) -> Result<String, Error> {
    let value = parse(input)?;
    serde_json::to_string(&value).map_err(|_| Error::InvalidJson)
}

fn parse(input: &str) -> Result<serde_json::Value, Error> {
    serde_json::from_str::<Checked>(input)
        .map(|checked| checked.0)
        .map_err(|_| Error::InvalidJson)
}

struct Checked(serde_json::Value);

impl<'de> Deserialize<'de> for Checked {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(CheckedVisitor).map(Checked)
    }
}

struct CheckedVisitor;

impl<'de> Visitor<'de> for CheckedVisitor {
    type Value = serde_json::Value;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("JSON")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Bool(v))
    }

    fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E> {
        Ok(serde_json::Value::from(v))
    }

    fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E> {
        Ok(serde_json::Value::from(v))
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(serde_json::Value::String(v.to_owned()))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Null)
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element::<Checked>()? {
            items.push(item.0);
        }
        Ok(serde_json::Value::Array(items))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        match map.next_key::<String>()? {
            None => Ok(serde_json::Value::Object(Default::default())),
            Some(key) if key == NUMBER_TOKEN => {
                let raw: String = map.next_value()?;
                check_number(&raw).map_err(A::Error::custom)?;
                raw.parse()
                    .map(serde_json::Value::Number)
                    .map_err(|_| A::Error::custom(Error::InvalidJson))
            }
            Some(key) => {
                let mut obj = serde_json::Map::new();
                obj.insert(key, map.next_value::<Checked>()?.0);
                while let Some(key) = map.next_key::<String>()? {
                    let value = map.next_value::<Checked>()?.0;
                    if obj.insert(key, value).is_some() {
                        return Err(A::Error::custom(Error::DuplicateKey));
                    }
                }
                Ok(serde_json::Value::Object(obj))
            }
        }
    }
}

fn check_number(raw: &str) -> Result<(), Error> {
    if raw.bytes().any(|b| matches!(b, b'.' | b'e' | b'E')) {
        return Err(Error::Float);
    }
    if raw == "-0" {
        return Err(Error::NegativeZero);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expecting_describes_json() {
        struct Description;
        impl fmt::Display for Description {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                CheckedVisitor.expecting(f)
            }
        }
        assert_eq!(Description.to_string(), "JSON");
    }
}
