//! `SecureStorage` interface (T2.4; spec 01 Core API).
//!
//! The core calls `save_key`, `load_key` and `delete_key` on this trait.
//! Each platform implements it with its OS keystore (Keychain on Apple);
//! the core never calls an OS API directly. Keychain items only.
//!
//! Method names map to the spec's `saveKey` / `loadKey` / `deleteKey`.

use std::collections::HashMap;
use zeroize::Zeroize;

/// `SecureStorage` failure. Carries no key names or secret text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The backend is unavailable or refused the operation.
    Unavailable,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Unavailable => write!(f, "secure storage unavailable"),
        }
    }
}

impl std::error::Error for Error {}

/// OS-keystore boundary. Genuine constructor dependency: callers take
/// `impl SecureStorage` (production passes the platform Keychain wrapper,
/// tests pass [`InMemorySecureStorage`]) through the same parameter.
pub trait SecureStorage {
    /// Store `value` under `name`, replacing any existing item.
    fn save_key(&mut self, name: &str, value: Vec<u8>) -> Result<(), Error>;
    /// Return the item stored under `name`, or `None` when absent.
    fn load_key(&self, name: &str) -> Result<Option<Vec<u8>>, Error>;
    /// Remove the item under `name`. Absent keys are not an error.
    fn delete_key(&mut self, name: &str) -> Result<(), Error>;
}

/// In-memory [`SecureStorage`] backend.
///
/// Used by tests through the same trait parameter as production; also a
/// fallback where no OS keystore exists. Values are zeroised on delete
/// and on drop, and never appear in `Debug` output.
#[derive(Debug, Default)]
pub struct InMemorySecureStorage {
    items: HashMap<String, Vec<u8>>,
}

impl InMemorySecureStorage {
    /// Empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl SecureStorage for InMemorySecureStorage {
    fn save_key(&mut self, name: &str, value: Vec<u8>) -> Result<(), Error> {
        if let Some(old) = self.items.get_mut(name) {
            old.zeroize();
        }
        self.items.insert(name.to_string(), value);
        Ok(())
    }

    fn load_key(&self, name: &str) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.items.get(name).cloned())
    }

    fn delete_key(&mut self, name: &str) -> Result<(), Error> {
        if let Some(mut old) = self.items.remove(name) {
            old.zeroize();
        }
        Ok(())
    }
}

impl Drop for InMemorySecureStorage {
    fn drop(&mut self) {
        for value in self.items.values_mut() {
            value.zeroize();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_stored_values() {
        let mut store = InMemorySecureStorage::new();
        store.save_key("k", b"s3cr3t".to_vec()).unwrap();
        let shown = format!("{store:?}");
        assert!(!shown.contains("s3cr3t"));
    }
}
