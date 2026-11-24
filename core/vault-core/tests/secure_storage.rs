use vault_core::secure_storage::{InMemorySecureStorage, SecureStorage};

// T2.4-01: save then load returns the stored bytes.
#[test]
fn t24_01_save_then_load_returns_stored_bytes() {
    let mut store = InMemorySecureStorage::new();
    store
        .save_key("argus-device", b"key-material".to_vec())
        .unwrap();
    assert_eq!(
        store.load_key("argus-device").unwrap(),
        Some(b"key-material".to_vec())
    );
}

// T2.4-02: load of a missing key returns None.
#[test]
fn t24_02_load_missing_key_returns_none() {
    let store = InMemorySecureStorage::new();
    assert_eq!(store.load_key("no-such-key").unwrap(), None);
}

// T2.4-03: delete removes the key; a second delete is not an error.
#[test]
fn t24_03_delete_removes_key_and_second_delete_is_ok() {
    let mut store = InMemorySecureStorage::new();
    store.save_key("k", b"v".to_vec()).unwrap();
    store.delete_key("k").unwrap();
    assert_eq!(store.load_key("k").unwrap(), None);
    store.delete_key("k").unwrap();
}

// T2.4-04: the core depends on no platform keystore crate.
#[test]
fn t24_04_core_has_no_platform_keystore_dependency() {
    let manifest = include_str!("../Cargo.toml");
    for banned in [
        "security-framework",
        "keyring",
        "keychain",
        "winapi",
        "windows-credential",
        "secret-service",
    ] {
        assert!(
            !manifest.to_lowercase().contains(banned),
            "vault-core must not depend on platform crate {banned}"
        );
    }
}

// T2.4-05: the double records each call; assert the unlock sequence.
#[test]
fn t24_05_double_records_expected_unlock_sequence() {
    struct Recording {
        inner: InMemorySecureStorage,
        calls: Vec<String>,
    }
    impl Recording {
        fn save(&mut self, name: &str, value: Vec<u8>) {
            self.calls.push(format!("save:{name}"));
            self.inner.save_key(name, value).unwrap();
        }
        fn load(&mut self, name: &str) -> Option<Vec<u8>> {
            self.calls.push(format!("load:{name}"));
            self.inner.load_key(name).unwrap()
        }
        fn delete(&mut self, name: &str) {
            self.calls.push(format!("delete:{name}"));
            self.inner.delete_key(name).unwrap();
        }
    }
    let mut rec = Recording {
        inner: InMemorySecureStorage::new(),
        calls: Vec::new(),
    };
    // Unlock path: store the key, read it back, drop it on lock.
    rec.save("argus-device", b"bytes".to_vec());
    assert_eq!(rec.load("argus-device"), Some(b"bytes".to_vec()));
    rec.delete("argus-device");
    assert_eq!(
        rec.calls,
        vec![
            "save:argus-device".to_string(),
            "load:argus-device".to_string(),
            "delete:argus-device".to_string(),
        ]
    );
}
