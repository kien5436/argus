//! T4.3 pin, rollback and fork detection (spec 03 section 3.5 rule 6).

use std::fs;
use vault_core::trust::{check_and_pin, load, Error};

fn unique_base(tag: &str) -> std::path::PathBuf {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let mut dir = std::env::temp_dir();
    dir.push(format!(
        "argus-t43-{}-{}-{}-{}",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        n
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn cleanup(dir: &std::path::Path) {
    let _ = fs::remove_dir_all(dir);
}

fn store_id() -> &'static str {
    "aaaaaaaaaaaaaaaaaaaaaaaaaa"
}

fn hash(seed: u8) -> String {
    std::iter::repeat_n(seed, 32)
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[test]
fn t43_01_no_pin_accepted_and_pinned() {
    let d = unique_base("nopin");
    check_and_pin(&d, store_id(), 3, &hash(0xab)).unwrap();
    let pin = load(&d).unwrap().expect("pinned");
    assert_eq!(pin.store_id, store_id());
    assert_eq!(pin.version, 3);
    assert_eq!(pin.hash, hash(0xab));
    cleanup(&d);
}

#[test]
fn t43_02_newer_version_replaces_pin() {
    let d = unique_base("newer");
    check_and_pin(&d, store_id(), 2, &hash(0x01)).unwrap();
    check_and_pin(&d, store_id(), 5, &hash(0x02)).unwrap();
    let pin = load(&d).unwrap().expect("pinned");
    assert_eq!((pin.version, pin.hash), (5, hash(0x02)));
    cleanup(&d);
}

#[test]
fn t43_03_lower_version_fails_rollback() {
    let d = unique_base("rollback");
    check_and_pin(&d, store_id(), 4, &hash(0x01)).unwrap();
    let err = check_and_pin(&d, store_id(), 3, &hash(0x00)).unwrap_err();
    assert_eq!(err, Error::Rollback);
    let pin = load(&d).unwrap().expect("pinned");
    assert_eq!(pin.version, 4);
    cleanup(&d);
}

#[test]
fn t43_04_same_version_same_hash_accepted() {
    let d = unique_base("same");
    check_and_pin(&d, store_id(), 4, &hash(0x01)).unwrap();
    check_and_pin(&d, store_id(), 4, &hash(0x01)).unwrap();
    let pin = load(&d).unwrap().expect("pinned");
    assert_eq!((pin.version, pin.hash), (4, hash(0x01)));
    cleanup(&d);
}

#[test]
fn t43_05_same_version_different_hash_fails_fork() {
    let d = unique_base("fork");
    check_and_pin(&d, store_id(), 4, &hash(0x01)).unwrap();
    let err = check_and_pin(&d, store_id(), 4, &hash(0x02)).unwrap_err();
    assert_eq!(err, Error::Fork);
    assert!(format!("{err}").contains("security alert"));
    let pin = load(&d).unwrap().expect("pinned");
    assert_eq!(pin.hash, hash(0x01));
    cleanup(&d);
}

#[test]
fn t43_06_trust_json_written_atomically() {
    let d = unique_base("atomic");
    check_and_pin(&d, store_id(), 1, &hash(0x09)).unwrap();
    let trust = d.join("trust.json");
    assert!(trust.is_file());
    assert!(!d.join("trust.json.tmp").exists());
    let raw = fs::read_to_string(&trust).unwrap();
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(v.get("storeId").and_then(|v| v.as_str()), Some(store_id()));
    cleanup(&d);
}

#[test]
fn t43_07_corrupt_trust_json_refuses_without_reset() {
    let d = unique_base("corrupt");
    check_and_pin(&d, store_id(), 2, &hash(0x01)).unwrap();
    fs::write(d.join("trust.json"), "{not json").unwrap();
    let err = load(&d).unwrap_err();
    assert_eq!(err, Error::Corrupt);
    assert!(format!("{err}").contains("user decision"));
    let err = check_and_pin(&d, store_id(), 3, &hash(0x02)).unwrap_err();
    assert_eq!(err, Error::Corrupt);
    assert_eq!(
        fs::read_to_string(d.join("trust.json")).unwrap(),
        "{not json"
    );
    cleanup(&d);
}

#[test]
fn t43_08_other_store_pin_mismatch_fails() {
    let d = unique_base("store");
    check_and_pin(&d, store_id(), 2, &hash(0x01)).unwrap();
    let err = check_and_pin(&d, "bbbbbbbbbbbbbbbbbbbbbbbbba", 3, &hash(0x02)).unwrap_err();
    assert_eq!(err, Error::StoreMismatch);
    let pin = load(&d).unwrap().expect("pinned");
    assert_eq!(pin.store_id, store_id());
    cleanup(&d);
}

#[test]
fn t43_09_invalid_inputs_and_error_text() {
    let d = unique_base("invalid");
    assert_eq!(
        check_and_pin(&d, store_id(), 0, &hash(0x01)).unwrap_err(),
        Error::Invalid("version")
    );
    assert_eq!(
        check_and_pin(&d, store_id(), 1, "xyz").unwrap_err(),
        Error::Invalid("hash")
    );
    assert_eq!(
        check_and_pin(&d, "bad-id", 1, &hash(0x01)).unwrap_err(),
        Error::Invalid("storeId")
    );
    assert_eq!(load(&d).unwrap(), None);
    assert!(format!("{}", Error::Rollback).contains("rollback"));
    assert!(format!("{}", Error::Fork).contains("security alert"));
    assert!(format!("{}", Error::Corrupt).contains("user decision"));
    assert!(format!("{}", Error::StoreMismatch).contains("different store"));
    assert!(format!("{}", Error::Invalid("version")).contains("version"));
    assert!(format!("{}", Error::Io("read trust")).contains("io error"));
    // A regular file as the data dir is not readable as a pin file.
    let file = d.join("blocker");
    fs::write(&file, b"x").unwrap();
    assert_eq!(load(&file).unwrap_err(), Error::Io("read trust"));
    cleanup(&d);
}
