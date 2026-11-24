//! T1.9 store layout and store.json tests (spec 03 section 3.3).

use std::fs;
use vault_core::store;

fn new_id() -> String {
    "aaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()
}

#[test]
fn t19_01_new_store_has_store_json_gitattributes_no_subdirs() {
    let dir = tempfile_dir();
    store::init(&dir, &new_id(), "2026-11-19T09:00:00Z").unwrap();
    assert!(dir.join("store.json").is_file());
    assert!(dir.join(".gitattributes").is_file());
    let attrs = fs::read_to_string(dir.join(".gitattributes")).unwrap();
    assert_eq!(attrs, "*.arg binary\n*.json -text\n");
    assert!(dir.join("store.json").is_file());
    // No subdirectories created.
    for entry in fs::read_dir(&dir).unwrap() {
        let entry = entry.unwrap();
        assert!(
            entry.file_type().unwrap().is_file(),
            "{}",
            entry.path().display()
        );
    }
}

#[test]
fn t19_02_store_json_has_format_1_and_26_char_store_id() {
    let dir = tempfile_dir();
    store::init(&dir, &new_id(), "2026-11-19T09:00:00Z").unwrap();
    let info = store::open(&dir).unwrap();
    assert_eq!(info.format, 1);
    assert_eq!(info.store_id.len(), 26);
    assert_eq!(info.store_id, new_id());
}

#[test]
fn t19_03_format_2_refused_with_format_unsupported_nothing_written() {
    let dir = tempfile_dir();
    fs::write(
        dir.join("store.json"),
        r#"{"format":2,"storeId":"aaaaaaaaaaaaaaaaaaaaaaaaaa","created":"2026-11-19T09:00:00Z"}"#,
    )
    .unwrap();
    assert_eq!(
        store::open(&dir).unwrap_err(),
        store::Error::FormatUnsupported(2)
    );
    // Nothing else written by open.
    assert!(!dir.join(".gitattributes").exists());
}

#[test]
fn t19_04_unknown_files_ignored_not_modified() {
    assert!(store::is_ignored("notes.txt"));
    assert!(store::is_ignored(".DS_Store"));
    assert!(!store::is_ignored("store.json"));
    assert!(!store::is_ignored("devices.json"));
    assert!(!store::is_ignored("devices.sig"));
    assert!(!store::is_ignored(&format!("{}.arg", new_id())));
    assert!(!store::is_ignored(&format!("pending-{}.json", new_id())));
}

#[test]
fn t19_05_entry_file_with_invalid_id_is_ignored() {
    assert!(store::is_ignored("not-an-id.arg"));
    assert!(store::is_ignored("ABC.arg"));
    assert!(!store::is_ignored(&format!("{}.arg", new_id())));
}

#[test]
fn t19_06_missing_store_json_reported_as_not_a_store() {
    let dir = tempfile_dir();
    assert_eq!(store::open(&dir).unwrap_err(), store::Error::NotAStore);
}

#[test]
fn store_error_displays_carry_no_paths_or_contents() {
    assert_eq!(format!("{}", store::Error::NotAStore), "not a store");
    assert_eq!(
        format!("{}", store::Error::FormatUnsupported(2)),
        "unsupported store format 2"
    );
    assert_eq!(
        format!("{}", store::Error::Invalid("created")),
        "invalid store: created"
    );
    assert_eq!(
        format!("{}", store::Error::Io("write store.json")),
        "store io error: write store.json"
    );
}

#[test]
fn init_refuses_empty_created_and_escapes_special_characters() {
    let dir = tempfile_dir();
    assert_eq!(
        store::init(&dir, &new_id(), "").unwrap_err(),
        store::Error::Invalid("created")
    );
    // A timestamp containing JSON metacharacters must be escaped, not
    // injected: the file still parses and round-trips verbatim.
    let hostile = "2026-11-19T09:00:00Z\",\"evil\":\"1";
    store::init(&dir, &new_id(), hostile).unwrap();
    let info = store::open(&dir).unwrap();
    assert_eq!(info.created, hostile);
}

fn tempfile_dir() -> std::path::PathBuf {
    let mut dir = std::env::temp_dir();
    dir.push(format!(
        "argus-t19-{}-{}",
        std::process::id(),
        rand_suffix()
    ));
    // Clean any previous run, then create.
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn rand_suffix() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let n = N.fetch_add(1, Ordering::SeqCst);
    // Unique per test invocation within this process.
    format!(
        "{}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        n
    )
}
