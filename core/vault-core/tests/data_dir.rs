//! T1.10 data folder and permissions tests (spec 01 data folder).

use std::fs;
use std::os::unix::fs::PermissionsExt;
use vault_core::data_dir;

fn unique_base(tag: &str) -> std::path::PathBuf {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let mut dir = std::env::temp_dir();
    dir.push(format!(
        "argus-t110-{}-{}-{}-{}",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        n
    ));
    let _ = fs::remove_dir_all(&dir);
    dir
}

#[test]
fn t110_01_folder_created_with_mode_0700() {
    let dir = unique_base("create");
    data_dir::ensure_dir(&dir).unwrap();
    assert!(dir.is_dir());
    let mode = fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn t110_02_file_written_by_core_has_mode_0600() {
    let dir = unique_base("file");
    data_dir::ensure_dir(&dir).unwrap();
    let path = dir.join("device.key");
    data_dir::write_file(&path, b"test-bytes").unwrap();
    let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    assert_eq!(fs::read(&path).unwrap(), b"test-bytes");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn t110_03_argus_home_overrides_location() {
    let dir = unique_base("home");
    std::env::set_var("ARGUS_HOME", &dir);
    let resolved = data_dir::resolve();
    std::env::remove_var("ARGUS_HOME");
    assert_eq!(resolved, dir);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn t110_04_existing_loose_folder_is_tightened_to_0700() {
    // Decision: tighten (chmod to 0700), not refuse. Recorded in test name.
    let dir = unique_base("tighten");
    fs::create_dir_all(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o777)).unwrap();
    data_dir::ensure_dir(&dir).unwrap();
    let mode = fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn t110_05_symlink_at_data_folder_is_refused() {
    let target = unique_base("target");
    fs::create_dir_all(&target).unwrap();
    let link = unique_base("link");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let err = data_dir::ensure_dir(&link).unwrap_err();
    assert_eq!(err, data_dir::Error::SymlinkRefused);
    let _ = fs::remove_dir_all(&target);
    let _ = fs::remove_file(&link);
}

#[test]
fn t110_06_default_macos_path_under_app_support() {
    let home = std::path::Path::new("/Users/alice");
    assert_eq!(
        data_dir::default_path(home),
        std::path::PathBuf::from("/Users/alice/Library/Application Support/Argus")
    );
}

#[test]
fn t110_07_empty_argus_home_falls_back_to_default() {
    assert_eq!(
        data_dir::resolve_with(Some(String::new()), "/Users/alice"),
        std::path::PathBuf::from("/Users/alice/Library/Application Support/Argus")
    );
    assert_eq!(
        data_dir::resolve_with(None, "/Users/alice"),
        std::path::PathBuf::from("/Users/alice/Library/Application Support/Argus")
    );
    assert_eq!(
        data_dir::resolve_with(Some("/tmp/custom".to_string()), "/Users/alice"),
        std::path::PathBuf::from("/tmp/custom")
    );
}

#[test]
fn t110_08_empty_path_is_invalid() {
    assert_eq!(
        data_dir::ensure_dir(std::path::Path::new("")).unwrap_err(),
        data_dir::Error::Invalid("empty path")
    );
}

#[test]
fn t110_09_write_file_creates_missing_parent() {
    let dir = unique_base("nested");
    let path = dir.join("sub").join("device.key");
    data_dir::write_file(&path, b"nested").unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"nested");
    #[cfg(unix)]
    {
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn t110_10_error_display_has_no_paths() {
    assert_eq!(
        data_dir::Error::SymlinkRefused.to_string(),
        "data folder is a symlink"
    );
    assert_eq!(
        data_dir::Error::Invalid("empty path").to_string(),
        "invalid data folder: empty path"
    );
    assert_eq!(
        data_dir::Error::Io("create dir").to_string(),
        "data folder io error: create dir"
    );
}
