//! Data folder and permissions (spec 01 data folder).
//!
//! `ARGUS_HOME` overrides the location (used by tests). Otherwise the
//! default macOS path `~/Library/Application Support/Argus/` is used.
//! Folders are mode 0700, files written by the core are mode 0600.
//! An existing folder with looser permissions is tightened to 0700.
//! A symlink at the data folder path is refused.

use std::fmt;
use std::path::{Path, PathBuf};

/// Data folder failure. Never carries secrets or paths inside the store.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    SymlinkRefused,
    Invalid(&'static str),
    Io(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::SymlinkRefused => write!(f, "data folder is a symlink"),
            Error::Invalid(reason) => write!(f, "invalid data folder: {reason}"),
            Error::Io(reason) => write!(f, "data folder io error: {reason}"),
        }
    }
}

impl std::error::Error for Error {}

/// Default macOS data folder for the given home directory.
pub fn default_path(home: &Path) -> PathBuf {
    home.join("Library/Application Support/Argus")
}

/// Resolve the data folder: `ARGUS_HOME` when set and non-empty,
/// otherwise the default path under the current user's home.
pub fn resolve() -> PathBuf {
    resolve_with(
        std::env::var("ARGUS_HOME").ok(),
        &std::env::var("HOME").unwrap_or_default(),
    )
}

/// Resolve with explicit inputs (test seam; `resolve` reads the environment).
pub fn resolve_with(argus_home: Option<String>, home: &str) -> PathBuf {
    if let Some(val) = argus_home {
        if !val.is_empty() {
            return PathBuf::from(val);
        }
    }
    default_path(Path::new(home))
}

/// Create the data folder with mode 0700, tightening existing loose
/// permissions. Refuses symlinks at the final path.
pub fn ensure_dir(path: &Path) -> Result<(), Error> {
    if path.as_os_str().is_empty() {
        return Err(Error::Invalid("empty path"));
    }
    if is_symlink(path) {
        return Err(Error::SymlinkRefused);
    }
    std::fs::create_dir_all(path).map_err(|_| Error::Io("create dir"))?;
    if is_symlink(path) {
        return Err(Error::SymlinkRefused);
    }
    chmod(path, 0o700).map_err(|_| Error::Io("chmod dir"))?;
    Ok(())
}

/// Write `bytes` to `path`, ensuring the file has mode 0600.
///
/// Creates the file with 0600 from the start (via `OpenOptions`) so there is
/// no window where a fresh file is readable by others before `chmod` runs.
pub fn write_file(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            ensure_dir(parent)?;
        }
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path).map_err(|_| Error::Io("write file"))?;
    std::io::Write::write_all(&mut file, bytes).map_err(|_| Error::Io("write file"))?;
    file.sync_all().map_err(|_| Error::Io("sync file"))?;
    drop(file);
    chmod(path, 0o600).map_err(|_| Error::Io("chmod file"))?;
    Ok(())
}

fn is_symlink(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
}

#[cfg(unix)]
fn chmod(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn chmod(_path: &Path, _mode: u32) -> std::io::Result<()> {
    Ok(())
}
