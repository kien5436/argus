//! Remote URLs, credentials, host keys (T3.2; spec 04 remote, 01 credentials).
//!
//! URL forms: scp-like `user@host:path`, `ssh://`, `https://` (spec 01:
//! remote over SSH or HTTPS only). Any URL carrying embedded credentials
//! (`user:password@`) is refused: HTTPS tokens travel as an
//! `Authorization` header built from SecureStorage, never in the URL.
//! SSH host keys are checked against `~/.ssh/known_hosts` content passed
//! in by the caller; unknown or changed keys fail.

use std::fmt;

use crate::secrets::SecretBytes;
use crate::secure_storage::SecureStorage;

/// A parsed git remote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteUrl {
    Ssh {
        user: String,
        host: String,
        path: String,
    },
    Https {
        host: String,
        path: String,
    },
}

impl RemoteUrl {
    /// Original-form string (never contains credentials: embedded
    /// credentials are refused at parse time).
    pub fn as_str(&self) -> String {
        match self {
            RemoteUrl::Ssh { user, host, path } => format!("{user}@{host}:{path}"),
            RemoteUrl::Https { host, path } => format!("https://{host}/{path}"),
        }
    }

    pub fn host(&self) -> &str {
        match self {
            RemoteUrl::Ssh { host, .. } => host,
            RemoteUrl::Https { host, .. } => host,
        }
    }

    pub fn parse(s: &str) -> Result<RemoteUrl, Error> {
        if let Some(rest) = s.strip_prefix("ssh://") {
            // ssh://[user@]host/path ; userinfo with ':' is embedded credentials.
            let (authority, path) = rest.split_once('/').ok_or(Error::Invalid)?;
            if authority.is_empty() || path.is_empty() {
                return Err(Error::Invalid);
            }
            if authority.contains('@') {
                // userinfo present: split user part before '@'
                let at = authority.rfind('@').unwrap();
                let userinfo = &authority[..at];
                let host = &authority[at + 1..];
                if userinfo.contains(':') {
                    return Err(Error::EmbeddedCredentials);
                }
                if userinfo.is_empty() || host.is_empty() {
                    return Err(Error::Invalid);
                }
                let _ = userinfo;
                return Ok(RemoteUrl::Ssh {
                    user: userinfo.to_string(),
                    host: host.to_string(),
                    path: path.to_string(),
                });
            }
            if authority.contains(':') {
                return Err(Error::EmbeddedCredentials);
            }
            return Ok(RemoteUrl::Ssh {
                user: "git".to_string(),
                host: authority.to_string(),
                path: path.to_string(),
            });
        }
        if let Some(rest) = s.strip_prefix("https://") {
            // https://host/path ; any '@' before the first '/' is embedded credentials.
            let (authority, path) = rest.split_once('/').ok_or(Error::Invalid)?;
            if authority.is_empty() || path.is_empty() {
                return Err(Error::Invalid);
            }
            if authority.contains('@') {
                return Err(Error::EmbeddedCredentials);
            }
            if authority.contains(':') {
                return Err(Error::EmbeddedCredentials);
            }
            return Ok(RemoteUrl::Https {
                host: authority.to_lowercase(),
                path: path.to_string(),
            });
        }
        // scp-like: user@host:path (no scheme, exactly one ':', no '/').
        if s.contains("://") {
            return Err(Error::UnsupportedScheme);
        }
        let (left, path) = s.split_once(':').ok_or(Error::Invalid)?;
        if left.is_empty() || path.is_empty() || path.starts_with('/') {
            return Err(Error::Invalid);
        }
        let (user, host) = left.split_once('@').ok_or(Error::Invalid)?;
        if user.is_empty() || host.is_empty() || user.contains('/') || host.contains('/') {
            return Err(Error::Invalid);
        }
        if user.contains(':') || host.contains(':') {
            return Err(Error::EmbeddedCredentials);
        }
        Ok(RemoteUrl::Ssh {
            user: user.to_string(),
            host: host.to_string(),
            path: path.to_string(),
        })
    }
}

/// Remote URL failure. No host keys or secrets inside.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Invalid,
    EmbeddedCredentials,
    UnsupportedScheme,
    StorageUnavailable,
    CorruptCredential,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Invalid => write!(f, "invalid remote URL"),
            Error::EmbeddedCredentials => write!(f, "remote URL must not contain credentials"),
            Error::UnsupportedScheme => write!(f, "unsupported remote scheme"),
            Error::StorageUnavailable => write!(f, "secure storage unavailable"),
            Error::CorruptCredential => write!(f, "stored credential is corrupt"),
        }
    }
}

impl std::error::Error for Error {}

/// HTTPS credential: username plus bearer token. Never prints contents.
pub struct GitCredential {
    username: String,
    token: SecretBytes,
}

impl GitCredential {
    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn token(&self) -> &SecretBytes {
        &self.token
    }
}

impl fmt::Debug for GitCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GitCredential([redacted])")
    }
}

impl fmt::Display for GitCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

/// Load the HTTPS credential for `host` from SecureStorage key
/// `git-https-<host>` (stored as `username\ntoken`). Returns `None` when
/// absent. Production passes the platform Keychain wrapper; tests pass the
/// in-memory double through the same parameter.
pub fn load_https_credential(
    storage: &impl SecureStorage,
    host: &str,
) -> Result<Option<GitCredential>, Error> {
    let key = format!("git-https-{}", host.to_lowercase());
    let raw = storage
        .load_key(&key)
        .map_err(|_| Error::StorageUnavailable)?;
    let Some(bytes) = raw else { return Ok(None) };
    let text = String::from_utf8(bytes).map_err(|_| Error::CorruptCredential)?;
    let Some((user, token)) = text.split_once('\n') else {
        return Err(Error::CorruptCredential);
    };
    if user.is_empty() || token.is_empty() {
        return Err(Error::CorruptCredential);
    }
    Ok(Some(GitCredential {
        username: user.to_string(),
        token: SecretBytes::new(token.as_bytes().to_vec()),
    }))
}

/// Build the `Authorization: Bearer <token>` header value for an HTTPS
/// request. The token never appears in a URL.
pub fn https_auth_header(cred: &GitCredential) -> (&'static str, SecretBytes) {
    let mut v = b"Bearer ".to_vec();
    v.extend_from_slice(cred.token.expose());
    ("Authorization", SecretBytes::new(v))
}

/// SSH host-key check failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKeyError {
    UnknownHost,
    Mismatch,
}

impl fmt::Display for HostKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HostKeyError::UnknownHost => write!(f, "unknown SSH host key"),
            HostKeyError::Mismatch => write!(f, "SSH host key changed"),
        }
    }
}

impl std::error::Error for HostKeyError {}

/// Verify `presented_key_base64` for `host` against `known_hosts` file
/// content (`<hosts> <keytype> <base64> [comment]` per line). Unknown hosts
/// and changed keys both fail; hashed (`|1|...`) entries never match.
pub fn verify_ssh_host_key(
    host: &str,
    presented_key_base64: &str,
    known_hosts: &str,
) -> Result<(), HostKeyError> {
    let mut found_host = false;
    for line in known_hosts.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let (Some(hosts), Some(_kt), Some(key)) = (parts.next(), parts.next(), parts.next()) else {
            continue;
        };
        if hosts.starts_with('|') {
            continue;
        }
        if !hosts.split(',').any(|h| h == host) {
            continue;
        }
        found_host = true;
        if key == presented_key_base64 {
            return Ok(());
        }
    }
    if found_host {
        Err(HostKeyError::Mismatch)
    } else {
        Err(HostKeyError::UnknownHost)
    }
}
