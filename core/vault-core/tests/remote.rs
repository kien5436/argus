//! T3.2 remote URLs, credentials, host keys (spec 04 remote; 01 credentials).

use vault_core::secure_storage::InMemorySecureStorage;
use vault_core::secure_storage::SecureStorage;

fn save_https_token(storage: &mut InMemorySecureStorage, host: &str, user: &str, token: &str) {
    storage
        .save_key(
            &format!("git-https-{host}"),
            format!("{user}\n{token}").into_bytes(),
        )
        .unwrap();
}

#[test]
fn t32_01_parses_scp_ssh_and_https_remotes() {
    let r = vault_core::remote::RemoteUrl::parse("git@github.com:me/vault.git").unwrap();
    assert_eq!(r.host(), "github.com");
    assert!(matches!(r, vault_core::remote::RemoteUrl::Ssh { .. }));

    let r = vault_core::remote::RemoteUrl::parse("ssh://git@github.com/me/vault.git").unwrap();
    assert_eq!(r.host(), "github.com");

    let r = vault_core::remote::RemoteUrl::parse("https://github.com/me/vault.git").unwrap();
    assert_eq!(r.host(), "github.com");
    assert!(matches!(r, vault_core::remote::RemoteUrl::Https { .. }));
}

#[test]
fn t32_02_url_with_embedded_credentials_is_refused() {
    let err =
        vault_core::remote::RemoteUrl::parse("https://user:token@github.com/me/v.git").unwrap_err();
    assert_eq!(err, vault_core::remote::Error::EmbeddedCredentials);
    // ssh:// with userinfo is also refused.
    let err = vault_core::remote::RemoteUrl::parse("ssh://user:pass@host/x.git").unwrap_err();
    assert_eq!(err, vault_core::remote::Error::EmbeddedCredentials);
}

#[test]
fn t32_03_file_remote_is_refused() {
    // Spec 01: remotes are SSH or HTTPS only. `file://` is not a remote;
    // tests needing a local repository use a temp dir through the git
    // backend directly, never through `RemoteUrl::parse`.
    use vault_core::remote::{Error, RemoteUrl};
    assert_eq!(
        RemoteUrl::parse("file:///tmp/vault.git").unwrap_err(),
        Error::UnsupportedScheme
    );
    assert_eq!(
        RemoteUrl::parse("file://").unwrap_err(),
        Error::UnsupportedScheme
    );
}

#[test]
fn t32_04_unknown_ssh_host_key_is_never_accepted_silently() {
    let known = "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GK\n";
    let err = vault_core::remote::verify_ssh_host_key(
        "unknown.example",
        "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GK",
        known,
    )
    .unwrap_err();
    assert_eq!(err, vault_core::remote::HostKeyError::UnknownHost);
}

#[test]
fn t32_05_ssh_to_host_whose_key_changed_fails() {
    let known = "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GK\n";
    let err = vault_core::remote::verify_ssh_host_key(
        "github.com",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        known,
    )
    .unwrap_err();
    assert_eq!(err, vault_core::remote::HostKeyError::Mismatch);
    // Matching key verifies.
    vault_core::remote::verify_ssh_host_key(
        "github.com",
        "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GK",
        known,
    )
    .unwrap();
}

#[test]
fn t32_06_credentials_are_read_from_secure_storage_and_never_printed() {
    let mut s = InMemorySecureStorage::new();
    save_https_token(&mut s, "github.com", "octocat", "ghp_secrettoken123");
    let cred = vault_core::remote::load_https_credential(&s, "github.com")
        .unwrap()
        .expect("credential");
    assert_eq!(cred.username(), "octocat");
    assert_eq!(cred.token().expose(), b"ghp_secrettoken123");
    // Debug/Display never reveal the token or username secret value.
    let dbg = format!("{cred:?}");
    assert!(!dbg.contains("ghp_secrettoken123"), "token leaked in Debug");
    assert!(!dbg.contains("octocat"), "username leaked in Debug");
    let disp = format!("{cred}");
    assert!(!disp.contains("ghp_secrettoken123"));
    // Missing host returns None.
    assert!(vault_core::remote::load_https_credential(&s, "gitlab.com")
        .unwrap()
        .is_none());
}

#[test]
fn t32_07_https_token_is_sent_as_header_not_in_url() {
    let mut s = InMemorySecureStorage::new();
    save_https_token(&mut s, "github.com", "octocat", "tok123");
    let cred = vault_core::remote::load_https_credential(&s, "github.com")
        .unwrap()
        .unwrap();
    let (name, value) = vault_core::remote::https_auth_header(&cred);
    assert_eq!(name, "Authorization");
    // Header value is `Bearer <token>` bytes; the URL itself carries nothing.
    assert_eq!(value.expose(), b"Bearer tok123");
    let url = vault_core::remote::RemoteUrl::parse("https://github.com/me/vault.git").unwrap();
    assert!(!url.as_str().contains("tok123"));
}

#[test]
fn t32_08_invalid_and_unsupported_remotes_are_refused() {
    use vault_core::remote::{Error, RemoteUrl};
    // Missing path segments, bad scp shapes, non-SSH/HTTPS schemes.
    assert_eq!(RemoteUrl::parse("ssh://host").unwrap_err(), Error::Invalid);
    assert_eq!(RemoteUrl::parse("ssh:///path").unwrap_err(), Error::Invalid);
    assert_eq!(
        RemoteUrl::parse("ssh://@host/path").unwrap_err(),
        Error::Invalid
    );
    assert_eq!(
        RemoteUrl::parse("ssh://user@/path").unwrap_err(),
        Error::Invalid
    );
    assert_eq!(
        RemoteUrl::parse("https://host").unwrap_err(),
        Error::Invalid
    );
    assert_eq!(
        RemoteUrl::parse("https:///path").unwrap_err(),
        Error::Invalid
    );
    assert_eq!(
        RemoteUrl::parse("no-colon-here").unwrap_err(),
        Error::Invalid
    );
    assert_eq!(RemoteUrl::parse(":path").unwrap_err(), Error::Invalid);
    assert_eq!(
        RemoteUrl::parse("user@host:/abs").unwrap_err(),
        Error::Invalid
    );
    assert_eq!(RemoteUrl::parse("user@/rel").unwrap_err(), Error::Invalid);
    assert_eq!(
        RemoteUrl::parse("ftp://host/repo.git").unwrap_err(),
        Error::UnsupportedScheme
    );
    // ssh:// with explicit user verifies and round-trips.
    let r = RemoteUrl::parse("ssh://git@host/x.git").unwrap();
    assert_eq!(r.as_str(), "git@host:x.git");
    assert!(matches!(r, RemoteUrl::Ssh { .. }));
    // ssh:// without a user defaults to git; https:// without port-like colon.
    let r = RemoteUrl::parse("ssh://host/x.git").unwrap();
    assert_eq!(r.as_str(), "git@host:x.git");
    assert_eq!(
        RemoteUrl::parse("ssh://host:22/x.git").unwrap_err(),
        Error::EmbeddedCredentials
    );
    assert_eq!(
        RemoteUrl::parse("https://HOST/Me/V.git").unwrap().host(),
        "host"
    );
    assert_eq!(
        RemoteUrl::parse("user@host:path").unwrap().as_str(),
        "user@host:path"
    );
    // Error display never carries secrets.
    for e in [
        Error::Invalid,
        Error::EmbeddedCredentials,
        Error::UnsupportedScheme,
        Error::StorageUnavailable,
        Error::CorruptCredential,
    ] {
        let s = format!("{e}");
        assert!(!s.contains("tok"), "{e:?}");
    }
    let hk = vault_core::remote::HostKeyError::UnknownHost;
    assert!(!format!("{hk}").is_empty());
    let hk = vault_core::remote::HostKeyError::Mismatch;
    assert!(!format!("{hk}").is_empty());
}

#[test]
fn t32_09_corrupt_credentials_and_known_hosts_edge_cases() {
    use vault_core::secure_storage::SecureStorage;
    // No newline separator.
    let mut s = InMemorySecureStorage::new();
    s.save_key("git-https-example.com", b"nouser".to_vec())
        .unwrap();
    assert_eq!(
        vault_core::remote::load_https_credential(&s, "example.com").unwrap_err(),
        vault_core::remote::Error::CorruptCredential
    );
    // Empty username / empty token.
    s.save_key("git-https-example.com", b"\ntok".to_vec())
        .unwrap();
    assert_eq!(
        vault_core::remote::load_https_credential(&s, "example.com").unwrap_err(),
        vault_core::remote::Error::CorruptCredential
    );
    s.save_key("git-https-example.com", b"user\n".to_vec())
        .unwrap();
    assert_eq!(
        vault_core::remote::load_https_credential(&s, "example.com").unwrap_err(),
        vault_core::remote::Error::CorruptCredential
    );
    // Non-UTF8 bytes.
    s.save_key("git-https-example.com", vec![0xff, 0xfe])
        .unwrap();
    assert_eq!(
        vault_core::remote::load_https_credential(&s, "example.com").unwrap_err(),
        vault_core::remote::Error::CorruptCredential
    );
    // Host lookup is case-insensitive.
    save_https_token(&mut s, "github.com", "u", "t");
    assert!(vault_core::remote::load_https_credential(&s, "GITHUB.COM")
        .unwrap()
        .is_some());

    // known_hosts: comments, blanks, hashed entries, comma lists, malformed lines.
    let known = "# comment\n\n|1|salt|hash ssh-ed25519 AAAA\nmalformedline\n".to_string()
        + "a.example,b.example ssh-ed25519 AAAAKEY\n";
    assert_eq!(
        vault_core::remote::verify_ssh_host_key("a.example", "AAAAKEY", &known).unwrap(),
        ()
    );
    assert_eq!(
        vault_core::remote::verify_ssh_host_key("b.example", "AAAAKEY", &known).unwrap(),
        ()
    );
    // Hashed entries never match: host behind a hash is unknown.
    assert_eq!(
        vault_core::remote::verify_ssh_host_key("hashed.example", "AAAA", &known).unwrap_err(),
        vault_core::remote::HostKeyError::UnknownHost
    );
}
