//! T3.3 fetch and push, refusal checks (spec 04 sections 4.8, 4.1).
//!
//! Remote interaction goes through the production `Backend` API only, using
//! local bare repositories as the remote (spec 01 allows SSH/HTTPS; tests
//! use temp dirs through the git backend, never `file://` URLs).

use std::fs;
use std::path::{Path, PathBuf};
use vault_core::git::{Author, Backend, Libgit2Backend, SystemBackend};

fn author() -> Author {
    Author::new("Argus Test", "argus-test@example.com").unwrap()
}

fn tmp(suffix: &str) -> PathBuf {
    let mut dir = std::env::temp_dir();
    dir.push(format!(
        "argus-t33-{}-{}-{}",
        std::process::id(),
        suffix,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn backends() -> Vec<(&'static str, Box<dyn Backend>)> {
    vec![
        ("system", Box::new(SystemBackend)),
        ("libgit2", Box::new(Libgit2Backend)),
    ]
}

fn bare(path: &Path) {
    let status = std::process::Command::new("git")
        .args(["init", "--bare", "-b", "master"])
        .arg(path)
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
fn t33_01_fetch_and_push_against_local_bare_succeed() {
    for (name, b) in backends() {
        let remote = tmp(&format!("remote-{name}"));
        bare(&remote);
        // Seed the remote without cloning it empty.
        let local = tmp(&format!("local-{name}"));
        b.init(&local).unwrap();
        b.add_remote(&local, "origin", remote.to_str().unwrap())
            .unwrap();
        fs::write(local.join("store.json"), "{\"format\":1}").unwrap();
        b.commit(&local, &author(), "init").unwrap();
        b.push(&local, "origin").unwrap();
        // Mutate via a second clone, push, then fetch here.
        let other = tmp(&format!("other-{name}"));
        // Remove the pre-created dir so clone creates it.
        let _ = fs::remove_dir_all(&other);
        b.clone_repo(&remote, &other).unwrap();
        fs::write(other.join("extra.txt"), "hello").unwrap();
        b.commit(&other, &author(), "update").unwrap();
        b.push(&other, "origin").unwrap();
        b.fetch(&local, "origin").unwrap();
    }
}

#[test]
fn t33_02_push_rejected_as_non_fast_forward_is_reported_as_rejected() {
    for (name, b) in backends() {
        let remote = tmp(&format!("rej-remote-{name}"));
        bare(&remote);
        let a = tmp(&format!("rej-a-{name}"));
        b.init(&a).unwrap();
        b.add_remote(&a, "origin", remote.to_str().unwrap())
            .unwrap();
        fs::write(a.join("f.txt"), "one").unwrap();
        b.commit(&a, &author(), "init").unwrap();
        b.push(&a, "origin").unwrap();
        let c = tmp(&format!("rej-b-{name}"));
        let _ = fs::remove_dir_all(&c);
        b.clone_repo(&remote, &c).unwrap();
        // Diverge: commit different content on both sides.
        fs::write(a.join("f.txt"), "two-a").unwrap();
        b.commit(&a, &author(), "update").unwrap();
        b.push(&a, "origin").unwrap();
        fs::write(c.join("f.txt"), "two-b").unwrap();
        b.commit(&c, &author(), "update").unwrap();
        let err = b.push(&c, "origin").unwrap_err();
        assert_eq!(err, vault_core::git::Error::Rejected, "{name}");
    }
}

#[test]
fn t33_03_shallow_clone_is_refused() {
    for (name, b) in backends() {
        let remote = tmp(&format!("sh-remote-{name}"));
        bare(&remote);
        let seed = tmp(&format!("sh-seed-{name}"));
        b.init(&seed).unwrap();
        b.add_remote(&seed, "origin", remote.to_str().unwrap())
            .unwrap();
        fs::write(seed.join("a.txt"), "one").unwrap();
        b.commit(&seed, &author(), "init").unwrap();
        fs::write(seed.join("b.txt"), "two").unwrap();
        b.commit(&seed, &author(), "update").unwrap();
        b.push(&seed, "origin").unwrap();
        let shallow = tmp(&format!("sh-clone-{name}"));
        let _ = fs::remove_dir_all(&shallow);
        b.clone_shallow(&remote, &shallow).unwrap();
        assert!(b.is_shallow(&shallow), "{name}");
        // The refusal check itself: shallow checkouts must be rejected.
        assert_eq!(
            vault_core::git::check_not_shallow(&shallow).unwrap_err(),
            vault_core::git::Error::Shallow,
            "{name}"
        );
    }
}

#[test]
fn t33_04_remote_with_files_but_no_store_json_is_refused_for_init() {
    let dir = tmp("nostore");
    fs::write(dir.join("README.md"), "hello").unwrap();
    let err = vault_core::git::classify_init_source(&dir).unwrap_err();
    assert_eq!(err, vault_core::git::Error::RemoteHasFilesWithoutStore);
}

#[test]
fn t33_05_empty_remote_is_accepted_for_init() {
    let dir = tmp("empty");
    assert_eq!(
        vault_core::git::classify_init_source(&dir).unwrap(),
        vault_core::git::InitSource::Empty
    );
    let dir2 = tmp("withstore");
    fs::write(dir2.join("store.json"), "{\"format\":1}").unwrap();
    assert_eq!(
        vault_core::git::classify_init_source(&dir2).unwrap(),
        vault_core::git::InitSource::HasStore
    );
    // A `.git` entry is ignored when classifying.
    let gitdir = tmp("gitdir");
    fs::create_dir(gitdir.join(".git")).unwrap();
    assert_eq!(
        vault_core::git::classify_init_source(&gitdir).unwrap(),
        vault_core::git::InitSource::Empty
    );
}

#[test]
fn t33_07_error_text_and_non_shallow_checkout() {
    use vault_core::git::Error;
    for e in [
        Error::Rejected,
        Error::Shallow,
        Error::RemoteHasFilesWithoutStore,
        Error::InvalidAuthor,
        Error::EmptyCommit,
        Error::NotARepo,
        Error::Git("x"),
    ] {
        let s = format!("{e}");
        assert!(!s.is_empty());
        let dbg = format!("{e:?}");
        assert!(!dbg.is_empty());
    }
    for (name, b) in backends() {
        let dir = tmp(&format!("notshallow-{name}"));
        b.init(&dir).unwrap();
        assert!(!b.is_shallow(&dir), "{name}");
        vault_core::git::check_not_shallow(&dir).unwrap();
    }
}

#[test]
fn t33_08_push_with_no_commits_is_accepted_as_noop() {
    for (name, b) in backends() {
        let remote = tmp(&format!("noop-remote-{name}"));
        bare(&remote);
        let local = tmp(&format!("noop-local-{name}"));
        b.init(&local).unwrap();
        b.add_remote(&local, "origin", remote.to_str().unwrap())
            .unwrap();
        // No commit yet: first-time use. Push must succeed without sending
        // anything, not fail.
        b.push(&local, "origin").unwrap();
        // The remote is still empty and the local repo unchanged.
        b.push(&local, "origin").unwrap();
    }
}

#[test]
fn t33_06_push_sends_only_commits_no_entry_plaintext_in_pack() {
    for (name, b) in backends() {
        let remote = tmp(&format!("pack-remote-{name}"));
        bare(&remote);
        let local = tmp(&format!("pack-local-{name}"));
        b.init(&local).unwrap();
        b.add_remote(&local, "origin", remote.to_str().unwrap())
            .unwrap();
        let secret = "SECRET-PLAINTEXT-ENTRY-BODY-9f8e7d6c5b";
        fs::write(local.join("entry.arg"), "ciphertext-envelope-bytes").unwrap();
        // Plaintext sits in an uncommitted, untracked helper file: it must
        // never reach the remote.
        fs::write(local.join("scratch.txt"), secret).unwrap();
        fs::remove_file(local.join("scratch.txt")).unwrap();
        fs::write(local.join("store.json"), "{\"format\":1}").unwrap();
        b.commit(&local, &author(), "init").unwrap();
        b.push(&local, "origin").unwrap();
        // Fresh clone must not contain the plaintext anywhere.
        let clone = tmp(&format!("pack-clone-{name}"));
        b.clone_repo(&remote, &clone).unwrap();
        assert!(!clone.join("scratch.txt").exists(), "{name}");
        // Scan every file under .git/objects for the secret bytes.
        let mut found = false;
        let mut stack = vec![remote.join("objects")];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = fs::read_dir(&dir) else {
                continue;
            };
            for e in entries.flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else if let Ok(bytes) = fs::read(&p) {
                    if bytes.windows(secret.len()).any(|w| w == secret.as_bytes()) {
                        found = true;
                    }
                }
            }
        }
        assert!(!found, "{name}: plaintext leaked into pack");
    }
}
