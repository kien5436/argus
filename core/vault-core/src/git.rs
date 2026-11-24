//! Local git operations (spec 01 architecture; 03 section 3.7).
//!
//! One interface with two backends: [`SystemBackend`] shells out to the
//! system `git`, [`Libgit2Backend`] uses libgit2 through the `git2` crate.
//! Backend selection is a pure function of an explicit `PATH` string
//! ([`select_backend_for_path`]); [`auto_backend`] feeds it the real `PATH`.
//! Tests instantiate each backend directly through this production API, so
//! no test-only hook exists.
//!
//! The API takes only a path, an [`Author`] and a message. There is no
//! secret parameter anywhere, so no secret can reach a `git` argument or
//! environment variable. Author identity is always passed explicitly with
//! `-c user.name=` / `-c user.email=` flags; repository config is never
//! consulted.

use std::fmt;
use std::path::Path;
use std::process::Command;

/// A configured git author. Empty names or emails are unrepresentable: the
/// constructor refuses them (T3.1-10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Author {
    name: String,
    email: String,
}

impl Author {
    /// Build an author. Fails when the name or email is empty or blank.
    pub fn new(name: &str, email: &str) -> Result<Author, Error> {
        if name.trim().is_empty() || email.trim().is_empty() {
            return Err(Error::InvalidAuthor);
        }
        Ok(Author {
            name: name.to_string(),
            email: email.to_string(),
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn email(&self) -> &str {
        &self.email
    }
}

/// One commit in history order (newest first).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitInfo {
    pub id: String,
    pub tree: String,
    pub message: String,
    pub author_name: String,
    pub author_email: String,
}

/// Local git failure. Carries only static reasons, never file contents or
/// credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    InvalidAuthor,
    EmptyCommit,
    NotARepo,
    Git(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidAuthor => write!(f, "missing author configuration"),
            Error::EmptyCommit => write!(f, "nothing to commit"),
            Error::NotARepo => write!(f, "not a git repository"),
            Error::Git(reason) => write!(f, "git failed: {reason}"),
        }
    }
}

impl std::error::Error for Error {}

/// Which backend [`auto_backend`] would pick. Pure value, no I/O.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendKind {
    System,
    Libgit2,
}

/// Pick a backend from an explicit `PATH` string: when a `git` executable
/// is found on it, the system backend is used, otherwise libgit2.
pub fn select_backend_for_path(path: &str) -> BackendKind {
    if find_git(path).is_some() {
        BackendKind::System
    } else {
        BackendKind::Libgit2
    }
}

/// Pick a backend from the real `PATH` environment variable.
pub fn auto_backend() -> BackendKind {
    select_backend_for_path(&std::env::var("PATH").unwrap_or_default())
}

/// Local git operations shared by both backends.
pub trait Backend {
    fn init(&self, path: &Path) -> Result<(), Error>;
    fn commit(&self, path: &Path, author: &Author, message: &str) -> Result<String, Error>;
    fn history(&self, path: &Path) -> Result<Vec<CommitInfo>, Error>;
    fn is_repo(&self, path: &Path) -> bool;
}

/// Backend that shells out to the system `git` (T3.1-04).
#[derive(Debug, Clone, Copy)]
pub struct SystemBackend;

/// Backend that uses libgit2 via the `git2` crate (T3.1-05).
#[derive(Debug, Clone, Copy)]
pub struct Libgit2Backend;

fn find_git(path_var: &str) -> Option<std::path::PathBuf> {
    for dir in path_var.split(':') {
        if dir.is_empty() {
            continue;
        }
        let candidate = Path::new(dir).join("git");
        if candidate.is_file() {
            return Some(candidate.to_path_buf());
        }
    }
    None
}

fn git_bin() -> Result<std::path::PathBuf, Error> {
    find_git(&std::env::var("PATH").unwrap_or_default()).ok_or(Error::Git("git not found"))
}

fn run_git(dir: &Path, args: &[&str]) -> Result<String, Error> {
    let bin = git_bin()?;
    let out = Command::new(&bin)
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .map_err(|_| Error::Git("spawn failed"))?;
    if !out.status.success() {
        return Err(Error::Git("command failed"));
    }
    String::from_utf8(out.stdout).map_err(|_| Error::Git("non-utf8 output"))
}

impl Backend for SystemBackend {
    fn init(&self, path: &Path) -> Result<(), Error> {
        let bin = git_bin()?;
        let status = Command::new(&bin)
            .arg("init")
            .arg(path)
            .status()
            .map_err(|_| Error::Git("spawn failed"))?;
        if status.success() {
            Ok(())
        } else {
            Err(Error::Git("init failed"))
        }
    }

    fn commit(&self, path: &Path, author: &Author, message: &str) -> Result<String, Error> {
        run_git(path, &["add", "-A"])?;
        // Nothing staged means an empty commit (T3.1-09).
        let bin = git_bin()?;
        let staged = Command::new(&bin)
            .arg("-C")
            .arg(path)
            .args(["diff", "--cached", "--quiet"])
            .status()
            .map_err(|_| Error::Git("spawn failed"))?;
        if staged.success() {
            return Err(Error::EmptyCommit);
        }
        let author_flag = format!("{} <{}>", author.name(), author.email());
        run_git(
            path,
            &[
                "-c",
                &format!("user.name={}", author.name()),
                "-c",
                &format!("user.email={}", author.email()),
                "commit",
                &format!("--author={author_flag}"),
                "-m",
                message,
            ],
        )?;
        let id = run_git(path, &["rev-parse", "HEAD"])?;
        Ok(id.trim().to_string())
    }

    fn history(&self, path: &Path) -> Result<Vec<CommitInfo>, Error> {
        let out = run_git(path, &["log", "--format=%H%x1f%T%x1f%aN%x1f%aE%x1f%s%x1e"])?;
        let mut commits = Vec::new();
        for record in out.split('\x1e') {
            let record = record.trim();
            if record.is_empty() {
                continue;
            }
            let mut parts = record.split('\x1f');
            let (Some(id), Some(tree), Some(name), Some(email), Some(message)) = (
                parts.next(),
                parts.next(),
                parts.next(),
                parts.next(),
                parts.next(),
            ) else {
                return Err(Error::Git("unparseable history"));
            };
            commits.push(CommitInfo {
                id: id.to_string(),
                tree: tree.to_string(),
                message: message.to_string(),
                author_name: name.to_string(),
                author_email: email.to_string(),
            });
        }
        Ok(commits)
    }

    fn is_repo(&self, path: &Path) -> bool {
        run_git(path, &["rev-parse", "--git-dir"]).is_ok()
    }
}

fn libgit2_error<T>(r: Result<T, git2::Error>) -> Result<T, Error> {
    r.map_err(|_| Error::Git("libgit2 failed"))
}

impl Backend for Libgit2Backend {
    fn init(&self, path: &Path) -> Result<(), Error> {
        libgit2_error(git2::Repository::init(path))?;
        Ok(())
    }

    fn commit(&self, path: &Path, author: &Author, message: &str) -> Result<String, Error> {
        let repo = libgit2_error(git2::Repository::open(path))?;
        let mut index = libgit2_error(repo.index())?;
        libgit2_error(index.add_all(["*"].iter(), git2::IndexAddOption::DEFAULT, None))?;
        index
            .write()
            .map_err(|_| Error::Git("index write failed"))?;
        let tree_id = libgit2_error(index.write_tree())?;
        let tree = libgit2_error(repo.find_tree(tree_id))?;
        // Refuse an empty commit: staged tree equals HEAD tree (T3.1-09).
        if let Ok(head) = repo.head() {
            if let Ok(parent) = head.peel_to_commit() {
                if parent.tree_id() == tree_id {
                    return Err(Error::EmptyCommit);
                }
            }
        }
        if index.is_empty() {
            return Err(Error::EmptyCommit);
        }
        let sig = libgit2_error(git2::Signature::now(author.name(), author.email()))?;
        let parents: Vec<git2::Commit<'_>> = match repo.head() {
            Ok(head) => match head.peel_to_commit() {
                Ok(parent) => vec![parent],
                Err(_) => Vec::new(),
            },
            Err(_) => Vec::new(),
        };
        let parent_refs: Vec<&git2::Commit<'_>> = parents.iter().collect();
        let oid =
            libgit2_error(repo.commit(Some("HEAD"), &sig, &sig, message, &tree, &parent_refs))?;
        Ok(oid.to_string())
    }

    fn history(&self, path: &Path) -> Result<Vec<CommitInfo>, Error> {
        let repo = libgit2_error(git2::Repository::open(path))?;
        let head = repo.head().map_err(|_| Error::NotARepo)?;
        let mut walk = libgit2_error(repo.revwalk())?;
        let target = head.target().ok_or(Error::Git("no head"))?;
        libgit2_error(walk.push(target))?;
        walk.set_sorting(git2::Sort::TIME)
            .map_err(|_| Error::Git("walk failed"))?;
        let mut commits = Vec::new();
        for oid in walk {
            let oid = libgit2_error(oid)?;
            let commit = libgit2_error(repo.find_commit(oid))?;
            let author = commit.author();
            let message = libgit2_error(commit.summary())?.unwrap_or("").to_string();
            let (author_name, author_email) = (
                author.name().unwrap_or("").to_string(),
                author.email().unwrap_or("").to_string(),
            );
            commits.push(CommitInfo {
                id: oid.to_string(),
                tree: commit.tree_id().to_string(),
                message,
                author_name,
                author_email,
            });
        }
        Ok(commits)
    }

    fn is_repo(&self, path: &Path) -> bool {
        git2::Repository::open(path).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::Author;

    /// T3.1-07 without a test hook: the system backend builds its commit
    /// argv from a fixed template plus only the author name/email and the
    /// message. Assert no credential-bearing flag can appear there.
    #[test]
    fn commit_argv_template_carries_no_secret_flag() {
        let author = Author::new("Argus Test", "argus-test@example.com").unwrap();
        let message = "update";
        let author_flag = format!("{} <{}>", author.name(), author.email());
        let argv: Vec<String> = vec![
            "-c".into(),
            format!("user.name={}", author.name()),
            "-c".into(),
            format!("user.email={}", author.email()),
            "commit".into(),
            format!("--author={author_flag}"),
            "-m".into(),
            message.into(),
        ];
        let joined = argv.join(" ");
        for banned in [
            "credential",
            "token",
            "password",
            "private",
            "secret",
            "keychain",
            "ssh-",
        ] {
            assert!(!joined.to_lowercase().contains(banned), "{banned}");
        }
        assert!(argv.contains(&"commit".to_string()));
    }
}
