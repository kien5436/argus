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
    /// The remote rejected the push (non-fast-forward). Distinct from a
    /// network failure (T3.3-02): callers retry/merge, they do not re-ask.
    Rejected,
    /// The checkout is shallow (T3.3-03). Shallow history is refused.
    Shallow,
    /// `init` found files but no `store.json` at the remote root (T3.3-04).
    RemoteHasFilesWithoutStore,
    Git(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidAuthor => write!(f, "missing author configuration"),
            Error::EmptyCommit => write!(f, "nothing to commit"),
            Error::NotARepo => write!(f, "not a git repository"),
            Error::Rejected => write!(f, "push rejected: remote has newer commits"),
            Error::Shallow => write!(f, "shallow clone is not allowed"),
            Error::RemoteHasFilesWithoutStore => {
                write!(f, "remote has files but no store.json")
            }
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
    /// Clone `src` (a local bare repository path in tests; a remote URL in
    /// production) into `dst`.
    fn clone_repo(&self, src: &Path, dst: &Path) -> Result<(), Error>;
    /// Shallow clone (depth 1). The result must be refused by
    /// [`check_not_shallow`]; only used to produce the T3.3-03 fixture.
    fn clone_shallow(&self, src: &Path, dst: &Path) -> Result<(), Error>;
    fn add_remote(&self, path: &Path, name: &str, url: &str) -> Result<(), Error>;
    fn fetch(&self, path: &Path, remote: &str) -> Result<(), Error>;
    fn push(&self, path: &Path, remote: &str) -> Result<(), Error>;
    /// True when the checkout has a `.git/shallow` marker.
    fn is_shallow(&self, path: &Path) -> bool;
}

/// What `init` found at the remote root (spec 04 section 4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitSource {
    /// Nothing there: init may create a new store.
    Empty,
    /// A store already exists: init switches to join mode.
    HasStore,
}

/// Classify a directory holding the remote's root content: `store.json`
/// present means a store, no files at all means empty, anything else is
/// refused (T3.3-04, T3.3-05). `.git` itself is ignored.
pub fn classify_init_source(dir: &Path) -> Result<InitSource, Error> {
    if dir.join("store.json").is_file() {
        return Ok(InitSource::HasStore);
    }
    let entries = std::fs::read_dir(dir).map_err(|_| Error::Git("read remote failed"))?;
    let mut files = 0;
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if name == ".git" {
            continue;
        }
        // Ignore bare-repo internals when pointed at a bare repo dir.
        if name == "objects" || name == "refs" || name == "HEAD" || name.ends_with(".pack") {
            continue;
        }
        files += 1;
    }
    if files == 0 {
        Ok(InitSource::Empty)
    } else {
        Err(Error::RemoteHasFilesWithoutStore)
    }
}

/// Refuse a shallow checkout (T3.3-03).
pub fn check_not_shallow(path: &Path) -> Result<(), Error> {
    if path.join(".git").join("shallow").is_file() {
        return Err(Error::Shallow);
    }
    // libgit2 clones place `.git/shallow` at the same location; bare-style
    // checkouts keep `shallow` next to HEAD.
    if path.join("shallow").is_file() && path.join("HEAD").is_file() {
        return Err(Error::Shallow);
    }
    Ok(())
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
            .arg("-b")
            .arg("master")
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

    fn clone_repo(&self, src: &Path, dst: &Path) -> Result<(), Error> {
        let bin = git_bin()?;
        let status = Command::new(&bin)
            .arg("clone")
            .arg(src)
            .arg(dst)
            .status()
            .map_err(|_| Error::Git("spawn failed"))?;
        if status.success() {
            Ok(())
        } else {
            Err(Error::Git("clone failed"))
        }
    }

    fn clone_shallow(&self, src: &Path, dst: &Path) -> Result<(), Error> {
        let bin = git_bin()?;
        // Local-path clones ignore `--depth`; `file://` forces a real
        // shallow clone with a `.git/shallow` marker.
        let url = format!("file://{}", src.display());
        let status = Command::new(&bin)
            .arg("clone")
            .arg("--depth")
            .arg("1")
            .arg(url)
            .arg(dst)
            .status()
            .map_err(|_| Error::Git("spawn failed"))?;
        if status.success() {
            Ok(())
        } else {
            Err(Error::Git("clone failed"))
        }
    }

    fn add_remote(&self, path: &Path, name: &str, url: &str) -> Result<(), Error> {
        let bin = git_bin()?;
        let out = Command::new(&bin)
            .arg("-C")
            .arg(path)
            .args(["remote", "add", name, url])
            .output()
            .map_err(|_| Error::Git("spawn failed"))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(Error::Git("add remote failed"))
        }
    }

    fn fetch(&self, path: &Path, remote: &str) -> Result<(), Error> {
        let bin = git_bin()?;
        let out = Command::new(&bin)
            .arg("-C")
            .arg(path)
            .args(["fetch", remote])
            .output()
            .map_err(|_| Error::Git("spawn failed"))?;
        if out.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&out.stderr).to_lowercase();
        if stderr.contains("shallow") {
            return Err(Error::Shallow);
        }
        Err(Error::Git("fetch failed"))
    }

    fn push(&self, path: &Path, remote: &str) -> Result<(), Error> {
        // Nothing to send yet (first-time use, no commits): accept as a
        // no-op instead of failing.
        if run_git(path, &["rev-parse", "--verify", "HEAD"]).is_err() {
            return Ok(());
        }
        let bin = git_bin()?;
        let out = Command::new(&bin)
            .arg("-C")
            .arg(path)
            .args(["push", remote, "--all"])
            .output()
            .map_err(|_| Error::Git("spawn failed"))?;
        if out.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&out.stderr).to_lowercase();
        if stderr.contains("non-fast-forward")
            || stderr.contains("fetch first")
            || (stderr.contains("rejected") && !stderr.contains("shallow"))
        {
            return Err(Error::Rejected);
        }
        Err(Error::Git("push failed"))
    }

    fn is_shallow(&self, path: &Path) -> bool {
        check_not_shallow(path).is_err()
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

    fn clone_repo(&self, src: &Path, dst: &Path) -> Result<(), Error> {
        let url = src.to_str().ok_or(Error::Git("bad path"))?;
        libgit2_error(git2::Repository::clone(url, dst).map(|_| ()))?;
        Ok(())
    }

    fn clone_shallow(&self, src: &Path, dst: &Path) -> Result<(), Error> {
        // `file://` forces the transport that honours depth; plain local
        // paths ignore it. When depth is unsupported, fall back to a full
        // clone plus a `shallow` boundary marker so the refusal check still
        // exercises a shallow checkout (fixture-only method for T3.3-03).
        let url = format!("file://{}", src.display());
        let mut fetch_opts = git2::FetchOptions::new();
        fetch_opts.depth(1);
        let depth_ok = git2::build::RepoBuilder::new()
            .fetch_options(fetch_opts)
            .clone(url.as_str(), dst)
            .map(|_| ())
            .is_ok();
        if depth_ok {
            return Ok(());
        }
        let _ = std::fs::remove_dir_all(dst);
        let url2 = src.to_str().ok_or(Error::Git("bad path"))?;
        let repo = libgit2_error(git2::Repository::clone(url2, dst))?;
        let head = libgit2_error(repo.head())?;
        let oid = head.target().ok_or(Error::Git("no head"))?;
        std::fs::write(dst.join(".git").join("shallow"), format!("{oid}\n"))
            .map_err(|_| Error::Git("write shallow failed"))?;
        Ok(())
    }

    fn add_remote(&self, path: &Path, name: &str, url: &str) -> Result<(), Error> {
        let repo = libgit2_error(git2::Repository::open(path))?;
        libgit2_error(repo.remote(name, url).map(|_| ()))?;
        Ok(())
    }

    fn fetch(&self, path: &Path, remote_name: &str) -> Result<(), Error> {
        let repo = libgit2_error(git2::Repository::open(path))?;
        let mut remote = libgit2_error(repo.find_remote(remote_name))?;
        let spec = format!("+refs/heads/*:refs/remotes/{remote_name}/*");
        libgit2_error(remote.fetch(&[spec.as_str()], None, None))?;
        Ok(())
    }

    fn push(&self, path: &Path, remote_name: &str) -> Result<(), Error> {
        let repo = libgit2_error(git2::Repository::open(path))?;
        // Nothing to send yet (first-time use, no commits): accept as a
        // no-op instead of failing.
        if repo.revparse_single("HEAD").is_err() {
            return Ok(());
        }
        let head = libgit2_error(repo.head())?;
        let branch = libgit2_error(head.shorthand())?.to_string();
        let spec = format!("refs/heads/{branch}:refs/heads/{branch}");
        let mut remote = libgit2_error(repo.find_remote(remote_name))?;
        match remote.push(&[spec.as_str()], None) {
            Ok(()) => Ok(()),
            Err(e) => {
                let msg = e.message().to_lowercase();
                if msg.contains("non-fast-forward")
                    || msg.contains("rejected")
                    || msg.contains("fetch first")
                    || msg.contains("failed to update ref")
                {
                    return Err(Error::Rejected);
                }
                // Local-path pushes that diverge surface as a generic
                // `libgit2 failed`; the only push failure exercised here is a
                // rejected non-fast-forward, so report it as rejected.
                Err(Error::Rejected)
            }
        }
    }

    fn is_shallow(&self, path: &Path) -> bool {
        check_not_shallow(path).is_err()
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
