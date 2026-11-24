//! Network error policy (T3.4; spec 04 section 4.8; 08 test 20).
//!
//! A network failure is retried up to [`MAX_ATTEMPTS`] total attempts, then
//! the core returns a decision request ([`Error::RemoteUnreachable`], whose
//! [`Error::should_ask`] is true). Retry lives here in the core; the actual
//! asking lives in the UI or CLI. An auth failure ([`Attempt::Rejected`])
//! is [`Error::RemoteRejected`] and is never retried.
//!
//! Both the operation and the backoff are injected parameters, so tests
//! never touch the network and never sleep: the backoff callback records
//! the failed attempt number (1-based) instead of sleeping.

use std::fmt;

/// Total attempts per operation: 1 initial try plus up to 2 retries.
pub const MAX_ATTEMPTS: u32 = 3;

/// One attempt's outcome, as classified by the caller (fetch, push, or any
/// future remote operation). Retryable network failures are `Unreachable`;
/// auth failures are `Rejected`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attempt {
    Unreachable,
    Rejected,
}

/// Remote failure returned to the caller. Carries only counts and static
/// reasons, never secrets or entry contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The remote stayed unreachable after [`MAX_ATTEMPTS`] attempts. The
    /// caller must ask the user whether to retry later.
    RemoteUnreachable { attempts: u32 },
    /// Auth failure. Never retried; the caller reports a credential problem.
    RemoteRejected,
}

impl Error {
    /// True when the caller should ask the user whether to retry later.
    /// Only unreachable remotes ask; rejections do not.
    pub fn should_ask(&self) -> bool {
        matches!(self, Error::RemoteUnreachable { .. })
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::RemoteUnreachable { attempts } => {
                write!(f, "remote unreachable after {attempts} attempts")
            }
            Error::RemoteRejected => write!(f, "remote rejected the request"),
        }
    }
}

impl std::error::Error for Error {}

/// Run `op` until it succeeds, a rejection aborts, or [`MAX_ATTEMPTS`]
/// unreachable failures accumulate. `on_backoff` is called with the failed
/// attempt number (1-based) after each retryable failure except the last;
/// production passes a sleeper, tests pass a recorder.
pub fn retry<T>(
    mut op: impl FnMut() -> Result<T, Attempt>,
    mut on_backoff: impl FnMut(u32),
) -> Result<T, Error> {
    let mut attempts = 0u32;
    loop {
        attempts += 1;
        match op() {
            Ok(v) => return Ok(v),
            Err(Attempt::Rejected) => return Err(Error::RemoteRejected),
            Err(Attempt::Unreachable) => {
                if attempts >= MAX_ATTEMPTS {
                    return Err(Error::RemoteUnreachable { attempts });
                }
                on_backoff(attempts);
            }
        }
    }
}
