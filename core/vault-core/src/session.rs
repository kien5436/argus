//! Unlocked session and lax-time policy (spec 05, spec 02 unlock lifecycle).
//!
//! Two policies: `FromUnlock` (CLI: fixed window from unlock) and
//! `FromInteraction` (apps: each interaction restarts the window).
//! `lax_secs == 0` disables caching: the session is never valid.
//!
//! Time comes from the [`Clock`] bound at construction. Production uses
//! [`SystemClock`] (monotonic); tests inject a manual counter. Callers never
//! pass a timestamp, so a caller cannot forge time to extend a session.

use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

use crate::device_key::DeviceKeys;

/// Default lax time: 45 seconds (spec 05).
pub const DEFAULT_LAX_SECS: u64 = 45;
/// Maximum lax time: 1 hour. Bounds key exposure in memory; spec 05 names no
/// maximum, so this is a strong default (see T2.2-07).
pub const MAX_LAX_SECS: u64 = 3600;

/// Lax-time policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    /// CLI: window counts from unlock, interactions do not extend it.
    FromUnlock,
    /// Apps: each interaction restarts the window.
    FromInteraction,
}

/// Session failure. Carries no secret text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// No usable unlocked key (never unlocked, expired, or locked).
    Locked,
    /// Lax value out of range.
    InvalidLax,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Locked => write!(f, "locked"),
            Error::InvalidLax => write!(f, "invalid lax-time"),
        }
    }
}

impl std::error::Error for Error {}

/// Monotonic time source in seconds. A genuine constructor dependency:
/// production passes [`SystemClock`], tests pass a manual counter through
/// the same [`Session::new`] parameter. There is no test-only constructor,
/// and time is never supplied per call, so callers cannot forge timestamps.
pub trait Clock: Send + Sync {
    fn now(&self) -> u64;
}

/// Monotonic production clock: seconds since first use.
#[derive(Debug)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> u64 {
        use std::sync::OnceLock;
        static T0: OnceLock<std::time::Instant> = OnceLock::new();
        T0.get_or_init(std::time::Instant::now).elapsed().as_secs()
    }
}

/// Parse a `lax-time` value: decimal integer within `0..=MAX_LAX_SECS`.
pub fn parse_lax(s: &str) -> Result<u64, Error> {
    let t = s.trim();
    if t.is_empty() {
        return Err(Error::InvalidLax);
    }
    if !t.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::InvalidLax);
    }
    let v: u64 = t.parse().map_err(|_| Error::InvalidLax)?;
    if v > MAX_LAX_SECS {
        return Err(Error::InvalidLax);
    }
    Ok(v)
}

/// An unlocked session holding the device keys in memory.
pub struct Session {
    policy: Policy,
    lax_secs: u64,
    unlock_at: Option<u64>,
    last_interaction: Option<u64>,
    keys: Option<DeviceKeys>,
    index: Option<Zeroizing<Vec<u8>>>,
    clock: Arc<dyn Clock>,
}

impl Session {
    /// Bind the session to `clock`: [`SystemClock`] in production, a manual
    /// counter in tests. The clock is fixed for the session's lifetime.
    pub fn new(policy: Policy, lax_secs: u64, clock: Arc<dyn Clock>) -> Result<Self, Error> {
        if lax_secs > MAX_LAX_SECS {
            return Err(Error::InvalidLax);
        }
        Ok(Self {
            policy,
            lax_secs,
            unlock_at: None,
            last_interaction: None,
            keys: None,
            index: None,
            clock,
        })
    }

    /// Store the unlocked keys, starting the window at the bound clock.
    pub fn unlock(&mut self, keys: DeviceKeys) {
        let now = self.clock.now();
        self.keys = Some(keys);
        self.unlock_at = Some(now);
        self.last_interaction = Some(now);
    }

    /// Record a user interaction now. Only extends `FromInteraction`.
    pub fn touch(&mut self) {
        if self.policy == Policy::FromInteraction && self.keys.is_some() {
            self.last_interaction = Some(self.clock.now());
        }
    }

    /// Placeholder for the in-memory search index (T6.2 owns the real one).
    /// Held here so `lock()` can drop it alongside the keys. Takes a
    /// pre-wrapped secret buffer so no plain-text copy crosses this API.
    pub fn set_index(&mut self, bytes: Zeroizing<Vec<u8>>) {
        self.index = Some(bytes);
    }

    pub fn has_index(&self) -> bool {
        self.index.is_some()
    }

    fn anchor(&self) -> Option<u64> {
        match self.policy {
            Policy::FromUnlock => self.unlock_at,
            Policy::FromInteraction => self.last_interaction,
        }
    }

    /// Validity at the bound clock's now. Expiry drops the keys (zeroised
    /// via `Drop`).
    pub fn is_valid(&mut self) -> bool {
        if self.lax_secs == 0 {
            return false;
        }
        let now = self.clock.now();
        let start = match (self.anchor(), self.keys.is_some()) {
            (Some(t), true) => t,
            _ => return false,
        };
        if now.wrapping_sub(start) < self.lax_secs {
            true
        } else {
            self.keys = None;
            self.index = None;
            false
        }
    }

    /// Borrow the keys if valid now, else `Locked`.
    pub fn keys(&mut self) -> Result<&DeviceKeys, Error> {
        if self.is_valid() {
            self.keys.as_ref().ok_or(Error::Locked)
        } else {
            Err(Error::Locked)
        }
    }

    /// Lock: zeroise keys and drop the index handle.
    pub fn lock(&mut self) {
        self.keys = None;
        self.index = None;
        self.unlock_at = None;
        self.last_interaction = None;
    }
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("policy", &self.policy)
            .field("lax_secs", &self.lax_secs)
            .field("locked", &self.keys.is_none())
            .finish_non_exhaustive()
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.index.zeroize();
    }
}
