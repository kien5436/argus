//! T2.2 session and lax-time policy tests. Injected clock, no sleeps.

use std::sync::{Arc, Mutex};
use vault_core::session::{Clock, Policy, Session};

struct ManualClock(Mutex<u64>);

impl ManualClock {
    fn at(t: u64) -> Arc<Self> {
        Arc::new(Self(Mutex::new(t)))
    }
    fn set(&self, t: u64) {
        *self.0.lock().unwrap() = t;
    }
}

impl Clock for ManualClock {
    fn now(&self) -> u64 {
        *self.0.lock().unwrap()
    }
}

fn keys() -> vault_core::device_key::DeviceKeys {
    vault_core::device_key::DeviceKeys {
        device_id: "test".to_string(),
        enc_public: [7u8; 32],
        enc_secret: vault_core::secrets::PrivateKey::new(vec![1u8; 32]),
        sign_seed: vault_core::secrets::PrivateKey::new(vec![2u8; 32]),
    }
}

fn session(policy: Policy, lax: u64, clock: &Arc<ManualClock>) -> Session {
    Session::new(policy, lax, clock.clone() as Arc<dyn Clock>).unwrap()
}

#[test]
fn t2_2_01_from_unlock_valid_until_45s() {
    let c = ManualClock::at(1000);
    let mut s = session(Policy::FromUnlock, 45, &c);
    s.unlock(keys());
    c.set(1044);
    assert!(s.is_valid());
    c.set(1045);
    assert!(!s.is_valid());
}

#[test]
fn t2_2_02_from_interaction_extends_to_75s() {
    let c = ManualClock::at(1000);
    let mut s = session(Policy::FromInteraction, 45, &c);
    s.unlock(keys());
    c.set(1030);
    s.touch();
    c.set(1074);
    assert!(s.is_valid());
    c.set(1075);
    assert!(!s.is_valid());
}

#[test]
fn t2_2_03_interaction_does_not_extend_from_unlock() {
    let c = ManualClock::at(1000);
    let mut s = session(Policy::FromUnlock, 45, &c);
    s.unlock(keys());
    c.set(1030);
    s.touch();
    c.set(1044);
    assert!(s.is_valid());
    c.set(1045);
    assert!(!s.is_valid());
}

#[test]
fn t2_2_04_lax_zero_never_valid() {
    let c = ManualClock::at(1000);
    let mut s = session(Policy::FromUnlock, 0, &c);
    s.unlock(keys());
    assert!(!s.is_valid());
    assert_eq!(s.keys().unwrap_err(), vault_core::session::Error::Locked);
}

#[test]
fn t2_2_05_lock_zeroises_and_later_use_fails() {
    let c = ManualClock::at(1000);
    let mut s = session(Policy::FromUnlock, 45, &c);
    s.unlock(keys());
    s.set_index(zeroize::Zeroizing::new(vec![9u8; 16]));
    s.lock();
    c.set(1001);
    assert_eq!(s.keys().unwrap_err(), vault_core::session::Error::Locked);
    assert!(!s.has_index());
}

#[test]
fn t2_2_06_expiry_zeroises_keys() {
    let c = ManualClock::at(1000);
    let mut s = session(Policy::FromUnlock, 45, &c);
    s.unlock(keys());
    // Move past expiry: next access must fail with Locked (keys dropped).
    c.set(1045);
    assert_eq!(s.keys().unwrap_err(), vault_core::session::Error::Locked);
    assert!(!s.is_valid());
    // A further access still fails: the keys were dropped, not retained.
    c.set(1046);
    assert_eq!(s.keys().unwrap_err(), vault_core::session::Error::Locked);
}

#[test]
fn t2_2_07_lax_time_range_validation() {
    let c = ManualClock::at(0);
    let as_clock = || c.clone() as Arc<dyn Clock>;
    assert!(Session::new(Policy::FromUnlock, 0, as_clock()).is_ok());
    assert!(Session::new(
        Policy::FromUnlock,
        vault_core::session::DEFAULT_LAX_SECS,
        as_clock()
    )
    .is_ok());
    assert!(Session::new(
        Policy::FromUnlock,
        vault_core::session::MAX_LAX_SECS,
        as_clock()
    )
    .is_ok());
    assert_eq!(
        Session::new(
            Policy::FromUnlock,
            vault_core::session::MAX_LAX_SECS + 1,
            as_clock()
        )
        .unwrap_err(),
        vault_core::session::Error::InvalidLax
    );
    assert_eq!(vault_core::session::parse_lax("45").unwrap(), 45);
    assert_eq!(vault_core::session::parse_lax("0").unwrap(), 0);
    for bad in ["-1", "abc", "", "4.5", "  "] {
        assert!(
            vault_core::session::parse_lax(bad).is_err(),
            "accepted {bad:?}"
        );
    }
    assert!(vault_core::session::parse_lax("999999999999").is_err());
}

#[test]
fn t2_2_08_time_is_injected_no_sleep() {
    // ManualClock proves no wall-clock use: validity is a pure function of
    // the injected clock.
    let c = ManualClock::at(0);
    let mut s = session(Policy::FromInteraction, 10, &c);
    s.unlock(keys());
    c.set(9);
    assert!(s.is_valid());
    s.touch();
    c.set(18);
    assert!(s.is_valid());
    c.set(19);
    assert!(!s.is_valid());
}

#[test]
fn error_and_session_debug_carry_no_secrets() {
    assert_eq!(format!("{}", vault_core::session::Error::Locked), "locked");
    assert_eq!(
        format!("{}", vault_core::session::Error::InvalidLax),
        "invalid lax-time"
    );
    let c = ManualClock::at(0);
    let mut s = session(Policy::FromUnlock, 45, &c);
    let locked_shown = format!("{s:?}");
    assert!(locked_shown.contains("locked"));
    s.unlock(keys());
    let shown = format!("{s:?}");
    assert!(!shown.contains('1'), "debug must not leak key bytes");
}

#[test]
fn system_clock_is_monotonic() {
    let clock = vault_core::session::SystemClock;
    let a = clock.now();
    let b = clock.now();
    assert!(b >= a);
}
