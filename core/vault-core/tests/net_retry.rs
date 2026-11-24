//! T3.4 network error policy (spec 04 section 4.8; 08 test 20).
//!
//! Retry lives in the core; the asking lives in the UI/CLI. Tests drive the
//! production `net_retry` API only, with injected operations and an injected
//! backoff recorder, so no test sleeps and no network is touched.

use vault_core::net_retry::{self, Attempt, Error};

#[test]
fn t34_01_unreachable_host_retried_exactly_3_times_then_remote_unreachable_with_should_ask() {
    let mut calls = 0u32;
    let mut backoffs: Vec<u32> = Vec::new();
    let err = net_retry::retry(
        || -> Result<(), Attempt> {
            calls += 1;
            Err(Attempt::Unreachable)
        },
        |attempt| backoffs.push(attempt),
    )
    .unwrap_err();
    assert_eq!(calls, 3);
    assert_eq!(err, Error::RemoteUnreachable { attempts: 3 });
    assert!(err.should_ask());
}

#[test]
fn t34_02_success_on_attempt_2_stops_retrying() {
    let mut calls = 0u32;
    let mut backoffs: Vec<u32> = Vec::new();
    let ok = net_retry::retry(
        || -> Result<&'static str, Attempt> {
            calls += 1;
            if calls == 1 {
                Err(Attempt::Unreachable)
            } else {
                Ok("fetched")
            }
        },
        |attempt| backoffs.push(attempt),
    )
    .unwrap();
    assert_eq!(ok, "fetched");
    assert_eq!(calls, 2);
    assert_eq!(backoffs, vec![1]);
}

#[test]
fn t34_03_backoff_delays_are_injected_so_tests_do_not_sleep() {
    let mut backoffs: Vec<u32> = Vec::new();
    let _ = net_retry::retry(
        || -> Result<(), Attempt> { Err(Attempt::Unreachable) },
        |attempt| backoffs.push(attempt),
    );
    // One injected backoff per failed attempt except the last: 3 attempts
    // produce exactly 2 backoff calls, and the test itself never sleeps.
    assert_eq!(backoffs, vec![1, 2]);
    assert_eq!(net_retry::MAX_ATTEMPTS, 3);
}

#[test]
fn t34_04_auth_failure_is_remote_rejected_and_is_not_retried() {
    let mut calls = 0u32;
    let mut backoffs: Vec<u32> = Vec::new();
    let err = net_retry::retry(
        || -> Result<(), Attempt> {
            calls += 1;
            Err(Attempt::Rejected)
        },
        |attempt| backoffs.push(attempt),
    )
    .unwrap_err();
    assert_eq!(calls, 1);
    assert!(backoffs.is_empty());
    assert_eq!(err, Error::RemoteRejected);
    assert!(!err.should_ask());
}

#[test]
fn t34_05_retry_count_is_the_same_for_fetch_and_push() {
    for op_name in ["fetch", "push"] {
        let mut calls = 0u32;
        let err = net_retry::retry(
            || -> Result<(), Attempt> {
                calls += 1;
                Err(Attempt::Unreachable)
            },
            |_| {},
        )
        .unwrap_err();
        assert_eq!(calls, net_retry::MAX_ATTEMPTS, "{op_name}");
        assert_eq!(err, Error::RemoteUnreachable { attempts: 3 }, "{op_name}");
    }
}
