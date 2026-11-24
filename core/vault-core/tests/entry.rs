//! T1.7 entry plaintext format tests (spec 03 section 3.4).

use vault_core::entry::{Algorithm, Entry, Error};

#[test]
fn t17_01_credential_round_trips_with_all_four_fields() {
    let entry = Entry::new_credential(
        "aaaaaaaaaaaaaaaaaaaaaaaaaa",
        "2026-11-19T09:00:00Z",
        "https://accounts.google.com",
        "me@example.com",
        "s3cr3t",
        "PIN 1234",
    );
    let bytes = entry.encode().unwrap();
    let back = Entry::decode(&bytes).unwrap();
    let (url, username, password, note) = back.as_credential().unwrap();
    assert_eq!(url, "https://accounts.google.com");
    assert_eq!(username, "me@example.com");
    assert_eq!(password, "s3cr3t");
    assert_eq!(note, "PIN 1234");
}

#[test]
fn t17_02_secret_note_round_trips_with_name_and_content() {
    let entry = Entry::new_note(
        "bbbbbbbbbbbbbbbbbbbbbbbbbb",
        "2026-11-19T09:00:00Z",
        "recovery codes",
        "code-1 code-2",
    );
    let back = Entry::decode(&entry.encode().unwrap()).unwrap();
    let (name, content) = back.as_note().unwrap();
    assert_eq!(name, "recovery codes");
    assert_eq!(content, "code-1 code-2");
}

#[test]
fn t17_03_otp_round_trips_with_all_fields_each_algorithm() {
    for algorithm in [Algorithm::Sha1, Algorithm::Sha256, Algorithm::Sha512] {
        let entry = Entry::new_otp(
            "cccccccccccccccccccccccccc",
            "2026-11-19T09:00:00Z",
            "Example:ada@example.com",
            "Example",
            "JBSWY3DPEHPK3PXP",
            algorithm,
            8,
            Some(30),
            None,
            None,
        )
        .unwrap();
        let back = Entry::decode(&entry.encode().unwrap()).unwrap();
        let otp = back.as_otp().unwrap();
        assert_eq!(otp.label, "Example:ada@example.com");
        assert_eq!(otp.issuer, "Example");
        assert_eq!(otp.secret, "JBSWY3DPEHPK3PXP");
        assert_eq!(otp.algorithm, algorithm);
        assert_eq!(otp.digits, 8);
        assert_eq!(otp.period, Some(30));
        assert_eq!(otp.counter, None);
    }
}

#[test]
fn t17_04_otp_with_digits_5_or_9_is_rejected() {
    for digits in [5, 9] {
        assert_eq!(
            Entry::new_otp(
                "cccccccccccccccccccccccccc",
                "2026-11-19T09:00:00Z",
                "label",
                "issuer",
                "JBSWY3DPEHPK3PXP",
                Algorithm::Sha1,
                digits,
                Some(30),
                None,
                None,
            )
            .unwrap_err(),
            Error::Invalid("digits")
        );
    }
}

#[test]
fn t17_05_otp_with_both_period_and_counter_is_rejected() {
    assert_eq!(
        Entry::new_otp(
            "cccccccccccccccccccccccccc",
            "2026-11-19T09:00:00Z",
            "label",
            "issuer",
            "JBSWY3DPEHPK3PXP",
            Algorithm::Sha1,
            6,
            Some(30),
            Some(7),
            None,
        )
        .unwrap_err(),
        Error::Invalid("period/counter")
    );
    // Neither set is a TOTP with the default period.
    let entry = Entry::new_otp(
        "cccccccccccccccccccccccccc",
        "2026-11-19T09:00:00Z",
        "label",
        "issuer",
        "JBSWY3DPEHPK3PXP",
        Algorithm::Sha1,
        6,
        None,
        None,
        None,
    )
    .unwrap();
    assert_eq!(entry.as_otp().unwrap().period, None);
    // Counter alone is an HOTP.
    let entry = Entry::new_otp(
        "cccccccccccccccccccccccccc",
        "2026-11-19T09:00:00Z",
        "label",
        "issuer",
        "JBSWY3DPEHPK3PXP",
        Algorithm::Sha1,
        6,
        None,
        Some(7),
        None,
    )
    .unwrap();
    assert_eq!(entry.as_otp().unwrap().counter, Some(7));
}

#[test]
fn t17_06_padding_brings_plaintext_to_multiple_of_512() {
    for len in [1usize, 511, 512, 513, 1000] {
        let name = "n".repeat(len);
        let entry = Entry::new_note(
            "bbbbbbbbbbbbbbbbbbbbbbbbbb",
            "2026-11-19T09:00:00Z",
            &name,
            "c",
        );
        let bytes = entry.encode().unwrap();
        assert_eq!(bytes.len() % 512, 0, "len {len}");
        let expected = if len == 0 { 0 } else { len.div_ceil(512) * 512 };
        assert!(bytes.len() >= expected, "len {len}");
    }
}

#[test]
fn t17_07_padding_is_trailing_spaces_ignored_by_json_parser() {
    let entry = Entry::new_note(
        "bbbbbbbbbbbbbbbbbbbbbbbbbb",
        "2026-11-19T09:00:00Z",
        "name",
        "content",
    );
    let bytes = entry.encode().unwrap();
    assert!(bytes.len().is_multiple_of(512));
    let text = std::str::from_utf8(&bytes).unwrap();
    assert!(text.trim_end().ends_with('}'));
    assert!(text[text.trim_end().len()..].chars().all(|c| c == ' '));
    // Decoding padded bytes works.
    let back = Entry::decode(&bytes).unwrap();
    assert_eq!(back.as_note().unwrap().0, "name");
}

#[test]
fn t17_08_entry_larger_than_1mib_rejected_on_write_and_read() {
    let big = "x".repeat(1_048_576);
    let entry = Entry::new_note(
        "bbbbbbbbbbbbbbbbbbbbbbbbbb",
        "2026-11-19T09:00:00Z",
        &big,
        "c",
    );
    assert_eq!(entry.encode().unwrap_err(), Error::TooLarge);
    let oversize = vec![b' '; 1_048_577];
    assert_eq!(Entry::decode(&oversize).unwrap_err(), Error::TooLarge);
}

#[test]
fn t17_08b_padding_to_exactly_1mib_succeeds_one_byte_over_fails() {
    // Overhead of the fixed JSON framing around the name.
    let framing = Entry::new_note(
        "bbbbbbbbbbbbbbbbbbbbbbbbbb",
        "2026-11-19T09:00:00Z",
        "",
        "c",
    )
    .encode()
    .unwrap()
    .len();
    assert_eq!(framing, 512);
    // Unpadded length just under 1 MiB pads to exactly 1 MiB: accepted.
    let name_len = 1_048_576 - 200;
    let entry = Entry::new_note(
        "bbbbbbbbbbbbbbbbbbbbbbbbbb",
        "2026-11-19T09:00:00Z",
        &"y".repeat(name_len),
        "c",
    );
    let bytes = entry.encode().unwrap();
    assert_eq!(bytes.len(), 1_048_576);
    // One byte more tips the unpadded length over 1 MiB: refused.
    let over = Entry::new_note(
        "bbbbbbbbbbbbbbbbbbbbbbbbbb",
        "2026-11-19T09:00:00Z",
        &"y".repeat(name_len + 201),
        "c",
    );
    assert_eq!(over.encode().unwrap_err(), Error::TooLarge);
}

#[test]
fn t17_09_unknown_fields_preserved_on_parse_and_rewrite() {
    let raw = r#"{"v":1,"id":"bbbbbbbbbbbbbbbbbbbbbbbbbb","type":"note","rev":1,"created":"2026-11-19T09:00:00Z","updated":"2026-11-19T09:00:00Z","data":{"name":"n","content":"c","future":"keep-me"},"noteExtra":42}"#;
    let entry = Entry::decode(raw.as_bytes()).unwrap();
    let bytes = entry.encode().unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    let value: serde_json::Value = serde_json::from_str(text.trim_end()).unwrap();
    assert_eq!(value["data"]["future"], "keep-me");
    assert_eq!(value["noteExtra"], 42);
}

#[test]
fn t17_10_unknown_type_parses_as_unsupported_and_keeps_bytes() {
    let raw = r#"{"v":1,"id":"dddddddddddddddddddddddddd","type":"passkey","rev":1,"created":"2026-11-19T09:00:00Z","updated":"2026-11-19T09:00:00Z","data":{"key":"value"}}"#;
    let entry = Entry::decode(raw.as_bytes()).unwrap();
    assert!(entry.as_credential().is_err());
    let bytes = entry.encode().unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    let value: serde_json::Value = serde_json::from_str(text.trim_end()).unwrap();
    assert_eq!(value["type"], "passkey");
    assert_eq!(value["data"]["key"], "value");
}

#[test]
fn t17_11_rev_starts_at_1_and_edit_writes_rev_plus_one() {
    let mut entry = Entry::new_note(
        "bbbbbbbbbbbbbbbbbbbbbbbbbb",
        "2026-11-19T09:00:00Z",
        "name",
        "content",
    );
    assert_eq!(entry.rev(), 1);
    entry.prepare_edit("2026-11-19T10:00:00Z");
    assert_eq!(entry.rev(), 2);
    assert_eq!(entry.updated(), "2026-11-19T10:00:00Z");
    let back = Entry::decode(&entry.encode().unwrap()).unwrap();
    assert_eq!(back.rev(), 2);
}

#[test]
fn t17_12_conflict_of_and_rotate_are_optional_and_round_trip() {
    let mut entry = Entry::new_note(
        "bbbbbbbbbbbbbbbbbbbbbbbbbb",
        "2026-11-19T09:00:00Z",
        "name",
        "content",
    );
    assert_eq!(entry.conflict_of(), None);
    assert!(!entry.rotate());
    entry.set_conflict_of(Some("aaaaaaaaaaaaaaaaaaaaaaaaaa"));
    entry.set_rotate(true);
    let back = Entry::decode(&entry.encode().unwrap()).unwrap();
    assert_eq!(back.conflict_of(), Some("aaaaaaaaaaaaaaaaaaaaaaaaaa"));
    assert!(back.rotate());
}

#[test]
fn t17_13_invalid_json_missing_v_and_v_not_1_rejected() {
    assert_eq!(
        Entry::decode(b"not json").unwrap_err(),
        Error::Invalid("json")
    );
    let missing_v = r#"{"id":"bbbbbbbbbbbbbbbbbbbbbbbbbb","type":"note","rev":1,"created":"2026-11-19T09:00:00Z","updated":"2026-11-19T09:00:00Z","data":{"name":"n","content":"c"}}"#;
    assert_eq!(
        Entry::decode(missing_v.as_bytes()).unwrap_err(),
        Error::Invalid("v")
    );
    let v2 = r#"{"v":2,"id":"bbbbbbbbbbbbbbbbbbbbbbbbbb","type":"note","rev":1,"created":"2026-11-19T09:00:00Z","updated":"2026-11-19T09:00:00Z","data":{"name":"n","content":"c"}}"#;
    assert_eq!(
        Entry::decode(v2.as_bytes()).unwrap_err(),
        Error::Invalid("v")
    );
}

#[test]
fn t17_14_debug_hides_password_note_content_and_otp_secret() {
    let cred = Entry::new_credential("a", "t", "u", "user", "pw-secret", "n");
    let shown = format!("{cred:?}");
    assert!(!shown.contains("pw-secret"), "{shown}");
    let note = Entry::new_note("a", "t", "n", "note-secret");
    assert!(!format!("{note:?}").contains("note-secret"));
    let otp = Entry::new_otp(
        "a",
        "t",
        "l",
        "i",
        "OTP-SECRET",
        Algorithm::Sha1,
        6,
        Some(30),
        None,
        None,
    )
    .unwrap();
    assert!(!format!("{otp:?}").contains("OTP-SECRET"));
}

#[test]
fn t17_15_wrong_type_accessors_fail_error_displays_sig_preserved() {
    use vault_core::entry::Error;
    let note = Entry::new_note("a", "t", "n", "c");
    assert_eq!(note.as_credential().unwrap_err(), Error::Invalid("type"));
    assert_eq!(note.as_otp().unwrap_err(), Error::Invalid("type"));
    assert_eq!(
        format!("{}", Error::Invalid("schema")),
        "invalid entry: schema"
    );
    assert_eq!(format!("{}", Error::TooLarge), "entry exceeds 1 MiB");
    // A signed entry keeps its sig through decode/encode (T1.8 groundwork).
    let raw = r#"{"v":1,"id":"aaaaaaaaaaaaaaaaaaaaaaaaaa","type":"note","rev":1,"created":"2026-11-19T09:00:00Z","updated":"2026-11-19T09:00:00Z","data":{"name":"n","content":"c"},"sig":{"by":"aaaaaaaaaaaaaaaaaaaaaaaaaa","v":"c2ln"}}"#;
    let back = Entry::decode(raw.as_bytes()).unwrap();
    let encoded = back.encode().unwrap();
    let text = std::str::from_utf8(&encoded).unwrap();
    let value: serde_json::Value = serde_json::from_str(text.trim_end()).unwrap();
    assert_eq!(value["sig"]["by"], "aaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert_eq!(value["sig"]["v"], "c2ln");
    // Debug of an unsupported entry names the type, not its bytes.
    let unsupported = Entry::decode(
        r#"{"v":1,"id":"d","type":"passkey","rev":1,"created":"t","updated":"t","data":{"k":"v"}}"#
            .as_bytes(),
    )
    .unwrap();
    let shown = format!("{unsupported:?}");
    assert!(shown.contains("passkey"));
    assert!(!shown.contains("\"k\""));
}
