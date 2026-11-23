use vault_core::canonical_json::canonicalize;

#[test]
fn t11_01_keys_sorted_by_utf16_code_units_including_non_bmp() {
    assert_eq!(
        canonicalize(r#"{"b":1,"a":2}"#).unwrap(),
        r#"{"a":2,"b":1}"#
    );
    assert_eq!(
        canonicalize("{\"z\":1,\"\u{1F600}\":2}").unwrap(),
        "{\"z\":1,\"\u{1F600}\":2}"
    );
    assert_eq!(
        canonicalize("{\"\u{1F600}\":1,\"\u{a9}\":2,\"z\":3}").unwrap(),
        "{\"z\":3,\"\u{a9}\":2,\"\u{1F600}\":1}"
    );
}

#[test]
fn t11_02_nested_objects_sorted_arrays_keep_order() {
    assert_eq!(
        canonicalize(r#"{"b":{"d":4,"c":3},"a":[3,2,1]}"#).unwrap(),
        r#"{"a":[3,2,1],"b":{"c":3,"d":4}}"#
    );
}

#[test]
fn t11_03_strings_escape_only_required_chars_non_ascii_as_utf8() {
    assert_eq!(
        canonicalize("{\"s\":\"a\u{a9}\u{1F600}\"}").unwrap(),
        "{\"s\":\"a\u{a9}\u{1F600}\"}"
    );
    assert_eq!(canonicalize(r#""\u00e9""#).unwrap(), "\"é\"");
}

#[test]
fn t11_04_control_characters_use_rfc8785_escapes() {
    let input = "{\"s\":\"\\b\\f\\n\\r\\t\\u0001\\u001f\"}";
    assert_eq!(canonicalize(input).unwrap(), input);
    assert_eq!(canonicalize("\"\\u0000\"").unwrap(), "\"\\u0000\"");
    assert!(canonicalize("{\"s\":\"\u{1}\"}").is_err());
}

#[test]
fn t11_05_integers_no_leading_zeros_no_sign_on_zero_minus_zero_rejected() {
    assert_eq!(canonicalize("0").unwrap(), "0");
    assert_eq!(canonicalize("-42").unwrap(), "-42");
    assert_eq!(
        canonicalize("123456789012345678901234567890").unwrap(),
        "123456789012345678901234567890"
    );
    assert!(canonicalize("01").is_err());
    assert!(canonicalize("-01").is_err());
    assert!(canonicalize("-0").is_err());
    assert!(canonicalize(r#"{"a":-0}"#).is_err());
}

#[test]
fn t11_06_floats_rejected() {
    for bad in ["1.0", "-2.5", "1e10", "1E-3", "0.5", "{\"a\":1.0}"] {
        assert!(canonicalize(bad).is_err(), "{bad} must be rejected");
    }
}

#[test]
fn t11_07_duplicate_keys_rejected() {
    assert!(canonicalize(r#"{"a":1,"a":2}"#).is_err());
    assert!(canonicalize(r#"{"a":{"b":1,"b":2}}"#).is_err());
    assert!(canonicalize(r#"{"a":1,"b":2,"a":3}"#).is_err());
}

#[test]
fn t11_08_empty_object_and_array_round_trip() {
    assert_eq!(canonicalize("{}").unwrap(), "{}");
    assert_eq!(canonicalize("[]").unwrap(), "[]");
    assert_eq!(canonicalize("  {  }  ").unwrap(), "{}");
}

#[test]
fn t11_09_rfc8785_vectors() {
    assert_eq!(canonicalize(" [1, 2, 3] ").unwrap(), "[1,2,3]");
    assert_eq!(
        canonicalize("{ \"b\": true, \"a\": null }").unwrap(),
        "{\"a\":null,\"b\":true}"
    );
    assert_eq!(
        canonicalize("{\"10\":\"x\",\"1\":\"y\",\"2\":\"z\"}").unwrap(),
        "{\"1\":\"y\",\"10\":\"x\",\"2\":\"z\"}"
    );
    assert_eq!(
        canonicalize("{\"e\":2,\"d\":1}").unwrap(),
        "{\"d\":1,\"e\":2}"
    );
}

#[test]
fn t11_10_output_stable_across_1000_random_inputs() {
    let mut state: u64 = 0x1234_5678_9abc_def0;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for _ in 0..1000 {
        let input = format!(
            "{{\"k{}\":{},\"a\":[{},\"x\",null,true]}}",
            next() % 100,
            next() as i64,
            next() as i64
        );
        let once = canonicalize(&input).unwrap();
        let twice = canonicalize(&once).unwrap();
        assert_eq!(once, twice);
    }
}

#[test]
fn t11_11_malformed_inputs_rejected() {
    for bad in [
        "",
        " ",
        "{",
        "[",
        "\"abc",
        "{\"a\"",
        "{\"a\":1",
        "{\"a\":1,",
        "[1,",
        "[1 2]",
        "{a:1}",
        "{,}",
        "{\"a\" 1}",
        "{\"a\",1}",
        "x",
        "-",
        "-x",
        "--1",
        "tru",
        "nul",
        "01x",
        "{}x",
        "1 2",
        "nullx",
    ] {
        assert!(canonicalize(bad).is_err(), "{bad:?} must be rejected");
    }
}

#[test]
fn t11_12_escape_and_unicode_edges() {
    assert_eq!(canonicalize(r#""\/""#).unwrap(), "\"/\"");
    assert_eq!(canonicalize(r#""\ud83d\ude00""#).unwrap(), "\"😀\"");
    assert_eq!(canonicalize(r#""\u0041""#).unwrap(), "\"A\"");
    for bad in [
        "\"\\q\"",
        "\"\\u00xz\"",
        "\"\\u12\"",
        "\"\\ud800\"",
        "\"\\udc00\"",
        "\"\\ud800\\u0041\"",
        "\"\\ud800x\"",
    ] {
        assert!(canonicalize(bad).is_err(), "{bad} must be rejected");
    }
}

#[test]
fn t11_13_nesting_limit_rejected() {
    let deep = format!("{}{}", "[".repeat(200), "]".repeat(200));
    assert!(canonicalize(&deep).is_err());
    let shallow = format!("{}{}", "[".repeat(10), "]".repeat(10));
    assert_eq!(canonicalize(&shallow).unwrap(), shallow);
}

#[test]
fn t11_14_errors_display_without_input_text() {
    use vault_core::canonical_json::Error;
    for e in [
        Error::DuplicateKey,
        Error::Float,
        Error::NegativeZero,
        Error::InvalidJson,
    ] {
        let msg = format!("{e}");
        assert!(!msg.is_empty());
    }
}
