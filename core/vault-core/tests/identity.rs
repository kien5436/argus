use vault_core::identity::{anchor_display, fingerprint, parse_anchor, parse_recipient};

fn ed_key() -> [u8; 32] {
    hex32("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
}

fn x_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    for (i, b) in k.iter_mut().enumerate() {
        *b = i as u8;
    }
    k
}

#[test]
fn t14_01_bech32_matches_bip173_vector() {
    let (hrp, data) = bech32::decode("a12uel5l").unwrap();
    assert_eq!(hrp.as_str(), "a");
    assert!(data.is_empty());
}

#[test]
fn t14_02_valid_recipient_round_trips_and_is_62_chars() {
    let s = "age1qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0savhh7m";
    let r = parse_recipient(s).unwrap();
    let back = r.to_string();
    assert_eq!(back, s);
    assert_eq!(back.len(), 62);
}

#[test]
fn t14_03_recipient_with_bad_checksum_is_rejected() {
    let mut s = "age1qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0savhh7m".to_owned();
    s.replace_range(10..11, "q");
    assert_ne!(s.chars().nth(10), Some('0'));
    assert!(parse_recipient(&s).is_err());
}

#[test]
fn t14_04_recipient_with_wrong_prefix_is_rejected() {
    let s =
        "age1qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0savhh7m".replace("age1", "age9");
    assert!(parse_recipient(&s).is_err());
}

#[test]
fn t14_05_recipient_with_bad_character_is_rejected() {
    let s = "age1ql3z7hj432v2jl2z8alunwwun8hm4s4hf0h2a29tuy0qxu3umxgl4qpI";
    assert!(parse_recipient(s).is_err());
}

#[test]
fn t14_06_fingerprint_is_sha256_of_prefix_plus_both_keys() {
    let mut prefixed = Vec::with_capacity(10 + 32 + 32);
    prefixed.extend_from_slice(b"argus-device-v1\n");
    prefixed.extend_from_slice(&ed_key());
    prefixed.extend_from_slice(&x_key());
    let expected = vault_core::encodings::sha256_hex(&prefixed);
    assert_eq!(hex_of(&fingerprint(&ed_key(), &x_key())), expected);
}

#[test]
fn t14_07_fingerprint_display_is_8_groups_of_4_lowercase_hex() {
    let display = vault_core::identity::fingerprint_display(&fingerprint(&ed_key(), &x_key()));
    let groups: Vec<&str> = display.split(' ').collect();
    assert_eq!(groups.len(), 8);
    for g in groups {
        assert_eq!(g.len(), 4);
        assert!(g.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
    }
}

#[test]
fn t14_08_anchor_is_version_plus_8_groups_of_file_hash() {
    let file = br#"{"format":1,"storeId":"aaaaaaaaaaaaaaaaaaaaaaaaaa"}"#;
    let anchor = anchor_display(3, file);
    assert!(anchor.starts_with("v3 "));
    let groups: Vec<&str> = anchor[3..].split(' ').collect();
    assert_eq!(groups.len(), 8);
    let digest = vault_core::encodings::sha256_hex(file);
    assert_eq!(groups.concat(), digest[..32].to_owned());
}

#[test]
fn t14_09_anchor_parse_accepts_canonical_form() {
    let file = b"devices-bytes";
    let shown = anchor_display(12, file);
    let anchor = parse_anchor(&shown).unwrap();
    assert_eq!(anchor.version, 12);
    assert_eq!(anchor_display(anchor.version, file), shown);
}

#[test]
fn t14_10_anchor_parse_ignores_case_and_spaces() {
    let file = b"devices-bytes";
    let shown = anchor_display(3, file);
    let upper = shown.to_uppercase();
    let nospace = shown.replace(' ', "");
    assert_eq!(parse_anchor(&upper).unwrap(), parse_anchor(&shown).unwrap());
    assert_eq!(
        parse_anchor(&nospace).unwrap(),
        parse_anchor(&shown).unwrap()
    );
    assert_eq!(
        parse_anchor(&upper.replace(' ', "")).unwrap(),
        parse_anchor(&shown).unwrap()
    );
}

#[test]
fn t14_11_anchor_rejects_non_hex_group_missing_group_and_zero_version() {
    let file = b"devices-bytes";
    let shown = anchor_display(3, file);
    let mut bad = shown.clone();
    bad.replace_range(3..4, "z");
    assert!(parse_anchor(&bad).is_err());
    let short = shown.rsplit_once(' ').unwrap().0.to_owned();
    assert!(parse_anchor(&short).is_err());
    let zero = shown.replacen("v3", "v0", 1);
    assert!(parse_anchor(&zero).is_err());
    assert!(parse_anchor("hello").is_err());
}

#[test]
fn t14_12_fingerprint_and_anchor_match_vectors() {
    let raw = include_str!("vectors/t14.json");
    let v: serde_json::Value = serde_json::from_str(raw).unwrap();
    let ed: [u8; 32] = hex32(v["ed25519"].as_str().unwrap());
    let x: [u8; 32] = hex32(v["x25519"].as_str().unwrap());
    assert_eq!(
        hex_of(&fingerprint(&ed, &x)),
        v["fingerprint_hex"].as_str().unwrap()
    );
    assert_eq!(
        vault_core::identity::fingerprint_display(&fingerprint(&ed, &x)),
        v["fingerprint_display"].as_str().unwrap()
    );
    let file = v["anchor_file"].as_str().unwrap().as_bytes();
    let version = v["anchor_version"].as_u64().unwrap();
    assert_eq!(
        anchor_display(version, file),
        v["anchor_display"].as_str().unwrap()
    );
    assert_eq!(
        parse_anchor(v["anchor_display"].as_str().unwrap())
            .unwrap()
            .version,
        version
    );
}

fn hex32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn t14_13_recipient_bytes_round_trip_and_huge_anchor_version_rejected() {
    let r =
        parse_recipient("age1qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0savhh7m").unwrap();
    let expected: Vec<u8> = (0u8..32).collect();
    assert_eq!(r.bytes(), expected.as_slice());
    assert!(
        parse_anchor("v99999999999999999999999 aaaa bbbb cccc dddd eeee ffff 1111 2222").is_err()
    );
}

#[test]
fn t14_14_errors_display_without_key_text() {
    use vault_core::identity::Error;
    assert!(!format!("{}", Error::InvalidRecipient).is_empty());
    assert!(!format!("{}", Error::InvalidAnchor).is_empty());
}
