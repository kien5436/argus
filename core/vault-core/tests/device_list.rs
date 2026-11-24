//! T4.1 device list model and devices.sig (spec 03 section 3.5).

use vault_core::device_list::{parse_device_list, parse_device_sig, DeviceEntry, DeviceList};
use vault_core::signatures::SigningKey;

fn entry(id: &str) -> DeviceEntry {
    DeviceEntry {
        id: id.to_string(),
        name: "MacBook".to_string(),
        enc: "argus1qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0s4vsgja".to_string(),
        sign: "A".repeat(43),
        git_key: None,
        added: "2026-11-19T09:00:00Z".to_string(),
        added_by: id.to_string(),
    }
}

fn list_v1() -> String {
    let id = "aaaaaaaaaaaaaaaaaaaaaaaaaa";
    let e = entry(id);
    format!(
        r#"{{"v":1,"storeId":"bbbbbbbbbbbbbbbbbbbbbbbbba","version":1,"prev":"","updated":"2026-11-19T09:00:00Z","devices":[{{"id":"{}","name":"{}","enc":"{}","sign":"{}","added":"{}","addedBy":"{}"}}]}}"#,
        e.id, e.name, e.enc, e.sign, e.added, e.added_by
    )
}

#[test]
fn t41_01_serialises_to_canonical_json_with_spec_fields() {
    let list = DeviceList {
        store_id: "bbbbbbbbbbbbbbbbbbbbbbbbba".to_string(),
        version: 2,
        prev: "00".repeat(32),
        updated: "2026-11-19T09:00:00Z".to_string(),
        devices: vec![entry("aaaaaaaaaaaaaaaaaaaaaaaaaa")],
    };
    let canonical = list.canonical_json().unwrap();
    let v: serde_json::Value = serde_json::from_str(&canonical).unwrap();
    assert_eq!(v["v"], 1);
    assert_eq!(v["storeId"], "bbbbbbbbbbbbbbbbbbbbbbbbba");
    assert_eq!(v["version"], 2);
    assert!(v.get("prev").is_some());
    assert!(v.get("updated").is_some());
    assert!(v["devices"][0]["addedBy"] != serde_json::Value::Null);
    // canonical: keys sorted, so "devices" after "created"... check determinism
    assert_eq!(canonical, list.canonical_json().unwrap());
}

#[test]
fn t41_02_device_sig_parses_signer_and_sig() {
    let sig_b64u = "A".repeat(86);
    let json = format!(r#"{{"signer":"aaaaaaaaaaaaaaaaaaaaaaaaaa","sig":"{sig_b64u}"}}"#);
    let sig = parse_device_sig(&json).unwrap();
    assert_eq!(sig.signer, "aaaaaaaaaaaaaaaaaaaaaaaaaa");
    let back = sig.to_canonical_json().unwrap();
    assert_eq!(parse_device_sig(&back).unwrap(), sig);
}

#[test]
fn t41_03_adding_device_does_not_bump_version_silently() {
    let mut list = DeviceList {
        store_id: "bbbbbbbbbbbbbbbbbbbbbbbbba".to_string(),
        version: 1,
        prev: String::new(),
        updated: "2026-11-19T09:00:00Z".to_string(),
        devices: vec![entry("aaaaaaaaaaaaaaaaaaaaaaaaaa")],
    };
    list.devices.push(entry("ccccccccccccccccccccccccca"));
    assert_eq!(list.version, 1, "push must not bump version");
}

#[test]
fn t41_04_missing_added_by_rejected() {
    let json = list_v1().replace(
        r#""addedBy":"aaaaaaaaaaaaaaaaaaaaaaaaaa""#,
        r#""addedBy2":"x""#,
    );
    // remove addedBy entirely
    let json = json.replace(r#","addedBy2":"x""#, "");
    assert_eq!(
        parse_device_list(&json),
        Err(vault_core::device_list::Error::Invalid("addedBy"))
    );
}

#[test]
fn t41_05_name_with_control_characters_rejected() {
    let json = list_v1().replace("MacBook", "Mac\\u0001Book");
    assert_eq!(
        parse_device_list(&json),
        Err(vault_core::device_list::Error::Invalid("name"))
    );
}

#[test]
fn t41_06_git_key_optional() {
    let list = parse_device_list(&list_v1()).unwrap();
    assert_eq!(list.devices[0].git_key, None);
    let with_key = list_v1().replace(
        r#""added":"2026-11-19T09:00:00Z""#,
        r#""added":"2026-11-19T09:00:00Z","gitKey":"SHA256:abc""#,
    );
    let parsed = parse_device_list(&with_key).unwrap();
    assert_eq!(parsed.devices[0].git_key.as_deref(), Some("SHA256:abc"));
}

fn list_v1_parsed() -> DeviceList {
    parse_device_list(&list_v1()).unwrap()
}

#[test]
fn t41_07_canonical_parse_round_trip() {
    let list = list_v1_parsed();
    let canonical = list.canonical_json().unwrap();
    assert_eq!(parse_device_list(&canonical).unwrap(), list);
}

#[test]
fn t41_08_sign_and_verify_devices_sig() {
    let list = list_v1_parsed();
    let sk = SigningKey::from_seed([7u8; 32]);
    let vk = sk.verifying_key();
    let sig = list.sign("aaaaaaaaaaaaaaaaaaaaaaaaaa", &sk).unwrap();
    assert_eq!(list.verify(&sig, &vk), Ok(()));
    let other = SigningKey::from_seed([9u8; 32]);
    assert_eq!(
        list.verify(&sig, &other.verifying_key()),
        Err(vault_core::device_list::Error::BadSignature)
    );
    let canonical = sig.to_canonical_json().unwrap();
    assert_eq!(parse_device_sig(&canonical).unwrap(), sig);
}

#[test]
fn t41_09_hash_hex_is_sha256_of_canonical_bytes() {
    use sha2::Digest;
    let list = list_v1_parsed();
    let canonical = list.canonical_json().unwrap();
    let expected: String = sha2::Sha256::digest(canonical.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(list.hash_hex().unwrap(), expected);
    assert_eq!(list.hash_hex().unwrap().len(), 64);
}

#[test]
fn t41_10_invalid_lists_rejected() {
    use vault_core::device_list::Error;
    let good = list_v1();
    // bad v
    assert_eq!(
        parse_device_list(&good.replace(r#""v":1"#, r#""v":2"#)),
        Err(Error::Invalid("v"))
    );
    // version 0
    assert_eq!(
        parse_device_list(&good.replace(r#""version":1"#, r#""version":0"#)),
        Err(Error::Invalid("version"))
    );
    // bad prev
    assert_eq!(
        parse_device_list(&good.replace(r#""prev":""#, r#""prev":"zz"#)),
        Err(Error::Invalid("prev"))
    );
    // empty updated
    assert_eq!(
        parse_device_list(&good.replace("2026-11-19T09:00:00Z", "")),
        Err(Error::Invalid("updated"))
    );
    // empty devices
    assert_eq!(
        parse_device_list(&good.replace(r#""devices":[{""#, r#""devices":[],"x":[{""#)),
        Err(Error::Invalid("devices"))
    );
    // bad device id
    assert_eq!(
        parse_device_list(&good.replace("aaaaaaaaaaaaaaaaaaaaaaaaaa", "short")),
        Err(Error::Invalid("id"))
    );
    // bad enc
    assert_eq!(
        parse_device_list(&good.replace("argus1", "argus2")),
        Err(Error::Invalid("enc"))
    );
    // bad sign
    assert_eq!(
        parse_device_list(&good.replace(&"A".repeat(43), "AA")),
        Err(Error::Invalid("sign"))
    );
    // gitKey wrong type
    assert_eq!(
        parse_device_list(&good.replace(
            r#""added":"2026-11-19T09:00:00Z""#,
            r#""added":"2026-11-19T09:00:00Z","gitKey":7"#
        )),
        Err(Error::Invalid("gitKey"))
    );
    // not an object
    assert_eq!(parse_device_list("[]"), Err(Error::Invalid("schema")));
}

#[test]
fn t41_11_invalid_sigs_rejected() {
    use vault_core::device_list::Error;
    let good_sig = "A".repeat(86);
    let good = format!(r#"{{"signer":"aaaaaaaaaaaaaaaaaaaaaaaaaa","sig":"{good_sig}"}}"#);
    assert_eq!(
        parse_device_sig(&good.replace("aaaaaaaaaaaaaaaaaaaaaaaaaa", "short")),
        Err(Error::Invalid("signer"))
    );
    assert_eq!(
        parse_device_sig(&good.replace(&good_sig, "AA")),
        Err(Error::Invalid("sig"))
    );
    assert_eq!(parse_device_sig("[]"), Err(Error::Invalid("schema")));
}
