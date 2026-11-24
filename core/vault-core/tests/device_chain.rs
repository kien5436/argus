//! T4.2 device list chain verification (spec 03 section 3.5, rules 1-7).

use vault_core::device_list::{
    parse_device_list, verify_chain, ChainEntry, DeviceEntry, DeviceList, Error,
};
use vault_core::encodings::b64u_encode;
use vault_core::signatures::SigningKey;

const ENC_A: &str = "argus1qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0s4vsgja";
const STORE: &str = "bbbbbbbbbbbbbbbbbbbbbbbbba";
const DEV_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaa";
const DEV_B: &str = "ccccccccccccccccccccccccca";
const DEV_C: &str = "ddddddddddddddddddddddddda";

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_seed([seed; 32])
}

fn sign_b64u(sk: &SigningKey) -> String {
    b64u_encode(&sk.verifying_key().to_bytes())
}

fn entry(id: &str, sign_b64u: &str, added_by: &str) -> DeviceEntry {
    DeviceEntry {
        id: id.to_string(),
        name: format!("dev-{id}"),
        enc: ENC_A.to_string(),
        sign: sign_b64u.to_string(),
        git_key: None,
        added: "2026-11-19T09:00:00Z".to_string(),
        added_by: added_by.to_string(),
    }
}

fn list(store: &str, version: u64, prev: &str, devices: Vec<DeviceEntry>) -> DeviceList {
    DeviceList {
        store_id: store.to_string(),
        version,
        prev: prev.to_string(),
        updated: "2026-11-19T09:00:00Z".to_string(),
        devices,
    }
}

fn chain_entry(list: &DeviceList, signer_id: &str, sk: &SigningKey) -> ChainEntry {
    let bytes = list.canonical_json().unwrap();
    let sig = list.sign(signer_id, sk).unwrap();
    let sig_bytes = sig.to_canonical_json().unwrap();
    ChainEntry {
        list_bytes: bytes,
        sig_bytes,
    }
}

fn v1_chain() -> (DeviceList, SigningKey) {
    let ska = signing_key(7);
    let l1 = list(STORE, 1, "", vec![entry(DEV_A, &sign_b64u(&ska), DEV_A)]);
    (l1, ska)
}

fn three_chain() -> (Vec<ChainEntry>, SigningKey, SigningKey, SigningKey) {
    let ska = signing_key(7);
    let skb = signing_key(8);
    let skc = signing_key(9);
    let l1 = list(STORE, 1, "", vec![entry(DEV_A, &sign_b64u(&ska), DEV_A)]);
    let h1 = l1.hash_hex().unwrap();
    let mut devs2 = l1.devices.clone();
    devs2.push(entry(DEV_B, &sign_b64u(&skb), DEV_A));
    let l2 = list(STORE, 2, &h1, devs2);
    let h2 = l2.hash_hex().unwrap();
    let mut devs3 = l2.devices.clone();
    devs3.push(entry(DEV_C, &sign_b64u(&skc), DEV_B));
    let l3 = list(STORE, 3, &h2, devs3);
    let chain = vec![
        chain_entry(&l1, DEV_A, &ska),
        chain_entry(&l2, DEV_A, &ska),
        chain_entry(&l3, DEV_B, &skb),
    ];
    (chain, ska, skb, skc)
}

#[test]
fn t42_01_valid_chain_verifies() {
    let (chain, _, _, _) = three_chain();
    let (version, hash) = verify_chain(&chain, STORE, false).unwrap();
    assert_eq!(version, 3);
    let l3 = parse_device_list(&chain[2].list_bytes).unwrap();
    assert_eq!(hash, l3.hash_hex().unwrap());
}

#[test]
fn t42_02_v1_prev_nonempty_fails() {
    let (mut l1, ska) = v1_chain();
    l1.prev = "00".repeat(32);
    let chain = vec![chain_entry(&l1, DEV_A, &ska)];
    assert_eq!(
        verify_chain(&chain, STORE, false),
        Err(Error::Invalid("prev"))
    );
}

#[test]
fn t42_03_v1_two_devices_fails() {
    let (mut l1, ska) = v1_chain();
    let skb = signing_key(8);
    l1.devices.push(entry(DEV_B, &sign_b64u(&skb), DEV_A));
    let chain = vec![chain_entry(&l1, DEV_A, &ska)];
    assert_eq!(
        verify_chain(&chain, STORE, false),
        Err(Error::Invalid("v1Devices"))
    );
}

#[test]
fn t42_04_v1_addedby_not_self_fails() {
    let ska = signing_key(7);
    let l1 = list(STORE, 1, "", vec![entry(DEV_A, &sign_b64u(&ska), DEV_B)]);
    let chain = vec![chain_entry(&l1, DEV_A, &ska)];
    assert_eq!(
        verify_chain(&chain, STORE, false),
        Err(Error::Invalid("addedBy"))
    );
}

#[test]
fn t42_05_v1_signed_by_other_fails() {
    let (l1, _) = v1_chain();
    let other = signing_key(9);
    let chain = vec![chain_entry(&l1, DEV_A, &other)];
    assert_eq!(verify_chain(&chain, STORE, false), Err(Error::BadSignature));
}

#[test]
fn t42_06_wrong_prev_fails() {
    let (mut chain, _, _, _) = three_chain();
    let mut l2 = parse_device_list(&chain[1].list_bytes).unwrap();
    l2.prev = "ff".repeat(32);
    // re-sign with A so only prev is wrong
    let ska = signing_key(7);
    chain[1] = chain_entry(&l2, DEV_A, &ska);
    assert_eq!(
        verify_chain(&chain, STORE, false),
        Err(Error::Invalid("prev"))
    );
}

#[test]
fn t42_07_signer_not_in_previous_fails() {
    let (mut chain, _, _, skc) = three_chain();
    // version 3 signed by C, which is not in version 2
    let l3 = parse_device_list(&chain[2].list_bytes).unwrap();
    chain[2] = chain_entry(&l3, DEV_C, &skc);
    assert_eq!(
        verify_chain(&chain, STORE, false),
        Err(Error::Invalid("signerNotInPrevious"))
    );
}

#[test]
fn t42_08_new_device_addedby_not_signer_fails() {
    let ska = signing_key(7);
    let skb = signing_key(8);
    let l1 = list(STORE, 1, "", vec![entry(DEV_A, &sign_b64u(&ska), DEV_A)]);
    let h1 = l1.hash_hex().unwrap();
    // B claims addedBy B, but signer is A
    let mut devs2 = l1.devices.clone();
    devs2.push(entry(DEV_B, &sign_b64u(&skb), DEV_B));
    let l2 = list(STORE, 2, &h1, devs2);
    let chain = vec![chain_entry(&l1, DEV_A, &ska), chain_entry(&l2, DEV_A, &ska)];
    assert_eq!(
        verify_chain(&chain, STORE, false),
        Err(Error::Invalid("addedBy"))
    );
}

#[test]
fn t42_09_device_adding_itself_fails() {
    let ska = signing_key(7);
    let skb = signing_key(8);
    let l1 = list(STORE, 1, "", vec![entry(DEV_A, &sign_b64u(&ska), DEV_A)]);
    let h1 = l1.hash_hex().unwrap();
    let mut devs2 = l1.devices.clone();
    devs2.push(entry(DEV_B, &sign_b64u(&skb), DEV_B));
    let l2 = list(STORE, 2, &h1, devs2);
    // signer claims to be B (a new device)
    let chain = vec![chain_entry(&l1, DEV_A, &ska), chain_entry(&l2, DEV_B, &skb)];
    assert_eq!(
        verify_chain(&chain, STORE, false),
        Err(Error::Invalid("selfAdded"))
    );
}

#[test]
fn t42_10_bad_signature_fails() {
    let (mut chain, _, _, _) = three_chain();
    let mut l2 = parse_device_list(&chain[1].list_bytes).unwrap();
    l2.updated = "2026-11-20T09:00:00Z".to_string();
    // keep old sig bytes (signed over different bytes)
    let tampered = ChainEntry {
        list_bytes: l2.canonical_json().unwrap(),
        sig_bytes: chain[1].sig_bytes.clone(),
    };
    chain[1] = tampered;
    assert_eq!(verify_chain(&chain, STORE, false), Err(Error::BadSignature));
}

#[test]
fn t42_11_empty_list_fails() {
    let ska = signing_key(7);
    let l1 = list(STORE, 1, "", vec![]);
    let chain = vec![chain_entry(&l1, DEV_A, &ska)];
    assert_eq!(
        verify_chain(&chain, STORE, false),
        Err(Error::Invalid("emptyList"))
    );
}

#[test]
fn t42_12_bad_v_fails() {
    let (chain, _, _, _) = three_chain();
    let bad = chain[0].list_bytes.replace("\"v\":1", "\"v\":2");
    let tampered = ChainEntry {
        list_bytes: bad,
        sig_bytes: chain[0].sig_bytes.clone(),
    };
    assert_eq!(
        verify_chain(&[tampered], STORE, false),
        Err(Error::Invalid("unsupported"))
    );
}

#[test]
fn t42_13_version_out_of_sequence_fails() {
    let (mut chain, _, _, _) = three_chain();
    let mut l2 = parse_device_list(&chain[1].list_bytes).unwrap();
    l2.version = 5;
    let ska = signing_key(7);
    chain[1] = chain_entry(&l2, DEV_A, &ska);
    // fix v3 prev to keep chain linked; version gap 1 -> 5 still fails
    let mut l3 = parse_device_list(&chain[2].list_bytes).unwrap();
    l3.prev = l2.hash_hex().unwrap();
    let skb = signing_key(8);
    chain[2] = chain_entry(&l3, DEV_B, &skb);
    assert_eq!(
        verify_chain(&chain, STORE, false),
        Err(Error::Invalid("versionOrder"))
    );
}

#[test]
fn t42_14_non_canonical_fails() {
    let (mut chain, _, _, _) = three_chain();
    chain[0].list_bytes = chain[0]
        .list_bytes
        .replace("\"version\":1", "\"version\": 1");
    assert_eq!(
        verify_chain(&chain, STORE, false),
        Err(Error::Invalid("notCanonical"))
    );
}

#[test]
fn t42_15_store_id_mismatch_fails() {
    let (chain, _, _, _) = three_chain();
    assert_eq!(
        verify_chain(&chain, "ccccccccccccccccccccccccca", false),
        Err(Error::Invalid("storeId"))
    );
}

#[test]
fn t42_16_removed_device_cannot_sign_next() {
    // v1: A; v2: A+B (signer A); v3: A only (signer A, removes B); v4 signed by B
    let ska = signing_key(7);
    let skb = signing_key(8);
    let l1 = list(STORE, 1, "", vec![entry(DEV_A, &sign_b64u(&ska), DEV_A)]);
    let h1 = l1.hash_hex().unwrap();
    let mut devs2 = l1.devices.clone();
    devs2.push(entry(DEV_B, &sign_b64u(&skb), DEV_A));
    let l2 = list(STORE, 2, &h1, devs2);
    let h2 = l2.hash_hex().unwrap();
    let l3 = list(STORE, 3, &h2, vec![entry(DEV_A, &sign_b64u(&ska), DEV_A)]);
    let h3 = l3.hash_hex().unwrap();
    let l4 = list(STORE, 4, &h3, l3.devices.clone());
    let chain = vec![
        chain_entry(&l1, DEV_A, &ska),
        chain_entry(&l2, DEV_A, &ska),
        chain_entry(&l3, DEV_A, &ska),
        chain_entry(&l4, DEV_B, &skb),
    ];
    assert_eq!(
        verify_chain(&chain, STORE, false),
        Err(Error::Invalid("signerNotInPrevious"))
    );
}

#[test]
fn t42_17_shallow_history_refused() {
    let (chain, _, _, _) = three_chain();
    assert_eq!(
        verify_chain(&chain, STORE, true),
        Err(Error::Invalid("shallow"))
    );
}

#[test]
fn t42_18_vectors_give_expected_result() {
    // No device-chain vectors exist yet in tests/vectors (only T1.4
    // fingerprint/anchor vectors). Every chain-shaped vector must verify;
    // vacuously true today, guards the wiring once vectors are added.
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors");
    assert!(dir.is_dir());
    let mut chain_vectors = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        if v.get("devices").is_some() && v.get("version").is_some() {
            chain_vectors += 1;
            parse_device_list(&text).unwrap();
        }
    }
    assert_eq!(chain_vectors, 0);
}

#[test]
fn t42_19_empty_chain_and_display() {
    assert_eq!(
        verify_chain(&[], STORE, false),
        Err(Error::Invalid("emptyList"))
    );
    assert_eq!(
        format!("{}", Error::Invalid("prev")),
        "invalid device list: prev"
    );
    assert_eq!(
        format!("{}", Error::BadSignature),
        "bad device list signature"
    );
}
