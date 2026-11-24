//! T4.4 recipient set and encrypt guard (spec 03 section 3.5 rule 7).

use vault_core::device_list::{ChainEntry, DeviceEntry, DeviceList};
use vault_core::encodings::b64u_encode;
use vault_core::recipients::{Error, VerifiedList};
use vault_core::signatures::SigningKey;

const ENC_A: &str = "argus1qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0s4vsgja";
const STORE: &str = "bbbbbbbbbbbbbbbbbbbbbbbbba";
const DEV_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaa";
const DEV_B: &str = "ccccccccccccccccccccccccca";

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_seed([seed; 32])
}

fn sign_b64u(sk: &SigningKey) -> String {
    b64u_encode(&sk.verifying_key().to_bytes())
}

fn entry(id: &str, enc: &str, sign_b64u: &str, added_by: &str) -> DeviceEntry {
    DeviceEntry {
        id: id.to_string(),
        name: format!("dev-{id}"),
        enc: enc.to_string(),
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
    ChainEntry {
        list_bytes: bytes,
        sig_bytes: sig.to_canonical_json().unwrap(),
    }
}

fn two_chain() -> (Vec<ChainEntry>, SigningKey, SigningKey, DeviceList) {
    let ska = signing_key(7);
    let skb = signing_key(8);
    let l1 = list(
        STORE,
        1,
        "",
        vec![entry(DEV_A, ENC_A, &sign_b64u(&ska), DEV_A)],
    );
    let h1 = l1.hash_hex().unwrap();
    let mut devs2 = l1.devices.clone();
    devs2.push(entry(DEV_B, ENC_A, &sign_b64u(&skb), DEV_A));
    let l2 = list(STORE, 2, &h1, devs2);
    let chain = vec![chain_entry(&l1, DEV_A, &ska), chain_entry(&l2, DEV_A, &ska)];
    (chain, ska, skb, l2)
}

#[test]
fn t44_01_recipient_set_equals_newest_verified_list() {
    let (chain, _, _, l2) = two_chain();
    let verified = VerifiedList::verify(&chain, STORE, false).unwrap();
    assert_eq!(verified.version(), 2);
    assert_eq!(verified.device_list(), &l2);
    // Both devices share ENC_A here, so two identical keys in list order.
    assert_eq!(verified.recipient_keys().len(), 2);
}

#[test]
fn t44_02_encrypt_with_unverified_list_fails() {
    let (mut chain, _, _, _) = two_chain();
    // Tamper the newest version so verification fails; encryption must refuse.
    let mut l2: DeviceList =
        vault_core::device_list::parse_device_list(&chain[1].list_bytes).unwrap();
    l2.updated = "2026-11-20T09:00:00Z".to_string();
    chain[1].list_bytes = l2.canonical_json().unwrap();
    let err = VerifiedList::verify(&chain, STORE, false).unwrap_err();
    assert_eq!(err, Error::VerificationFailed("badSignature"));
    assert!(format!("{err}").contains("VerificationFailed"));
}

#[test]
fn t44_03_removed_device_is_not_a_recipient() {
    let ska = signing_key(7);
    let skb = signing_key(8);
    let l1 = list(
        STORE,
        1,
        "",
        vec![entry(DEV_A, ENC_A, &sign_b64u(&ska), DEV_A)],
    );
    let h1 = l1.hash_hex().unwrap();
    let mut devs2 = l1.devices.clone();
    devs2.push(entry(DEV_B, ENC_A, &sign_b64u(&skb), DEV_A));
    let l2 = list(STORE, 2, &h1, devs2);
    let h2 = l2.hash_hex().unwrap();
    // v3 removes B, signed by A.
    let l3 = list(
        STORE,
        3,
        &h2,
        vec![entry(DEV_A, ENC_A, &sign_b64u(&ska), DEV_A)],
    );
    let chain = vec![
        chain_entry(&l1, DEV_A, &ska),
        chain_entry(&l2, DEV_A, &ska),
        chain_entry(&l3, DEV_A, &ska),
    ];
    let verified = VerifiedList::verify(&chain, STORE, false).unwrap();
    assert_eq!(verified.recipient_keys().len(), 1);
    let removed = vault_core::identity::parse_recipient(ENC_A).unwrap();
    assert!(verified.recipient_keys().contains(removed.bytes()));
}

#[test]
fn t44_04_entry_signed_by_unknown_device_refused_as_security_alert() {
    use vault_core::entry::Entry;
    let (chain, _, _, _) = two_chain();
    let verified = VerifiedList::verify(&chain, STORE, false).unwrap();
    // Entry signed by a key not in the current list.
    let outsider = signing_key(99);
    let outsider_id = "eeeeeeeeeeeeeeeeeeeeeeeeea";
    let mut e = Entry::new_credential(
        "aaaaaaaaaaaaaaaaaaaaaaaaaa",
        "2026-11-19T09:00:00Z",
        "https://example.com",
        "user",
        "pw",
        "",
    );
    e.sign(outsider_id, &outsider).unwrap();
    let err = verified.verify_entry(&e).unwrap_err();
    assert_eq!(err, Error::UnknownSigner);
    assert!(format!("{err}").contains("security alert"));
}

fn enc_of(pk: &[u8; 32]) -> String {
    use bech32::{Bech32m, Hrp};
    let hrp = Hrp::parse("argus").unwrap();
    bech32::encode::<Bech32m>(hrp, pk).unwrap()
}

fn box_pair(seed: u8) -> ([u8; 32], [u8; 32]) {
    dryoc::classic::crypto_box::crypto_box_seed_keypair(&[seed; 32])
}

#[test]
fn t44_05_encrypt_to_verified_recipients_round_trips() {
    let (pk, sk) = box_pair(21);
    let ska = signing_key(7);
    let l1 = list(
        STORE,
        1,
        "",
        vec![entry(DEV_A, &enc_of(&pk), &sign_b64u(&ska), DEV_A)],
    );
    let chain = vec![chain_entry(&l1, DEV_A, &ska)];
    let verified = VerifiedList::verify(&chain, STORE, false).unwrap();
    assert_eq!(verified.hash(), l1.hash_hex().unwrap());
    assert_eq!(verified.recipient_keys(), &[pk]);
    let bytes = verified.encrypt(b"hello argus").unwrap();
    let plain = vault_core::envelope::decrypt(&bytes, &pk, &sk).unwrap();
    assert!(plain.starts_with(b"hello argus"));
}

#[test]
fn t44_06_entry_signed_by_listed_device_verifies() {
    use vault_core::entry::Entry;
    let (chain, ska, _, _) = two_chain();
    let verified = VerifiedList::verify(&chain, STORE, false).unwrap();
    let mut e = Entry::new_credential(
        "aaaaaaaaaaaaaaaaaaaaaaaaaa",
        "2026-11-19T09:00:00Z",
        "https://example.com",
        "user",
        "pw",
        "",
    );
    e.sign(DEV_A, &ska).unwrap();
    verified.verify_entry(&e).unwrap();
}

#[test]
fn t44_07_tampered_entry_fails_verification() {
    use vault_core::entry::Entry;
    let (chain, ska, _, _) = two_chain();
    let verified = VerifiedList::verify(&chain, STORE, false).unwrap();
    let mut e = Entry::new_credential(
        "aaaaaaaaaaaaaaaaaaaaaaaaaa",
        "2026-11-19T09:00:00Z",
        "https://example.com",
        "user",
        "pw",
        "",
    );
    e.sign(DEV_A, &ska).unwrap();
    // Re-sign over different bytes, then restore the original signature text
    // by signing a copy: simplest tamper is to edit after signing.
    e.prepare_edit("2026-11-20T09:00:00Z");
    let err = verified.verify_entry(&e).unwrap_err();
    assert_eq!(err, Error::VerificationFailed("badSignature"));
    assert!(format!("{err}").contains("VerificationFailed"));
}

#[test]
fn t44_09_empty_history_fails_verification() {
    let err = VerifiedList::verify(&[], STORE, false).unwrap_err();
    assert_eq!(err, Error::VerificationFailed("emptyList"));
}

#[test]
fn t44_10_absurd_recipient_count_refused() {
    // More recipients than the envelope `rcount` field can hold: the guard
    // refuses instead of truncating. Device ids repeat; the point here is
    // the encrypt bound, not list hygiene.
    let ska = signing_key(7);
    let l1 = list(
        STORE,
        1,
        "",
        vec![entry(DEV_A, ENC_A, &sign_b64u(&ska), DEV_A)],
    );
    let h1 = l1.hash_hex().unwrap();
    let mut devs = l1.devices.clone();
    for _ in 0..65_537 {
        devs.push(entry(DEV_B, ENC_A, &sign_b64u(&ska), DEV_A));
    }
    let l2 = list(STORE, 2, &h1, devs);
    let chain = vec![chain_entry(&l1, DEV_A, &ska), chain_entry(&l2, DEV_A, &ska)];
    let verified = VerifiedList::verify(&chain, STORE, false).unwrap();
    assert_eq!(
        verified.encrypt(b"x").unwrap_err(),
        Error::Encrypt("refused")
    );
}

#[test]
fn t44_08_oversize_plaintext_refused() {
    let (chain, _, _, _) = two_chain();
    let verified = VerifiedList::verify(&chain, STORE, false).unwrap();
    let big = vec![b'x'; 1_048_577];
    assert_eq!(
        verified.encrypt(&big).unwrap_err(),
        Error::Encrypt("tooLarge")
    );
    assert!(format!("{}", Error::Encrypt("tooLarge")).contains("refused"));
}
