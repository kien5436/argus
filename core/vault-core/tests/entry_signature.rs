//! T1.8 entry signature tests (spec 03 section 3.4, Entry signature).

use vault_core::entry::{Entry, Error};
use vault_core::signatures::{sign, Domain, SigningKey, VerifyingKey};

fn device(id_seed: u8, key_seed: u8) -> (String, SigningKey, VerifyingKey) {
    let id = format!("{id_seed:026}");
    let sk = SigningKey::from_seed([key_seed; 32]);
    let vk = sk.verifying_key();
    (id, sk, vk)
}

fn signed_note() -> (Entry, String, VerifyingKey) {
    let (id, sk, vk) = device(1, 7);
    let mut entry = Entry::new_note(
        "bbbbbbbbbbbbbbbbbbbbbbbbbb",
        "2026-11-19T09:00:00Z",
        "name",
        "content",
    );
    entry.sign(&id, &sk).unwrap();
    (entry, id, vk)
}

#[test]
fn t18_01_signed_entry_verifies_with_signers_key() {
    let (entry, id, vk) = signed_note();
    assert_eq!(entry.verify(&[(&id, &vk)]), Ok(()));
}

#[test]
fn t18_02_changing_any_field_after_signing_fails() {
    let (mut entry, id, vk) = signed_note();
    entry.prepare_edit("2026-11-19T10:00:00Z");
    assert_eq!(
        entry.verify(&[(&id, &vk)]),
        Err(Error::Invalid("signature"))
    );
}

#[test]
fn t18_03_signature_from_key_not_in_list_fails() {
    let (entry, _id, _vk) = signed_note();
    let (other_id, _, other_vk) = device(2, 9);
    assert_eq!(
        entry.verify(&[(&other_id, &other_vk)]),
        Err(Error::Invalid("signer"))
    );
}

#[test]
fn t18_04_sig_by_mismatch_with_key_found_fails() {
    // Signed by B's key but names A's id: lookup finds A's key, check fails.
    let (id_a, _sk_a, vk_a) = device(1, 7);
    let (_id_b, sk_b, _vk_b) = device(2, 8);
    let mut entry = Entry::new_note(
        "bbbbbbbbbbbbbbbbbbbbbbbbbb",
        "2026-11-19T09:00:00Z",
        "name",
        "content",
    );
    entry.sign(&id_a, &sk_b).unwrap();
    assert_eq!(
        entry.verify(&[(&id_a, &vk_a)]),
        Err(Error::Invalid("signature"))
    );
}

#[test]
fn t18_05_devices_prefix_signature_does_not_verify_as_entry() {
    use vault_core::canonical_json::canonicalize;
    use vault_core::encodings::b64u_encode;

    let (id, sk, vk) = device(1, 7);
    let entry = Entry::new_note(
        "bbbbbbbbbbbbbbbbbbbbbbbbbb",
        "2026-11-19T09:00:00Z",
        "name",
        "content",
    );
    // Sign the unsigned canonical bytes under the wrong domain, splice the
    // sig in as raw JSON, and parse back: public API only.
    let unsigned = entry.encode().unwrap();
    let text = std::str::from_utf8(&unsigned).unwrap().trim_end();
    let canonical = canonicalize(text).unwrap();
    let sig = sign(&sk, Domain::Devices, canonical.as_bytes());
    let mut value: serde_json::Value = serde_json::from_str(text).unwrap();
    value["sig"] = serde_json::json!({"by": id, "v": b64u_encode(&sig.to_bytes())});
    let hacked = serde_json::to_vec(&value).unwrap();
    let entry = Entry::decode(&hacked).unwrap();
    assert_eq!(
        entry.verify(&[(&id, &vk)]),
        Err(Error::Invalid("signature"))
    );
}

#[test]
fn t18_06_sig_missing_from_entry_fails_verification() {
    let (id, _sk, vk) = device(1, 7);
    let entry = Entry::new_note(
        "bbbbbbbbbbbbbbbbbbbbbbbbbb",
        "2026-11-19T09:00:00Z",
        "name",
        "content",
    );
    assert_eq!(entry.verify(&[(&id, &vk)]), Err(Error::Invalid("sig")));
}
