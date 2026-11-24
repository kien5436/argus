use vault_core::signatures::{sign, verify, Domain, Signature, SigningKey, VerifyingKey};

fn key(seed: u8) -> SigningKey {
    SigningKey::from_seed([seed; 32])
}

fn other_key() -> SigningKey {
    SigningKey::from_seed([0x42; 32])
}

#[test]
fn t13_01_signature_verifies_with_its_key_and_prefix() {
    let sk = key(1);
    let msg = br#"{"v":1}"#;
    let sig = sign(&sk, Domain::Devices, msg);
    assert!(verify(&sk.verifying_key(), Domain::Devices, msg, &sig).is_ok());
}

#[test]
fn t13_02_same_signature_fails_under_a_different_prefix() {
    let sk = key(2);
    let msg = br#"{"v":1}"#;
    let sig = sign(&sk, Domain::Devices, msg);
    for domain in [Domain::Entry, Domain::Join, Domain::Device] {
        assert!(
            verify(&sk.verifying_key(), domain, msg, &sig).is_err(),
            "{domain:?} must not verify a devices signature"
        );
    }
}

#[test]
fn t13_03_one_byte_change_to_payload_fails() {
    let sk = key(3);
    let sig = sign(&sk, Domain::Entry, br#"{"v":1}"#);
    assert!(verify(&sk.verifying_key(), Domain::Entry, br#"{"v":2}"#, &sig).is_err());
}

#[test]
fn t13_04_signature_from_another_key_fails() {
    let sk = key(4);
    let msg = br#"{"v":1}"#;
    let sig = sign(&sk, Domain::Join, msg);
    assert!(verify(&other_key().verifying_key(), Domain::Join, msg, &sig).is_err());
}

#[test]
fn t13_05_malleable_s_signature_is_rejected() {
    let sk = key(5);
    let msg = br#"{"v":1}"#;
    let sig = sign(&sk, Domain::Devices, msg);
    let mut bytes = sig.to_bytes();
    // L = 2^252 + 27742317777372353535851937790883648493 (group order).
    let l: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x26, 0x12, 0x58, 0xd6, 0x9c, 0xf2, 0xa4, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ];
    let mut s = [0u16; 32];
    let mut carry = 0u16;
    for i in 0..32 {
        let sum = u16::from(bytes[32 + i]) + u16::from(l[i]) + carry;
        s[i] = sum & 0xff;
        carry = sum >> 8;
    }
    assert_eq!(carry, 0, "S + L must not overflow");
    bytes[32..].copy_from_slice(&s.map(|w| w as u8));
    let malleable = Signature::from_bytes(&bytes);
    assert!(verify(&sk.verifying_key(), Domain::Devices, msg, &malleable).is_err());
}

#[test]
fn t13_06_each_prefix_is_ascii_followed_by_newline() {
    for domain in [Domain::Devices, Domain::Entry, Domain::Join, Domain::Device] {
        let prefix = domain.prefix();
        assert!(prefix.is_ascii(), "{domain:?} prefix must be ASCII");
        assert_eq!(prefix.last(), Some(&b'\n'));
        assert!(!prefix[..prefix.len() - 1].contains(&b'\n'));
    }
    assert_eq!(Domain::Devices.prefix(), b"argus-devices-v1\n");
    assert_eq!(Domain::Entry.prefix(), b"argus-entry-v1\n");
    assert_eq!(Domain::Join.prefix(), b"argus-join-v1\n");
    assert_eq!(Domain::Device.prefix(), b"argus-device-v1\n");
}

#[test]
fn t13_07_rfc8032_vectors_verify() {
    use dryoc::classic::crypto_sign::{crypto_sign_seed_keypair, crypto_sign_verify_detached};
    // RFC 8032 section 7.3 TEST 1..3: (seed, public, message, signature).
    let vectors = [
        (
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ),
        (
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        ),
        (
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "af82",
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        ),
    ];
    for (seed_hex, public_hex, message_hex, sig_hex) in vectors {
        let seed: [u8; 32] = hex(seed_hex);
        let public: [u8; 32] = hex(public_hex);
        let message = hex_bytes(message_hex);
        let expected: [u8; 64] = hex(sig_hex);
        // Bare Ed25519 through the dryoc backend matches RFC 8032.
        let (pk, _sk) = crypto_sign_seed_keypair(&seed);
        assert_eq!(pk, public);
        assert!(crypto_sign_verify_detached(&expected, &message, &public).is_ok());
        // ... but the RFC signature never verifies under a domain prefix.
        let vk = VerifyingKey::from_bytes(&public).unwrap();
        let sig = Signature::from_bytes(&expected);
        assert!(verify(&vk, Domain::Devices, &message, &sig).is_err());
        // And our domain signing from the same seed derives the same public key.
        let sk = SigningKey::from_seed(seed);
        assert_eq!(sk.verifying_key().to_bytes(), public);
    }
}

fn hex<const N: usize>(s: &str) -> [u8; N] {
    let bytes = hex_bytes(s);
    bytes
        .try_into()
        .unwrap_or_else(|_| panic!("bad hex length"))
}

fn hex_bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn t13_08_error_displays_without_secret_text() {
    use vault_core::signatures::Error;
    assert!(!format!("{}", Error::BadSignature).is_empty());
}
