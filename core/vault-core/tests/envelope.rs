//! T1.6 crypto envelope tests (spec 03 section 3.4).

use dryoc::classic::crypto_box::crypto_box_seed_keypair;
use vault_core::envelope::{add_recipient, decrypt, encrypt, Error};

fn pair(seed: u8) -> ([u8; 32], [u8; 32]) {
    let s = [seed; 32];
    crypto_box_seed_keypair(&s)
}

/// Plaintext as stored: padded with trailing spaces to 512 bytes.
fn padded(plaintext: impl AsRef<[u8]>) -> Vec<u8> {
    let plaintext = plaintext.as_ref();
    if plaintext.is_empty() {
        return Vec::new();
    }
    let plen = plaintext.len().div_ceil(512) * 512;
    let mut out = vec![b' '; plen];
    out[..plaintext.len()].copy_from_slice(plaintext);
    out
}

#[test]
fn t16_01_encrypt_then_decrypt_one_recipient_round_trips() {
    let (pk, sk) = pair(1);
    let plaintext = b"hello argus";
    let bytes = encrypt(plaintext, &[pk]);
    assert_eq!(decrypt(&bytes, &pk, &sk).unwrap(), padded(plaintext));
}

#[test]
fn t16_02_encrypt_to_two_recipients_either_decrypts() {
    let (pk1, sk1) = pair(11);
    let (pk2, sk2) = pair(22);
    let plaintext = b"shared secret";
    let bytes = encrypt(plaintext, &[pk1, pk2]);
    assert_eq!(decrypt(&bytes, &pk1, &sk1).unwrap(), padded(plaintext));
    assert_eq!(decrypt(&bytes, &pk2, &sk2).unwrap(), padded(plaintext));
}

#[test]
fn t16_03_decrypt_with_identity_not_in_set_fails() {
    let (pk, _sk) = pair(31);
    let (other_pk, other_sk) = pair(32);
    let bytes = encrypt(b"data", &[pk]);
    assert_eq!(
        decrypt(&bytes, &other_pk, &other_sk).unwrap_err(),
        Error::DecryptFailed
    );
}

#[test]
fn t16_04_flipped_byte_in_magic_version_plen_rcount_fails() {
    let (pk, sk) = pair(41);
    let bytes = encrypt(b"data", &[pk]);
    // Offsets: magic 0..6, version 6, plen 7..11, payload 11+24=35..,
    // rcount at 35+plen+16.
    let plen = u32::from_be_bytes(bytes[7..11].try_into().unwrap()) as usize;
    let rcount_off = 35 + plen + 16;
    for &off in &[0usize, 6, 7, rcount_off] {
        let mut bad = bytes.clone();
        bad[off] ^= 0x01;
        assert!(
            decrypt(&bad, &pk, &sk).is_err(),
            "flip at offset {off} must fail"
        );
    }
}

#[test]
fn t16_05_flipped_byte_in_payload_fails_authentication() {
    let (pk, sk) = pair(51);
    let bytes = encrypt(b"payload tamper test", &[pk]);
    let mut bad = bytes.clone();
    bad[40] ^= 0x01;
    assert_eq!(decrypt(&bad, &pk, &sk).unwrap_err(), Error::DecryptFailed);
}

#[test]
fn t16_06_empty_plaintext_round_trips() {
    let (pk, sk) = pair(61);
    let bytes = encrypt(b"", &[pk]);
    assert_eq!(decrypt(&bytes, &pk, &sk).unwrap(), b"");
}

#[test]
fn t16_07_one_mib_round_trips() {
    let (pk, sk) = pair(71);
    let plaintext = vec![0xABu8; 1_048_576];
    let bytes = encrypt(&plaintext, &[pk]);
    assert_eq!(decrypt(&bytes, &pk, &sk).unwrap(), padded(plaintext));
}

#[test]
fn t16_08_truncated_ciphertext_fails() {
    let (pk, sk) = pair(81);
    let bytes = encrypt(b"truncate me", &[pk]);
    let short = &bytes[..bytes.len() / 2];
    assert!(decrypt(short, &pk, &sk).is_err());
}

#[test]
fn t16_09_plen_not_multiple_of_512_or_over_1mib_is_damaged() {
    let (pk, sk) = pair(91);
    let bytes = encrypt(b"x", &[pk]);
    // plen = 1 is not a multiple of 512.
    let mut bad = bytes.clone();
    bad[7..11].copy_from_slice(&1u32.to_be_bytes());
    assert_eq!(decrypt(&bad, &pk, &sk).unwrap_err(), Error::Damaged("plen"));
    // plen over the maximum.
    let mut bad2 = bytes.clone();
    bad2[7..11].copy_from_slice(&(1_048_577u32).to_be_bytes());
    assert_eq!(
        decrypt(&bad2, &pk, &sk).unwrap_err(),
        Error::Damaged("plen")
    );
}

#[test]
fn t16_10_add_recipient_appends_sealed_key_payload_unchanged() {
    let (pk1, sk1) = pair(101);
    let (pk2, sk2) = pair(102);
    let plaintext = b"approve path";
    let before = encrypt(plaintext, &[pk1]);
    let plen = u32::from_be_bytes(before[7..11].try_into().unwrap()) as usize;
    let payload_end = 35 + plen + 16;
    let after = add_recipient(&before, &pk2, &pk1, &sk1).unwrap();
    // Nonce, plen, payload and file key unchanged: compare those slices.
    assert_eq!(&after[7..payload_end], &before[7..payload_end]);
    // New device decrypts, original still decrypts.
    assert_eq!(decrypt(&after, &pk2, &sk2).unwrap(), padded(plaintext));
    assert_eq!(decrypt(&after, &pk1, &sk1).unwrap(), padded(plaintext));
    // rcount bumped by one.
    let r0 = u16::from_be_bytes(before[payload_end..payload_end + 2].try_into().unwrap());
    let r1 = u16::from_be_bytes(after[payload_end..payload_end + 2].try_into().unwrap());
    assert_eq!((r0, r1), (1, 2));
}

#[test]
fn t16_11_rcount_mismatch_marks_entry_damaged() {
    let (pk, sk) = pair(111);
    let bytes = encrypt(b"data", &[pk]);
    let plen = u32::from_be_bytes(bytes[7..11].try_into().unwrap()) as usize;
    let rcount_off = 35 + plen + 16;
    let mut bad = bytes.clone();
    let r = u16::from_be_bytes(bad[rcount_off..rcount_off + 2].try_into().unwrap());
    bad[rcount_off..rcount_off + 2].copy_from_slice(&(r + 1).to_be_bytes());
    assert_eq!(
        decrypt(&bad, &pk, &sk).unwrap_err(),
        Error::Damaged("rcount")
    );
}

#[test]
fn t16_13_input_shorter_than_header_is_damaged() {
    let (pk, sk) = pair(121);
    assert_eq!(
        decrypt(&[0x41u8; 10], &pk, &sk).unwrap_err(),
        Error::Damaged("truncated")
    );
    assert_eq!(
        decrypt(&[], &pk, &sk).unwrap_err(),
        Error::Damaged("truncated")
    );
}

#[test]
fn t16_14_error_displays_without_secret_text() {
    assert_eq!(format!("{}", Error::Damaged("plen")), "damaged entry: plen");
    assert_eq!(format!("{}", Error::DecryptFailed), "decryption failed");
}
