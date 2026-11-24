//! T1.6-12 interop: dryoc and C libsodium read each other's envelopes.
//!
//! Requires the `libsodium-sys-stable` dev-dependency (bundled source build,
//! no system library needed). Layout follows spec 03 section 3.4.

use dryoc::classic::crypto_box::crypto_box_seed_keypair;

fn pair(seed: u8) -> ([u8; 32], [u8; 32]) {
    crypto_box_seed_keypair(&[seed; 32])
}

fn init() {
    unsafe {
        assert!(libsodium_sys::sodium_init() >= 0);
    }
}

fn parse_layout(bytes: &[u8]) -> (usize, &[u8], &[u8], Vec<&[u8]>) {
    assert_eq!(&bytes[..6], &[0x41, 0x52, 0x47, 0x55, 0x53, 0x01]);
    assert_eq!(bytes[6], 0x01);
    let plen = u32::from_be_bytes(bytes[7..11].try_into().unwrap()) as usize;
    let nonce = &bytes[11..35];
    let payload_end = 35 + plen + 16;
    let payload = &bytes[35..payload_end];
    let rcount =
        u16::from_be_bytes(bytes[payload_end..payload_end + 2].try_into().unwrap()) as usize;
    let mut sealed = Vec::new();
    let mut off = payload_end + 2;
    for _ in 0..rcount {
        sealed.push(&bytes[off..off + 80]);
        off += 80;
    }
    assert_eq!(off, bytes.len());
    (plen, nonce, payload, sealed)
}

#[test]
fn t16_12a_dryoc_file_decrypts_through_c_libsodium() {
    init();
    let (pk, sk) = pair(201);
    let plaintext = b"interop dryoc -> c";
    let bytes = vault_core::envelope::encrypt(plaintext, &[pk]);
    let (plen, nonce, payload, sealed) = parse_layout(&bytes);

    let mut file_key = [0u8; 32];
    let rc = unsafe {
        libsodium_sys::crypto_box_seal_open(
            file_key.as_mut_ptr(),
            sealed[0].as_ptr(),
            sealed[0].len() as u64,
            pk.as_ptr(),
            sk.as_ptr(),
        )
    };
    assert_eq!(rc, 0, "C seal_open must open dryoc's sealed key");

    let mut out = vec![0u8; plen];
    let rc = unsafe {
        libsodium_sys::crypto_secretbox_open_easy(
            out.as_mut_ptr(),
            payload.as_ptr(),
            payload.len() as u64,
            nonce.as_ptr(),
            file_key.as_ptr(),
        )
    };
    assert_eq!(rc, 0, "C secretbox open must verify dryoc's payload");
    let mut expected = vec![b' '; plen];
    expected[..plaintext.len()].copy_from_slice(plaintext);
    assert_eq!(out, expected);
}

#[test]
fn t16_12b_c_libsodium_file_decrypts_through_dryoc() {
    init();
    let (pk, sk) = pair(202);
    let plaintext = b"interop c -> dryoc";
    let plen = plaintext.len().div_ceil(512) * 512;
    let mut padded = vec![b' '; plen];
    padded[..plaintext.len()].copy_from_slice(plaintext);

    let file_key = [0x77u8; 32];
    let nonce = [0x99u8; 24];
    let mut payload = vec![0u8; plen + 16];
    let rc = unsafe {
        libsodium_sys::crypto_secretbox_easy(
            payload.as_mut_ptr(),
            padded.as_ptr(),
            padded.len() as u64,
            nonce.as_ptr(),
            file_key.as_ptr(),
        )
    };
    assert_eq!(rc, 0);

    let mut sealed = [0u8; 80];
    let rc = unsafe {
        libsodium_sys::crypto_box_seal(
            sealed.as_mut_ptr(),
            file_key.as_ptr(),
            file_key.len() as u64,
            pk.as_ptr(),
        )
    };
    assert_eq!(rc, 0);

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&[0x41, 0x52, 0x47, 0x55, 0x53, 0x01]);
    bytes.push(0x01);
    bytes.extend_from_slice(&(plen as u32).to_be_bytes());
    bytes.extend_from_slice(&nonce);
    bytes.extend_from_slice(&payload);
    bytes.extend_from_slice(&1u16.to_be_bytes());
    bytes.extend_from_slice(&sealed);

    assert_eq!(
        vault_core::envelope::decrypt(&bytes, &pk, &sk).unwrap(),
        padded
    );
}
