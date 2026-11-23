use rand::TryRng;
use std::convert::Infallible;
use vault_core::encodings::{b64u_decode, b64u_encode, generate_id, sha256_hex, validate_id};

#[test]
fn t12_01_sha256_matches_nist_vectors() {
    assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn t12_02_base64url_round_trips_rfc4648_vectors_without_padding_or_sign_chars() {
    let vectors = [
        ("", ""),
        ("f", "Zg"),
        ("fo", "Zm8"),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg"),
        ("fooba", "Zm9vYmE"),
        ("foobar", "Zm9vYmFy"),
    ];
    for (raw, encoded) in vectors {
        assert_eq!(b64u_encode(raw.as_bytes()), encoded);
        assert_eq!(b64u_decode(encoded).unwrap(), raw.as_bytes());
    }
    assert!(!b64u_encode(b"\xfb\xff\xfe").contains(['=', '+', '/']));
    assert!(b64u_decode("Zm9v=").is_err());
    assert!(b64u_decode("Zm9v/Yg").is_err());
}

#[test]
fn t12_03_id_is_26_chars_lowercase_base32() {
    struct Zero;
    impl TryRng for Zero {
        type Error = Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Infallible> {
            Ok(0)
        }
        fn try_next_u64(&mut self) -> Result<u64, Infallible> {
            Ok(0)
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Infallible> {
            dest.fill(0);
            Ok(())
        }
    }
    let id = generate_id(&mut Zero);
    assert_eq!(id.len(), 26);
    assert!(id.bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7')));
}

#[test]
fn t12_04_fixed_rng_gives_fixed_id() {
    struct Counter(u8);
    impl TryRng for Counter {
        type Error = Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Infallible> {
            Ok(u32::from(self.0) << 24)
        }
        fn try_next_u64(&mut self) -> Result<u64, Infallible> {
            Ok(0)
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Infallible> {
            for b in dest.iter_mut() {
                let v = self.0;
                self.0 = self.0.wrapping_add(1);
                *b = v;
            }
            Ok(())
        }
    }
    let first = generate_id(&mut Counter(0));
    let second = generate_id(&mut Counter(0));
    assert_eq!(first, second);
    assert_ne!(first, generate_id(&mut Counter(1)));
}

#[test]
fn t12_05_real_rng_never_collides_in_10000_samples() {
    use std::collections::HashSet;
    let mut rng = rand::rng();
    let mut seen = HashSet::new();
    for _ in 0..10_000 {
        assert!(seen.insert(generate_id(&mut rng)));
    }
}

#[test]
fn t12_06_decoding_bad_id_is_an_error() {
    assert!(validate_id(&generate_id(&mut rand::rng())).is_ok());
    assert!(validate_id("abc").is_err());
    assert!(validate_id(&"a".repeat(27)).is_err());
    assert!(validate_id(&"0".repeat(26)).is_err());
    assert!(validate_id(&"!".repeat(26)).is_err());
    assert!(validate_id(&"A".repeat(26)).is_err());
}

#[test]
fn t12_07_errors_display_without_input_text() {
    use vault_core::encodings::Error;
    assert!(!format!("{}", Error::InvalidBase64).is_empty());
    assert!(!format!("{}", Error::InvalidId).is_empty());
}
