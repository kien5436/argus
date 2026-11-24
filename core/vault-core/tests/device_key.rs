//! T2.1 device.key tests. Fixed RNG and scripted KDF; no real secrets.

use rand::TryRng;
use subtle::ConstantTimeEq;
use vault_core::device_key::Kdf;
use vault_core::secrets::MasterPassword;

/// Deterministic xorshift64* RNG: reproducible ids, keys, salts, nonces.
struct FixedRng(u64);

impl FixedRng {
    fn step(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut i = 0;
        while i < dest.len() {
            let v = self.step().to_le_bytes();
            let n = (dest.len() - i).min(8);
            dest[i..i + n].copy_from_slice(&v[..n]);
            i += n;
        }
    }
}

impl TryRng for FixedRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.step() as u32)
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(self.step())
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand::TryCryptoRng for FixedRng {}

/// Scripted KDF: records requested (opslimit, memlimit), fails when told to,
/// and derives deterministically via SHA-256 so tests stay fast.
struct ScriptedKdf {
    calls: std::cell::RefCell<Vec<(u64, usize)>>,
    fail_at_or_above: usize,
}

impl ScriptedKdf {
    fn always_ok() -> Self {
        Self {
            calls: std::cell::RefCell::new(Vec::new()),
            fail_at_or_above: usize::MAX,
        }
    }
}

impl Kdf for ScriptedKdf {
    fn derive(
        &self,
        out: &mut [u8],
        password: &[u8],
        salt: &[u8],
        opslimit: u64,
        memlimit: usize,
    ) -> Result<(), vault_core::device_key::Error> {
        self.calls.borrow_mut().push((opslimit, memlimit));
        if memlimit >= self.fail_at_or_above {
            return Err(vault_core::device_key::Error::Kdf);
        }
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        h.update(password);
        h.update(salt);
        h.update(opslimit.to_le_bytes());
        h.update(memlimit.to_le_bytes());
        let d = h.finalize();
        for (i, b) in out.iter_mut().enumerate() {
            *b = d[i % d.len()];
        }
        Ok(())
    }
}

fn pw(s: &str) -> MasterPassword {
    MasterPassword::new(s.as_bytes().to_vec())
}

#[test]
fn t2_1_01_create_then_reopen_returns_same_keys() {
    let kdf = ScriptedKdf::always_ok();
    let mut rng = FixedRng(0x1234_5678_9abc_def0);
    let bytes = vault_core::device_key::create(&pw("correct horse battery staple"), &mut rng, &kdf);
    assert!(bytes.is_ok(), "create failed: {:?}", bytes.err());
    let bytes = bytes.unwrap();

    let opened = vault_core::device_key::open(&bytes, &pw("correct horse battery staple"), &kdf);
    assert!(opened.is_ok(), "open failed: {:?}", opened.err());
    let opened = opened.unwrap();

    let mut rng2 = FixedRng(0x1234_5678_9abc_def0);
    let again =
        vault_core::device_key::create(&pw("correct horse battery staple"), &mut rng2, &kdf)
            .unwrap();
    let opened2 =
        vault_core::device_key::open(&again, &pw("correct horse battery staple"), &kdf).unwrap();
    assert_eq!(opened.device_id, opened2.device_id);
    assert_eq!(opened.enc_public, opened2.enc_public);
    assert!(opened.enc_secret.ct_eq(&opened2.enc_secret).unwrap_u8() == 1);
    assert!(opened.sign_seed.ct_eq(&opened2.sign_seed).unwrap_u8() == 1);
}

#[test]
fn t2_1_02_wrong_password_fails_with_wrong_password() {
    let kdf = ScriptedKdf::always_ok();
    let mut rng = FixedRng(0xabcd);
    let bytes = vault_core::device_key::create(&pw("right password"), &mut rng, &kdf).unwrap();
    let err = vault_core::device_key::open(&bytes, &pw("wrong password"), &kdf).unwrap_err();
    assert_eq!(err, vault_core::device_key::Error::WrongPassword);
}

#[test]
fn t2_1_03_flipped_byte_fails_without_wrong_key() {
    let kdf = ScriptedKdf::always_ok();
    let mut rng = FixedRng(0xabcd);
    let bytes = vault_core::device_key::create(&pw("right password"), &mut rng, &kdf).unwrap();
    for pos in [7, 31, 55, bytes.len() - 1] {
        let mut bad = bytes.clone();
        bad[pos] ^= 0x01;
        let res = vault_core::device_key::open(&bad, &pw("right password"), &kdf);
        assert!(res.is_err(), "flipped byte at {pos} opened successfully");
    }
    // Corrupt magic reports damage, not a wrong password.
    let mut bad = bytes.clone();
    bad[0] ^= 0x01;
    assert_eq!(
        vault_core::device_key::open(&bad, &pw("right password"), &kdf).unwrap_err(),
        vault_core::device_key::Error::Corrupt("magic")
    );
}

#[test]
fn t2_1_04_header_records_opslimit_3_and_256mib() {
    let kdf = ScriptedKdf::always_ok();
    let mut rng = FixedRng(0x1111);
    let bytes = vault_core::device_key::create(&pw("password"), &mut rng, &kdf).unwrap();
    assert_eq!(&bytes[..6], b"ARGUSK");
    assert_eq!(bytes[6], 0x01);
    assert_eq!(u32::from_be_bytes(bytes[23..27].try_into().unwrap()), 3);
    assert_eq!(
        u32::from_be_bytes(bytes[27..31].try_into().unwrap()),
        256 * 1024 * 1024
    );
    assert_eq!(kdf.calls.borrow().as_slice(), &[(3, 256 * 1024 * 1024)]);
}

#[test]
fn t2_1_05_alloc_failure_falls_back_to_64mib_with_opslimit_3() {
    let kdf = ScriptedKdf {
        calls: std::cell::RefCell::new(Vec::new()),
        fail_at_or_above: 256 * 1024 * 1024,
    };
    let mut rng = FixedRng(0x2222);
    let bytes = vault_core::device_key::create(&pw("password"), &mut rng, &kdf).unwrap();
    assert_eq!(u32::from_be_bytes(bytes[23..27].try_into().unwrap()), 3);
    assert_eq!(
        u32::from_be_bytes(bytes[27..31].try_into().unwrap()),
        64 * 1024 * 1024
    );
    assert_eq!(
        kdf.calls.borrow().as_slice(),
        &[(3, 256 * 1024 * 1024), (3, 64 * 1024 * 1024)]
    );
    let opened = vault_core::device_key::open(&bytes, &pw("password"), &kdf).unwrap();
    assert_eq!(opened.device_id.len(), 26);
}

#[test]
fn t2_1_06_empty_master_password_is_refused() {
    let kdf = ScriptedKdf::always_ok();
    let mut rng = FixedRng(0x3333);
    assert_eq!(
        vault_core::device_key::create(&pw(""), &mut rng, &kdf).unwrap_err(),
        vault_core::device_key::Error::EmptyPassword
    );
}

#[test]
fn t2_1_07_unicode_passwords_round_trip() {
    let kdf = ScriptedKdf::always_ok();
    for password in ["pässwörd-🔑-test", "é", "é"] {
        let mut rng = FixedRng(0x4444);
        let bytes = vault_core::device_key::create(&pw(password), &mut rng, &kdf).unwrap();
        let opened = vault_core::device_key::open(&bytes, &pw(password), &kdf).unwrap();
        assert_eq!(opened.device_id.len(), 26);
    }
    // NFC: precomposed é opens a file created with combining e + acute.
    let mut rng = FixedRng(0x5555);
    let bytes = vault_core::device_key::create(&pw("é"), &mut rng, &kdf).unwrap();
    assert!(vault_core::device_key::open(&bytes, &pw("é"), &kdf).is_ok());
}

#[test]
fn t2_1_08_plaintext_has_only_documented_fields() {
    let kdf = ScriptedKdf::always_ok();
    let mut rng = FixedRng(0x6666);
    let password = "field check";
    let bytes = vault_core::device_key::create(&pw(password), &mut rng, &kdf).unwrap();
    // Re-derive the scripted key and decrypt the payload directly.
    let salt = &bytes[7..23];
    let mut key = [0u8; 32];
    kdf.derive(&mut key, password.as_bytes(), salt, 3, 256 * 1024 * 1024)
        .unwrap();
    let nonce: [u8; 24] = bytes[31..55].try_into().unwrap();
    let ct = &bytes[55..];
    let mut plain = vec![0u8; ct.len() - 16];
    dryoc::classic::crypto_secretbox::crypto_secretbox_open_easy(&mut plain, ct, &nonce, &key)
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&plain).unwrap();
    let obj = v.as_object().unwrap();
    let keys: std::collections::BTreeSet<&str> = obj.keys().map(String::as_str).collect();
    assert_eq!(keys, ["deviceId", "encSecret", "signSeed", "v"].into());
    assert_eq!(obj["v"], 1);
    // Extra fields are rejected on open.
    let extra = serde_json::json!({
        "v": 1,
        "deviceId": obj["deviceId"],
        "encSecret": obj["encSecret"],
        "signSeed": obj["signSeed"],
        "extra": "nope",
    });
    let extra_bytes = serde_json::to_vec(&extra).unwrap();
    let mut payload = vec![0u8; extra_bytes.len() + 16];
    dryoc::classic::crypto_secretbox::crypto_secretbox_easy(
        &mut payload,
        &extra_bytes,
        &nonce,
        &key,
    )
    .unwrap();
    let mut bad = bytes[..55].to_vec();
    bad.extend_from_slice(&payload);
    assert!(vault_core::device_key::open(&bad, &pw(password), &kdf).is_err());
}

#[test]
fn t2_1_09_two_devices_have_different_keys() {
    let kdf = ScriptedKdf::always_ok();
    let a = vault_core::device_key::create(&pw("same password"), &mut rand::rng(), &kdf).unwrap();
    let b = vault_core::device_key::create(&pw("same password"), &mut rand::rng(), &kdf).unwrap();
    assert_ne!(a, b);
    let ka = vault_core::device_key::open(&a, &pw("same password"), &kdf).unwrap();
    let kb = vault_core::device_key::open(&b, &pw("same password"), &kdf).unwrap();
    assert_ne!(ka.device_id, kb.device_id);
    assert_ne!(ka.enc_public, kb.enc_public);
}

#[test]
fn t2_1_real_kdf_round_trip() {
    let kdf = vault_core::device_key::RealKdf;
    let bytes =
        vault_core::device_key::create(&pw("real kdf password"), &mut rand::rng(), &kdf).unwrap();
    assert_eq!(u32::from_be_bytes(bytes[23..27].try_into().unwrap()), 3);
    let opened = vault_core::device_key::open(&bytes, &pw("real kdf password"), &kdf).unwrap();
    assert_eq!(opened.device_id.len(), 26);
    assert_eq!(
        vault_core::device_key::open(&bytes, &pw("nope"), &kdf).unwrap_err(),
        vault_core::device_key::Error::WrongPassword
    );
}

#[test]
fn t2_1_error_paths_and_displays_carry_no_secrets() {
    let kdf = ScriptedKdf::always_ok();
    let mut rng = FixedRng(0x7777);
    let bytes = vault_core::device_key::create(&pw("secret pw"), &mut rng, &kdf).unwrap();

    // Truncated, bad version, and unknown params are structural damage.
    assert_eq!(
        vault_core::device_key::open(&bytes[..10], &pw("secret pw"), &kdf).unwrap_err(),
        vault_core::device_key::Error::Corrupt("truncated")
    );
    let mut bad_version = bytes.clone();
    bad_version[6] = 0x02;
    assert_eq!(
        vault_core::device_key::open(&bad_version, &pw("secret pw"), &kdf).unwrap_err(),
        vault_core::device_key::Error::Corrupt("version")
    );
    let mut bad_params = bytes.clone();
    bad_params[27..31].copy_from_slice(&1u32.to_be_bytes());
    assert_eq!(
        vault_core::device_key::open(&bad_params, &pw("secret pw"), &kdf).unwrap_err(),
        vault_core::device_key::Error::Corrupt("params")
    );

    // Total KDF failure (even fallback) surfaces as Kdf, on create and open.
    let dead = ScriptedKdf {
        calls: std::cell::RefCell::new(Vec::new()),
        fail_at_or_above: 1,
    };
    assert_eq!(
        vault_core::device_key::create(&pw("secret pw"), &mut FixedRng(1), &dead).unwrap_err(),
        vault_core::device_key::Error::Kdf
    );
    assert_eq!(
        vault_core::device_key::open(&bytes, &pw("secret pw"), &dead).unwrap_err(),
        vault_core::device_key::Error::Kdf
    );

    // Non-UTF8 passwords are refused without secret text.
    let raw = vault_core::secrets::MasterPassword::new(vec![0xff, 0xfe]);
    assert_eq!(
        vault_core::device_key::create(&raw, &mut FixedRng(1), &kdf).unwrap_err(),
        vault_core::device_key::Error::InvalidPassword
    );

    // Displays carry no password or key text.
    for err in [
        vault_core::device_key::Error::WrongPassword,
        vault_core::device_key::Error::Corrupt("magic"),
        vault_core::device_key::Error::EmptyPassword,
        vault_core::device_key::Error::InvalidPassword,
        vault_core::device_key::Error::Kdf,
    ] {
        let shown = format!("{err}");
        assert!(!shown.contains("secret pw"), "leak in {shown:?}");
        assert!(!shown.is_empty());
    }
    let keys = vault_core::device_key::open(&bytes, &pw("secret pw"), &kdf).unwrap();
    for shown in [format!("{:?}", keys.enc_secret), format!("{keys:?}")] {
        assert!(!shown.contains("secret pw"), "leak in {shown:?}");
    }
}
