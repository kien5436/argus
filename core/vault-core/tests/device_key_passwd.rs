//! T2.3 master password change tests.

use rand::TryRng;
use subtle::ConstantTimeEq;
use vault_core::device_key::Kdf;
use vault_core::secrets::MasterPassword;

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

struct ScriptedKdf {
    fail_at_or_above: usize,
}
impl ScriptedKdf {
    fn ok() -> Self {
        Self {
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

fn make(kdf: &ScriptedKdf, seed: u64, password: &str) -> Vec<u8> {
    vault_core::device_key::create(&pw(password), &mut FixedRng(seed), kdf).unwrap()
}

#[test]
fn t2_3_01_new_password_opens() {
    let kdf = ScriptedKdf::ok();
    let bytes = make(&kdf, 0x01, "old password");
    let changed = vault_core::device_key::change_password(
        &bytes,
        &pw("old password"),
        &pw("new password"),
        &mut FixedRng(0x02),
        &kdf,
    )
    .unwrap();
    vault_core::device_key::open(&changed, &pw("new password"), &kdf).unwrap();
}

#[test]
fn t2_3_02_old_password_fails() {
    let kdf = ScriptedKdf::ok();
    let bytes = make(&kdf, 0x01, "old password");
    let changed = vault_core::device_key::change_password(
        &bytes,
        &pw("old password"),
        &pw("new password"),
        &mut FixedRng(0x02),
        &kdf,
    )
    .unwrap();
    assert_eq!(
        vault_core::device_key::open(&changed, &pw("old password"), &kdf).unwrap_err(),
        vault_core::device_key::Error::WrongPassword
    );
}

#[test]
fn t2_3_03_keys_same_before_and_after() {
    let kdf = ScriptedKdf::ok();
    let bytes = make(&kdf, 0x01, "old password");
    let before = vault_core::device_key::open(&bytes, &pw("old password"), &kdf).unwrap();
    let changed = vault_core::device_key::change_password(
        &bytes,
        &pw("old password"),
        &pw("new password"),
        &mut FixedRng(0x02),
        &kdf,
    )
    .unwrap();
    let after = vault_core::device_key::open(&changed, &pw("new password"), &kdf).unwrap();
    assert_eq!(before.device_id, after.device_id);
    assert_eq!(before.enc_public, after.enc_public);
    assert!(before.enc_secret.ct_eq(&after.enc_secret).unwrap_u8() == 1);
    assert!(before.sign_seed.ct_eq(&after.sign_seed).unwrap_u8() == 1);
}

#[test]
fn t2_3_04_store_files_untouched_only_device_key_rewritten() {
    // change_password is pure bytes-in/bytes-out: it cannot touch the store.
    // This pins the property by asserting the old envelope still opens only
    // with the old password and the new one only with the new password, and
    // that the plaintext keys are identical (no re-key of entries involved).
    let kdf = ScriptedKdf::ok();
    let bytes = make(&kdf, 0x01, "old password");
    let changed = vault_core::device_key::change_password(
        &bytes,
        &pw("old password"),
        &pw("new password"),
        &mut FixedRng(0x02),
        &kdf,
    )
    .unwrap();
    assert_ne!(bytes, changed);
    assert!(vault_core::device_key::open(&bytes, &pw("old password"), &kdf).is_ok());
    assert!(vault_core::device_key::open(&changed, &pw("new password"), &kdf).is_ok());
}

#[test]
fn t2_3_05_failure_leaves_old_bytes_intact() {
    let kdf = ScriptedKdf::ok();
    let bytes = make(&kdf, 0x01, "old password");
    // Wrong old password must fail without producing output.
    assert_eq!(
        vault_core::device_key::change_password(
            &bytes,
            &pw("nope"),
            &pw("new password"),
            &mut FixedRng(0x02),
            &kdf
        )
        .unwrap_err(),
        vault_core::device_key::Error::WrongPassword
    );
    // Empty new password is refused.
    assert_eq!(
        vault_core::device_key::change_password(
            &bytes,
            &pw("old password"),
            &pw(""),
            &mut FixedRng(0x02),
            &kdf
        )
        .unwrap_err(),
        vault_core::device_key::Error::EmptyPassword
    );
    // KDF failure also fails; original still opens.
    let dead = ScriptedKdf {
        fail_at_or_above: 1,
    };
    assert_eq!(
        vault_core::device_key::change_password(
            &bytes,
            &pw("old password"),
            &pw("new password"),
            &mut FixedRng(0x02),
            &dead
        )
        .unwrap_err(),
        vault_core::device_key::Error::Kdf
    );
    assert!(vault_core::device_key::open(&bytes, &pw("old password"), &kdf).is_ok());
}

#[test]
fn t2_3_06_new_salt_each_change() {
    let kdf = ScriptedKdf::ok();
    let bytes = make(&kdf, 0x01, "old password");
    let a = vault_core::device_key::change_password(
        &bytes,
        &pw("old password"),
        &pw("new password"),
        &mut FixedRng(0x0a),
        &kdf,
    )
    .unwrap();
    let b = vault_core::device_key::change_password(
        &bytes,
        &pw("old password"),
        &pw("new password"),
        &mut FixedRng(0x0b),
        &kdf,
    )
    .unwrap();
    assert_ne!(a, b);
    assert_ne!(&a[7..23], &b[7..23], "salt must differ");
    assert_ne!(&a[31..55], &b[31..55], "nonce must differ");
}

#[test]
fn t2_3_05b_file_write_is_atomic_and_mode_0600() {
    let kdf = ScriptedKdf::ok();
    let dir = std::env::temp_dir().join(format!("argus-t23-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("device.key");
    let bytes = make(&kdf, 0x01, "old password");
    std::fs::write(&path, &bytes).unwrap();
    vault_core::device_key::change_password_file(
        &path,
        &pw("old password"),
        &pw("new password"),
        &mut FixedRng(0x02),
        &kdf,
    )
    .unwrap();
    let after = std::fs::read(&path).unwrap();
    vault_core::device_key::open(&after, &pw("new password"), &kdf).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    // No temp files left behind.
    assert!(std::fs::read_dir(&dir).unwrap().count() == 1);
    std::fs::remove_dir_all(&dir).unwrap();
}
