use vault_core::secrets::{MasterPassword, OtpCode, OtpSecret, PrivateKey, SecretBytes};

#[test]
fn t15_01_debug_and_display_print_fixed_redaction() {
    assert_eq!(
        format!("{:?}", SecretBytes::new(b"hunter2".to_vec())),
        "[redacted]"
    );
    assert_eq!(
        format!("{}", SecretBytes::new(b"hunter2".to_vec())),
        "[redacted]"
    );
    assert_eq!(
        format!("{:?}", MasterPassword::new(b"master".to_vec())),
        "[redacted]"
    );
    assert_eq!(
        format!("{}", MasterPassword::new(b"master".to_vec())),
        "[redacted]"
    );
    assert_eq!(
        format!("{:?}", PrivateKey::new(vec![7u8; 32])),
        "[redacted]"
    );
    assert_eq!(format!("{}", PrivateKey::new(vec![7u8; 32])), "[redacted]");
    assert_eq!(
        format!("{:?}", OtpSecret::new(b"JBSWY3DPEHPK3PXP".to_vec())),
        "[redacted]"
    );
    assert_eq!(
        format!("{}", OtpSecret::new(b"JBSWY3DPEHPK3PXP".to_vec())),
        "[redacted]"
    );
    assert_eq!(
        format!("{:?}", OtpCode::new(b"123456".to_vec())),
        "[redacted]"
    );
    assert_eq!(
        format!("{}", OtpCode::new(b"123456".to_vec())),
        "[redacted]"
    );
    assert_eq!(SecretBytes::new(b"hunter2".to_vec()).expose(), b"hunter2");
    assert_eq!(MasterPassword::new(b"master".to_vec()).expose(), b"master");
    assert_eq!(PrivateKey::new(vec![7u8; 32]).expose(), [7u8; 32]);
    assert_eq!(
        OtpSecret::new(b"JBSWY3DPEHPK3PXP".to_vec()).expose(),
        b"JBSWY3DPEHPK3PXP"
    );
    assert_eq!(OtpCode::new(b"123456".to_vec()).expose(), b"123456");
}

#[test]
fn t15_02_entry_like_struct_hides_password_in_debug() {
    #[derive(Debug)]
    #[allow(dead_code)]
    struct CredentialLike {
        username: String,
        password: SecretBytes,
    }
    let entry = CredentialLike {
        username: "ada".to_owned(),
        password: SecretBytes::new(b"s3cr3t-pw".to_vec()),
    };
    let shown = format!("{entry:?}");
    assert!(shown.contains("[redacted]"));
    assert!(!shown.contains("s3cr3t-pw"));
    assert!(shown.contains("ada"));
}

#[test]
fn t15_05_equality_is_constant_time_and_correct() {
    use subtle::ConstantTimeEq;
    let a = SecretBytes::new(b"same-content".to_vec());
    let b = SecretBytes::new(b"same-content".to_vec());
    let c = SecretBytes::new(b"other-content!".to_vec());
    assert_eq!(a, b);
    assert_ne!(a, c);
    assert_eq!(a.ct_eq(&b).unwrap_u8(), 1);
    assert_eq!(a.ct_eq(&c).unwrap_u8(), 0);
}
