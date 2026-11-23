use vault_core::secrets::SecretBytes;

fn main() {
    let s = SecretBytes::new(b"no-serialize".to_vec());
    let _ = serde_json::to_string(&s).unwrap();
}
