use vault_core::secrets::SecretBytes;

fn main() {
    let s = SecretBytes::new(b"no-clone".to_vec());
    let _ = s.clone();
}
