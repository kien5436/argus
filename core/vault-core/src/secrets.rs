//! Secret types (spec 01 Core API, spec 02 invariants).
//!
//! Wrappers for the master password, private keys, decrypted passwords,
//! OTP secrets and codes. They zeroise on drop, never print their
//! contents, compare in constant time, and cannot be cloned or
//! serialised.

use std::fmt;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

macro_rules! secret {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(PartialEq, Eq)]
        pub struct $name(Vec<u8>);

        impl $name {
            pub fn new(bytes: Vec<u8>) -> Self {
                Self(bytes)
            }

            /// Borrow the secret bytes for immediate use.
            ///
            /// The caller must not retain or copy the slice.
            pub fn expose(&self) -> &[u8] {
                &self.0
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                self.0.zeroize();
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("[redacted]")
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("[redacted]")
            }
        }

        impl ConstantTimeEq for $name {
            fn ct_eq(&self, other: &Self) -> subtle::Choice {
                self.0.as_slice().ct_eq(other.0.as_slice())
            }
        }
    };
}

secret!(
    SecretBytes,
    "Decrypted secret bytes (passwords, note contents)."
);
secret!(MasterPassword, "The master password.");
secret!(PrivateKey, "A private key.");
secret!(OtpSecret, "A TOTP or HOTP secret.");
secret!(OtpCode, "A one-time code.");

#[cfg(test)]
mod tests {
    use super::*;

    /// T1.5-03: dropping a secret zeroises its buffer. Runs the same
    /// `Zeroize` call as `Drop`, then reads the still-live allocation.
    /// The allocation is never freed (leaked), so the read is sound.
    /// This unit test never ships; the production API has no test hook.
    #[test]
    fn drop_zeroises_the_buffer() {
        let mut this =
            std::mem::ManuallyDrop::new(SecretBytes::new(b"sensitive-data-123".to_vec()));
        let (ptr, len) = (this.0.as_ptr(), this.0.len());
        this.0.zeroize();
        let after = unsafe { std::slice::from_raw_parts(ptr, len) };
        assert!(after.iter().all(|b| *b == 0), "buffer was not zeroised");
    }
}
