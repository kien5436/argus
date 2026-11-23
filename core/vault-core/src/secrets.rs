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

            /// Test-only hook: zeroise the buffer and leak its allocation,
            /// returning a pointer to the still-live memory.
            ///
            /// Proves [`Zeroize`] ran on the real buffer. Reading the
            /// result is sound because the allocation is leaked, never
            /// freed; the leak is acceptable in tests.
            #[doc(hidden)]
            pub fn __test_zeroize_and_leak(self) -> (*const u8, usize) {
                let mut this = std::mem::ManuallyDrop::new(self);
                this.0.zeroize();
                (this.0.as_ptr(), this.0.len())
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
