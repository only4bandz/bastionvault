//! # crypto-core
//!
//! **Zero-knowledge** cryptographic core of the password manager.
//!
//! All encryption happens client-side (in the browser via WASM, or natively).
//! The server never sees the master password, the master key, or a single
//! item in the clear — only opaque [`aead::EncryptedBlob`] values.
//!
//! ## Primitives
//! - **Argon2id**: slow, memory-hard derivation of the master password.
//! - **Secret Key** (128 bits, held by the user) mixed in as the HKDF salt
//!   → offline brute-force is infeasible even with a weak password.
//! - **HKDF-SHA256**: separation into independent sub-keys.
//! - **XChaCha20-Poly1305**: authenticated encryption (192-bit nonce).
//!
//! ## WASM target — validated
//! The crate targets native **and** WebAssembly. The `crypto-wasm` crate wires
//! randomness to the browser's entropy (`getrandom/js`) and validates it with a
//! real `wasm32` test (`wasm-pack test --node`): salt/key/nonce generation and
//! the full registration → encryption → unlock cycle all pass under WASM.
//!
//! ## Quick start
//! ```
//! use crypto_core::vault::Vault;
//!
//! // Registration: creates the vault + returns the Secret Key to show once.
//! let (vault, reg, secret_key) = Vault::register(b"my master password").unwrap();
//! let _emergency_kit = secret_key.emergency_kit("alice@example.com");
//!
//! // Encrypting an item (the server will only store this blob).
//! let blob = vault.encrypt_item(b"super-secret", "item-1").unwrap();
//!
//! // Unlock: both the master password AND the Secret Key are required.
//! let (vault2, _auth) = Vault::unlock(
//!     b"my master password",
//!     &secret_key,
//!     &reg.salt,
//!     reg.kdf,
//!     &reg.wrapped_vault_key,
//! )
//! .unwrap();
//! assert_eq!(&vault2.decrypt_item(&blob, "item-1").unwrap()[..], b"super-secret");
//! ```

pub mod account_secret;
pub mod aead;
pub mod error;
pub mod kdf;
pub mod manifest;
pub mod secret;
pub mod send;
pub mod vault;

// Recommended public API: go through `Vault`. The low-level AEAD primitives
// (`aead::encrypt`/`decrypt`) are deliberately `pub(crate)` to avoid pitfalls
// (mishandled nonce/AAD, raw plaintext left unwiped).
pub use account_secret::AccountSecret;
pub use aead::EncryptedBlob;
pub use error::{CryptoError, Result};
pub use kdf::KdfParams;
pub use manifest::{IntegrityReport, Manifest, ManifestEntry};
pub use send::{
    open as send_open, safety_number, seal as send_seal, IdentityKeys, OpenedMessage,
    PublicIdentity, SendBlob,
};
pub use vault::{AuthSecret, Registration, Vault};
