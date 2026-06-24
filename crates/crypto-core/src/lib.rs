//! # crypto-core
//!
//! Cœur cryptographique **zero-knowledge** du gestionnaire de mots de passe.
//!
//! Tout le chiffrement se fait côté client (navigateur via WASM, ou natif).
//! Le serveur ne voit jamais le mot de passe maître, la clé maître, ni un seul
//! item en clair — uniquement des [`aead::EncryptedBlob`] opaques.
//!
//! ## Primitives
//! - **Argon2id** : dérivation lente et mémoire-dure du mot de passe maître.
//! - **Secret Key** (128 bits, détenue par l'utilisateur) mélangée comme sel
//!   HKDF → brute-force hors-ligne infaisable même avec un mot de passe faible.
//! - **HKDF-SHA256** : séparation en sous-clés indépendantes.
//! - **XChaCha20-Poly1305** : chiffrement authentifié (nonce 192 bits).
//!
//! ## Cible WASM — validée
//! Le crate vise natif **et** WebAssembly. Le crate `crypto-wasm` câble l'aléa
//! sur l'entropie du navigateur (`getrandom/js`) et le valide par un test
//! `wasm32` réel (`wasm-pack test --node`) : génération de sel/clés/nonces et
//! cycle complet inscription → chiffrement → déverrouillage passent en WASM.
//!
//! ## Démarrage rapide
//! ```
//! use crypto_core::vault::Vault;
//!
//! // Inscription : crée le coffre + renvoie la Secret Key à montrer une fois.
//! let (vault, reg, secret_key) = Vault::register(b"mon mot de passe maitre").unwrap();
//! let _emergency_kit = secret_key.emergency_kit("alice@example.com");
//!
//! // Chiffrement d'un item (le serveur ne stockera que ce blob).
//! let blob = vault.encrypt_item(b"super-secret", "item-1").unwrap();
//!
//! // Déverrouillage : mot de passe maître ET Secret Key sont requis.
//! let (vault2, _auth) = Vault::unlock(
//!     b"mon mot de passe maitre",
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
pub mod vault;

// API publique recommandée : passez par `Vault`. Les primitives AEAD bas niveau
// (`aead::encrypt`/`decrypt`) sont volontairement `pub(crate)` pour éviter les
// pièges (nonce/AAD mal gérés, clair brut non effacé).
pub use account_secret::AccountSecret;
pub use aead::EncryptedBlob;
pub use error::{CryptoError, Result};
pub use kdf::KdfParams;
pub use manifest::{IntegrityReport, Manifest, ManifestEntry};
pub use vault::{AuthSecret, Registration, Vault};
