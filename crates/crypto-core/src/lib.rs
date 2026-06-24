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
//! - **HKDF-SHA256** : séparation en sous-clés indépendantes.
//! - **XChaCha20-Poly1305** : chiffrement authentifié (nonce 192 bits).
//!
//! ## Démarrage rapide
//! ```
//! use crypto_core::vault::Vault;
//!
//! // Inscription : crée le coffre + les données à envoyer au serveur.
//! let (vault, reg) = Vault::register(b"mon mot de passe maitre").unwrap();
//!
//! // Chiffrement d'un item (le serveur ne stockera que ce blob).
//! let blob = vault.encrypt_item(b"super-secret", "item-1").unwrap();
//!
//! // Plus tard, déverrouillage avec les données rendues par le serveur.
//! let (vault2, _auth) =
//!     Vault::unlock(b"mon mot de passe maitre", &reg.salt, reg.kdf, &reg.wrapped_vault_key)
//!         .unwrap();
//! assert_eq!(&vault2.decrypt_item(&blob, "item-1").unwrap()[..], b"super-secret");
//! ```

pub mod aead;
pub mod error;
pub mod kdf;
pub mod secret;
pub mod vault;

// API publique recommandée : passez par `Vault`. Les primitives AEAD bas niveau
// (`aead::encrypt`/`decrypt`) sont volontairement `pub(crate)` pour éviter les
// pièges (nonce/AAD mal gérés, clair brut non effacé).
pub use aead::EncryptedBlob;
pub use error::{CryptoError, Result};
pub use kdf::KdfParams;
pub use vault::{Registration, Vault};
