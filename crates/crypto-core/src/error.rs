//! Error types of the crypto core.
//!
//! Security rule: error messages NEVER reveal a secret, nor do they distinguish
//! "wrong password" from "corrupted data" to an attacker — a decryption failure
//! stays a decryption failure.

use thiserror::Error;

/// Standard result of the crate.
pub type Result<T> = core::result::Result<T, CryptoError>;

#[derive(Debug, Error)]
pub enum CryptoError {
    /// Argon2id derivation failed (invalid parameters, OOM, etc.).
    #[error("key derivation failed")]
    KeyDerivation,

    /// An AEAD encryption/decryption failure.
    ///
    /// Deliberately opaque: it covers both a wrong password and a tampered
    /// ciphertext (invalid tag).
    #[error("decryption failed or data was tampered with")]
    Aead,

    /// Invalid encoded data (base64, key/nonce length).
    #[error("malformed encrypted data")]
    Malformed,

    /// A message claims a sender identity the caller asked to verify, but
    /// carries no signature at all.
    ///
    /// Distinct from [`CryptoError::Aead`] on purpose: a failed *check* may
    /// mean the contact rotated their key, while a missing signature can only
    /// mean the claim was fabricated. Collapsing the two let a stranger forge
    /// a key-rotation alarm against a verified contact.
    #[error("sender identity claimed without a signature")]
    UnsignedSenderClaim,

    /// Empty master password — rejected at the crypto boundary.
    ///
    /// The full password policy (length, entropy) remains the caller's
    /// responsibility; we only reject the degenerate empty case.
    #[error("master password must not be empty")]
    EmptyPassword,

    /// KDF parameters outside the allowed policy.
    ///
    /// Either too weak for a new vault (security floor), or unreasonably high
    /// (client-side anti-denial-of-service ceiling).
    #[error("KDF parameters are outside the allowed policy")]
    KdfPolicy,

    /// Manifest older than the last known version → rollback detected.
    ///
    /// A malicious server re-served a stale manifest to hide a change (item
    /// deletion/addition).
    #[error("stale manifest: possible rollback detected")]
    StaleManifest,
}
