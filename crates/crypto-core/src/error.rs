//! Types d'erreur du cœur crypto.
//!
//! Règle de sécurité : les messages d'erreur ne révèlent JAMAIS de secret ni
//! ne distinguent « mauvais mot de passe » de « données corrompues » côté
//! attaquant — un échec de déchiffrement reste un échec de déchiffrement.

use thiserror::Error;

/// Résultat standard du crate.
pub type Result<T> = core::result::Result<T, CryptoError>;

#[derive(Debug, Error)]
pub enum CryptoError {
    /// La dérivation Argon2id a échoué (paramètres invalides, OOM…).
    #[error("key derivation failed")]
    KeyDerivation,

    /// Échec d'un chiffrement/déchiffrement AEAD.
    ///
    /// Volontairement opaque : couvre aussi bien un mauvais mot de passe
    /// qu'une altération du chiffré (tag invalide).
    #[error("decryption failed or data was tampered with")]
    Aead,

    /// Donnée encodée (base64, longueur de clé/nonce) invalide.
    #[error("malformed encrypted data")]
    Malformed,

    /// Mot de passe maître vide — rejeté à la frontière crypto.
    ///
    /// La politique de mot de passe complète (longueur, entropie) reste de la
    /// responsabilité de l'appelant ; on refuse seulement le cas dégénéré vide.
    #[error("master password must not be empty")]
    EmptyPassword,

    /// Paramètres KDF hors de la politique autorisée.
    ///
    /// Soit trop faibles pour un nouveau coffre (plancher de sécurité), soit
    /// déraisonnablement élevés (plafond anti-déni-de-service côté client).
    #[error("KDF parameters are outside the allowed policy")]
    KdfPolicy,
}
