//! Matériel secret de 32 octets, effacé de la mémoire au drop.

use rand_core::{OsRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Longueur d'une clé symétrique (256 bits).
pub const KEY_LEN: usize = 32;

/// Une clé/secret de 256 bits qui s'auto-efface de la mémoire au drop.
///
/// Ne dérive PAS `Clone`/`Debug`/`Serialize` volontairement : un secret ne doit
/// pas être copié ou journalisé par accident.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; KEY_LEN]);

impl SecretKey {
    /// Construit à partir d'octets bruts.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Génère une clé aléatoire via le CSPRNG du système.
    pub fn generate() -> Self {
        let mut bytes = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut bytes);
        let key = Self(bytes);
        bytes.zeroize();
        key
    }

    /// Accès en lecture seule aux octets bruts (pour le chiffrement).
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}
