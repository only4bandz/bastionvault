//! Chiffrement authentifié (AEAD) avec XChaCha20-Poly1305.
//!
//! Choix de XChaCha20-Poly1305 : nonce de 192 bits, donc générer le nonce
//! aléatoirement est sûr (probabilité de collision négligeable), contrairement
//! à AES-GCM dont le nonce de 96 bits oblige à une gestion d'état délicate.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};

use crate::error::{CryptoError, Result};
use crate::secret::SecretKey;

const NONCE_LEN: usize = 24;

/// Une enveloppe chiffrée : nonce + chiffré (qui inclut le tag d'authentification).
///
/// Sérialisable (base64) pour le stockage serveur et le transport. Ne contient
/// aucun secret : sans la clé, c'est du bruit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedBlob {
    /// Nonce de 192 bits, encodé base64.
    pub nonce: String,
    /// Texte chiffré + tag Poly1305, encodé base64.
    pub ct: String,
}

/// Chiffre `plaintext` avec `key`.
///
/// `aad` (additional authenticated data) est authentifié mais pas chiffré :
/// utile pour lier le chiffré à un contexte (ex. l'id de l'item) et empêcher
/// qu'un blob soit déplacé ailleurs. Passer `&[]` si inutile.
pub(crate) fn encrypt(key: &SecretKey, plaintext: &[u8], aad: &[u8]) -> Result<EncryptedBlob> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ct = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Aead)?;
    Ok(EncryptedBlob {
        nonce: B64.encode(nonce),
        ct: B64.encode(ct),
    })
}

/// Déchiffre une enveloppe. Échoue si la clé est fausse, le nonce/chiffré
/// malformé, ou si le chiffré (ou l'`aad`) a été altéré.
pub(crate) fn decrypt(key: &SecretKey, blob: &EncryptedBlob, aad: &[u8]) -> Result<Vec<u8>> {
    let nonce_bytes = B64
        .decode(&blob.nonce)
        .map_err(|_| CryptoError::Malformed)?;
    if nonce_bytes.len() != NONCE_LEN {
        return Err(CryptoError::Malformed);
    }
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ct = B64.decode(&blob.ct).map_err(|_| CryptoError::Malformed)?;

    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    cipher
        .decrypt(nonce, Payload { msg: &ct, aad })
        .map_err(|_| CryptoError::Aead)
}
