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

/// Version du format d'enveloppe AEAD. Permet de migrer (nouvel algorithme,
/// nouveau schéma) sans rendre illisibles les coffres existants.
pub const FORMAT_VERSION: u8 = 1;

// Bornes sur des entrées NON FIABLES, vérifiées AVANT tout décodage base64 ou
// allocation : un blob fourni par un serveur malveillant ne doit pas pouvoir
// déclencher une allocation massive avant l'authentification. Le nonce encodé
// fait ~32 octets ; on plafonne le chiffré encodé à ~8 Mio (≈ 6 Mio de clair),
// large pour une note sécurisée mais garde-fou anti-DoS.
const MAX_ENCODED_NONCE_LEN: usize = 64;
const MAX_ENCODED_CT_LEN: usize = 8 * 1024 * 1024;

/// Une enveloppe chiffrée : version + nonce + chiffré (qui inclut le tag d'auth).
///
/// Sérialisable (base64) pour le stockage serveur et le transport. Ne contient
/// aucun secret : sans la clé, c'est du bruit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedBlob {
    /// Version du format (voir [`FORMAT_VERSION`]).
    pub v: u8,
    /// Nonce de 192 bits, encodé base64.
    pub nonce: String,
    /// Texte chiffré + tag Poly1305, encodé base64.
    pub ct: String,
}

/// Construit l'AAD effectif en y préfixant la version de format. Ainsi la
/// version `v` (métadonnée hors chiffré) est **authentifiée** : la flipper
/// invalide le tag, au lieu de n'être qu'un champ libre côté serveur.
fn versioned_aad(version: u8, aad: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + aad.len());
    out.push(version);
    out.extend_from_slice(aad);
    out
}

/// Chiffre `plaintext` avec `key`.
///
/// `aad` (additional authenticated data) est authentifié mais pas chiffré :
/// utile pour lier le chiffré à un contexte (ex. l'id de l'item) et empêcher
/// qu'un blob soit déplacé ailleurs. La version de format y est aussi liée.
/// Passer `&[]` si aucun contexte propre.
pub(crate) fn encrypt(key: &SecretKey, plaintext: &[u8], aad: &[u8]) -> Result<EncryptedBlob> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let aad = versioned_aad(FORMAT_VERSION, aad);
    let ct = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::Aead)?;
    Ok(EncryptedBlob {
        v: FORMAT_VERSION,
        nonce: B64.encode(nonce),
        ct: B64.encode(ct),
    })
}

/// Déchiffre une enveloppe. Échoue si la clé est fausse, le nonce/chiffré
/// malformé, ou si le chiffré (ou l'`aad`) a été altéré.
pub(crate) fn decrypt(key: &SecretKey, blob: &EncryptedBlob, aad: &[u8]) -> Result<Vec<u8>> {
    // Version connue ?
    if blob.v != FORMAT_VERSION {
        return Err(CryptoError::Malformed);
    }
    // Bornes d'entrée AVANT décodage/allocation (anti-DoS sur input non fiable).
    if blob.nonce.len() > MAX_ENCODED_NONCE_LEN || blob.ct.len() > MAX_ENCODED_CT_LEN {
        return Err(CryptoError::Malformed);
    }
    let nonce_bytes = B64
        .decode(&blob.nonce)
        .map_err(|_| CryptoError::Malformed)?;
    if nonce_bytes.len() != NONCE_LEN {
        return Err(CryptoError::Malformed);
    }
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ct = B64.decode(&blob.ct).map_err(|_| CryptoError::Malformed)?;

    let aad = versioned_aad(blob.v, aad);
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: &ct,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::Aead)
}
