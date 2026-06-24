//! Clé secrète de compte (« Secret Key », modèle 1Password) : un secret
//! aléatoire de 128 bits détenu **uniquement** par l'utilisateur et JAMAIS
//! envoyé au serveur.
//!
//! Elle entre dans la dérivation de clé comme **sel HKDF** (cf. [`crate::kdf`]),
//! ce qui la mélange à *toutes* les sous-clés (wrap + auth). Conséquence : un
//! attaquant qui vole l'intégralité des données côté serveur (sel, coffre
//! enveloppé, secret d'auth) ne peut **rien** dériver sans cette Secret Key —
//! le brute-force hors-ligne devient infaisable même avec un mot de passe
//! maître faible.
//!
//! Elle est montrée une seule fois (Emergency Kit) et ressaisie/scannée sur
//! chaque nouvel appareil.

use data_encoding::BASE32_NOPAD;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{CryptoError, Result};

/// Longueur de la Secret Key (128 bits — sweet spot sécurité/ergonomie, aligné
/// sur 1Password ; combinée au mot de passe, 128 bits suffisent largement).
pub const ACCOUNT_SECRET_LEN: usize = 16;

/// Longueur du checksum encodé avec la clé (16 bits → ~1/65536 de laisser
/// passer une faute de frappe).
const CHECKSUM_LEN: usize = 2;

/// Préfixe de version du format encodé, pour faire évoluer le schéma plus tard.
/// Le « 1 » n'appartient pas à l'alphabet base32 (A-Z2-7) : aucune collision
/// possible avec le corps encodé.
const VERSION_TAG: &str = "A1";

/// Checksum tronqué (16 bits) de la clé, pour détecter une saisie erronée
/// **localement**, avant toute dérivation Argon2id coûteuse.
fn checksum(secret: &[u8; ACCOUNT_SECRET_LEN]) -> [u8; CHECKSUM_LEN] {
    let mut h = Sha256::new();
    h.update(b"pm:v1:secret-key-checksum");
    h.update(secret);
    let digest = h.finalize();
    [digest[0], digest[1]]
}

/// Secret de compte de 128 bits, effacé de la mémoire au drop.
///
/// Ne dérive pas `Clone`/`Debug`/`Serialize` : ce secret ne doit jamais être
/// copié, journalisé, ni sérialisé par accident (il ne quitte pas l'appareil).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AccountSecret([u8; ACCOUNT_SECRET_LEN]);

impl AccountSecret {
    /// Génère une nouvelle Secret Key via le CSPRNG du système.
    pub fn generate() -> Self {
        let mut bytes = [0u8; ACCOUNT_SECRET_LEN];
        OsRng.fill_bytes(&mut bytes);
        let secret = Self(bytes);
        bytes.zeroize();
        secret
    }

    /// Octets bruts — usage interne (sel HKDF).
    pub(crate) fn as_bytes(&self) -> &[u8; ACCOUNT_SECRET_LEN] {
        &self.0
    }

    /// Représentation lisible pour l'humain : `A1-XXXXX-XXXXX-…` (base32
    /// majuscule, groupée par 5, checksum 16 bits inclus). À conserver dans
    /// l'Emergency Kit / QR.
    pub fn to_formatted(&self) -> String {
        // Charge utile = secret ‖ checksum, dans un tampon effacé au drop.
        let mut payload = Zeroizing::new(Vec::with_capacity(ACCOUNT_SECRET_LEN + CHECKSUM_LEN));
        payload.extend_from_slice(&self.0);
        payload.extend_from_slice(&checksum(&self.0));
        let body = BASE32_NOPAD.encode(&payload);
        let mut out = String::with_capacity(body.len() + body.len() / 5 + 3);
        out.push_str(VERSION_TAG);
        for (i, ch) in body.chars().enumerate() {
            if i % 5 == 0 {
                out.push('-');
            }
            out.push(ch);
        }
        out
    }

    /// Parse une Secret Key saisie ou scannée. Tolérant : ignore tirets, espaces
    /// et casse, accepte avec ou sans le préfixe de version. Le checksum permet
    /// de **rejeter une faute de frappe immédiatement** (sans Argon2id).
    pub fn parse(input: &str) -> Result<Self> {
        let cleaned: String = input
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect::<String>()
            .to_ascii_uppercase();
        let body = cleaned.strip_prefix(VERSION_TAG).unwrap_or(&cleaned);
        let bytes = Zeroizing::new(
            BASE32_NOPAD
                .decode(body.as_bytes())
                .map_err(|_| CryptoError::Malformed)?,
        );
        if bytes.len() != ACCOUNT_SECRET_LEN + CHECKSUM_LEN {
            return Err(CryptoError::Malformed);
        }
        let mut secret = [0u8; ACCOUNT_SECRET_LEN];
        secret.copy_from_slice(&bytes[..ACCOUNT_SECRET_LEN]);
        if bytes[ACCOUNT_SECRET_LEN..] != checksum(&secret) {
            secret.zeroize();
            return Err(CryptoError::Malformed);
        }
        let out = Self(secret);
        secret.zeroize();
        Ok(out)
    }

    /// Texte « Emergency Kit » à imprimer et conserver hors-ligne.
    ///
    /// Contient la Secret Key (récupérable nulle part ailleurs) et un
    /// emplacement pour noter le mot de passe maître à la main.
    pub fn emergency_kit(&self, account_label: &str) -> String {
        format!(
            "================ EMERGENCY KIT — COFFRE ================\n\
             \n\
             Compte     : {account_label}\n\
             Secret Key : {secret}\n\
             \n\
             Mot de passe maître : ______________________________\n\
             \n\
             - Conservez ce document hors-ligne, en lieu sûr.\n\
             - Sans la Secret Key ET le mot de passe maître, le coffre est\n\
             \x20 DÉFINITIVEMENT irrécupérable : personne, pas même le serveur,\n\
             \x20 ne peut les retrouver.\n\
             =======================================================\n",
            account_label = account_label,
            secret = self.to_formatted(),
        )
    }
}
