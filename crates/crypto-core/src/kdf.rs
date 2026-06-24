//! Dérivation de clé à partir du mot de passe maître.
//!
//! Deux étages :
//! 1. **Argon2id** (lent, mémoire-dur) transforme le mot de passe maître + sel
//!    en une *clé maître* de 256 bits. C'est l'unique étape coûteuse — elle
//!    protège contre le brute-force hors-ligne.
//! 2. **HKDF-SHA256** (rapide) dérive de la clé maître plusieurs sous-clés à
//!    usage unique (chiffrement du coffre, secret d'authentification…).
//!
//! La clé maître ne sort jamais de l'appareil. Le serveur ne reçoit que le
//! secret d'authentification (cf. [`crate::vault`]).

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::account_secret::AccountSecret;
use crate::error::{CryptoError, Result};
use crate::secret::{SecretKey, KEY_LEN};

/// Longueur du sel Argon2 (128 bits).
pub const SALT_LEN: usize = 16;

/// Paramètres Argon2id, stockés avec le compte pour pouvoir les durcir plus
/// tard sans casser les comptes existants.
///
/// Valeurs par défaut alignées sur les recommandations d'un gestionnaire de
/// mots de passe (plus fortes que l'OWASP minimal) : 64 Mio, 3 passes, p=4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Coût mémoire en kibioctets.
    pub mem_kib: u32,
    /// Nombre de passes (coût temps).
    pub iterations: u32,
    /// Degré de parallélisme.
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            mem_kib: 64 * 1024, // 64 Mio
            iterations: 3,
            parallelism: 4,
        }
    }
}

impl KdfParams {
    // ─── Politique KDF ───
    // Planchers : minimum acceptable pour CRÉER un nouveau coffre. En dessous,
    // le brute-force hors-ligne devient trop bon marché.
    /// Mémoire minimale (19 Mio, ligne OWASP pour Argon2id).
    pub const MIN_MEM_KIB: u32 = 19 * 1024;
    /// Passes minimales.
    pub const MIN_ITERATIONS: u32 = 2;
    /// Parallélisme minimal.
    pub const MIN_PARALLELISM: u32 = 1;
    // Plafonds : au-delà, on refuse même d'essayer — un serveur malveillant ou
    // un enregistrement corrompu pourrait sinon épuiser la RAM/CPU du client.
    /// Mémoire maximale tolérée (1 Gio).
    pub const MAX_MEM_KIB: u32 = 1024 * 1024;
    /// Passes maximales.
    pub const MAX_ITERATIONS: u32 = 20;
    /// Parallélisme maximal.
    pub const MAX_PARALLELISM: u32 = 16;

    /// Politique pour un **nouveau** coffre (inscription / rotation) :
    /// plancher de sécurité ET plafond anti-DoS.
    pub fn validate_for_new_vault(&self) -> Result<()> {
        if self.mem_kib < Self::MIN_MEM_KIB
            || self.iterations < Self::MIN_ITERATIONS
            || self.parallelism < Self::MIN_PARALLELISM
        {
            return Err(CryptoError::KdfPolicy);
        }
        self.validate_ceiling()
    }

    /// Politique pour **ouvrir** un coffre existant : plafond anti-DoS seul.
    ///
    /// On n'applique PAS le plancher ici : un coffre créé sous une politique
    /// plus ancienne (params plus faibles) doit rester déverrouillable. Le
    /// durcissement se fait à la rotation, pas en verrouillant l'utilisateur
    /// hors de ses données.
    pub fn validate_for_unlock(&self) -> Result<()> {
        self.validate_ceiling()
    }

    /// `true` si les paramètres sont sous le plancher actuel — l'appelant
    /// devrait proposer une rotation pour durcir le coffre.
    pub fn is_below_policy_floor(&self) -> bool {
        self.mem_kib < Self::MIN_MEM_KIB
            || self.iterations < Self::MIN_ITERATIONS
            || self.parallelism < Self::MIN_PARALLELISM
    }

    fn validate_ceiling(&self) -> Result<()> {
        if self.mem_kib > Self::MAX_MEM_KIB
            || self.iterations > Self::MAX_ITERATIONS
            || self.parallelism > Self::MAX_PARALLELISM
        {
            return Err(CryptoError::KdfPolicy);
        }
        Ok(())
    }

    fn to_argon2(self) -> Result<Argon2<'static>> {
        let params = Params::new(
            self.mem_kib,
            self.iterations,
            self.parallelism,
            Some(KEY_LEN),
        )
        .map_err(|_| CryptoError::KeyDerivation)?;
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }
}

/// Génère un sel aléatoire de 128 bits via le CSPRNG du système.
pub fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Étage 1 — dérive la clé maître de 256 bits via Argon2id.
pub fn derive_master_key(
    password: &[u8],
    salt: &[u8; SALT_LEN],
    params: KdfParams,
) -> Result<SecretKey> {
    let argon2 = params.to_argon2()?;
    let mut out = [0u8; KEY_LEN];
    argon2
        .hash_password_into(password, salt, &mut out)
        .map_err(|_| CryptoError::KeyDerivation)?;
    let key = SecretKey::from_bytes(out);
    // `out` est copié dans le SecretKey ; on efface la pile.
    use zeroize::Zeroize;
    out.zeroize();
    Ok(key)
}

/// Étiquettes de domaine pour HKDF — garantissent que des sous-clés à usages
/// différents sont cryptographiquement indépendantes.
const INFO_VAULT_WRAP: &[u8] = b"pm:v1:vault-wrap-key";
const INFO_AUTH: &[u8] = b"pm:v1:auth-secret";

/// Étage 2 — dérive la clé qui chiffre (wrap) la clé de coffre.
pub fn derive_wrap_key(master: &SecretKey, account_secret: &AccountSecret) -> SecretKey {
    expand(master, account_secret, INFO_VAULT_WRAP)
}

/// Étage 2 — dérive le secret d'authentification envoyé au serveur.
///
/// Le serveur n'apprend rien de la clé maître : HKDF est à sens unique et ce
/// secret est indépendant de la clé de chiffrement du coffre.
///
/// ⚠️ Côté serveur, ce secret DOIT être re-hashé lentement (Argon2id) avant
/// stockage et comparé en temps constant — voir [`crate::vault::Registration`].
pub fn derive_auth_secret(master: &SecretKey, account_secret: &AccountSecret) -> SecretKey {
    expand(master, account_secret, INFO_AUTH)
}

/// HKDF avec la **Secret Key comme sel** (HKDF-Extract), puis Expand par domaine.
///
/// Mélanger la Secret Key au stade Extract la fait entrer dans toutes les sous-
/// clés : sans elle, rien n'est dérivable même si la clé maître (donc le mot de
/// passe) est connue. C'est ce qui rend le brute-force hors-ligne infaisable.
fn expand(master: &SecretKey, account_secret: &AccountSecret, info: &[u8]) -> SecretKey {
    let hk = Hkdf::<Sha256>::new(Some(account_secret.as_bytes()), master.as_bytes());
    let mut out = [0u8; KEY_LEN];
    hk.expand(info, &mut out)
        .expect("32 octets <= 255 * HashLen");
    let key = SecretKey::from_bytes(out);
    use zeroize::Zeroize;
    out.zeroize();
    key
}
