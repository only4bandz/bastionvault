//! API de haut niveau : inscription, déverrouillage, chiffrement des items.
//!
//! C'est l'interface qu'utiliseront l'app web et l'extension Chrome (via WASM).
//! Tout se passe côté client. Le serveur ne stocke que des données opaques.
//!
//! Modèle de clés (inspiré de Bitwarden / 1Password) :
//!
//! ```text
//!   mot de passe maître ──Argon2id(sel)──► clé maître
//!                                            │
//!                          ┌─────HKDF────────┼─────HKDF─────┐
//!                          ▼                                ▼
//!                     clé de wrap                      secret d'auth ──► serveur
//!                          │                            (vérifie l'identité,
//!                          │ chiffre/déchiffre           n'ouvre rien)
//!                          ▼
//!     clé de coffre (aléatoire) ──chiffre──► tous les items
//! ```
//!
//! La clé de coffre est une clé aléatoire, *enveloppée* par la clé de wrap.
//! Avantage : changer de mot de passe maître ne ré-enveloppe que la clé de
//! coffre — pas besoin de re-chiffrer tous les items.

use core::fmt;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::account_secret::AccountSecret;
use crate::aead::{self, EncryptedBlob};
use crate::error::{CryptoError, Result};
use crate::kdf::{self, KdfParams};
use crate::manifest::Manifest;
use crate::secret::{SecretKey, KEY_LEN};

/// AAD liant la clé de coffre enveloppée à son rôle.
const AAD_VAULT_KEY: &[u8] = b"pm:v1:wrapped-vault-key";

/// AAD liant le manifest d'intégrité à son rôle.
const AAD_MANIFEST: &[u8] = b"pm:v1:manifest";

/// Borne sur le sel encodé reçu (non fiable), vérifiée avant décodage.
/// Le sel fait 16 octets → ~24 caractères base64 ; 64 laisse de la marge.
const MAX_ENCODED_SALT_LEN: usize = 64;

/// Secret d'authentification présenté au serveur. Type dédié plutôt qu'une
/// `String` nue pour éviter les fuites : `Debug` est **masqué**, il n'est pas
/// `Clone`, et la comparaison se fait en **temps constant**.
///
/// Sérialise/désérialise de façon transparente comme la chaîne base64 sous-
/// jacente (format réseau inchangé).
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct AuthSecret(String);

impl AuthSecret {
    fn from_b64(value: String) -> Self {
        Self(value)
    }

    /// Expose la valeur base64 — à n'envoyer **qu'au serveur**, jamais à logger.
    pub fn expose_b64(&self) -> &str {
        &self.0
    }

    /// Octets (base64) pour transmission/comparaison contrôlée.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Égalité en temps constant avec un autre secret d'authentification.
    pub fn ct_eq(&self, other: &AuthSecret) -> bool {
        auth_secret_eq(self.0.as_bytes(), other.0.as_bytes())
    }
}

impl fmt::Debug for AuthSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthSecret(<redacted>)")
    }
}

/// Données à publier au serveur lors de l'inscription. Aucune n'est secrète
/// au sens où le serveur ne peut rien déchiffrer avec.
///
/// Pas de `Clone` : `auth_secret` est un credential, on évite les copies
/// silencieuses.
#[derive(Debug, Serialize, Deserialize)]
pub struct Registration {
    /// Version du format d'enregistrement, pour migrer le schéma sans casser
    /// les comptes existants.
    pub version: u8,
    /// Sel Argon2 (base64). Public par nature.
    pub salt: String,
    /// Paramètres KDF à réutiliser au login.
    pub kdf: KdfParams,
    /// Clé de coffre enveloppée par la clé de wrap.
    pub wrapped_vault_key: EncryptedBlob,
    /// Secret d'authentification (base64), présenté au serveur pour prouver
    /// l'identité — il n'ouvre **aucun** coffre (indépendant de la clé de wrap).
    ///
    /// ⚠️ SÉCURITÉ SERVEUR (obligation) : bien que ce secret ait 256 bits
    /// d'entropie, le serveur ne DOIT JAMAIS le stocker en clair ni avec un hash
    /// rapide (SHA-256, bcrypt à faible coût…). Il DOIT le passer dans un hash
    /// lent dédié (Argon2id de préférence) avant stockage, et le comparer en
    /// temps constant via [`AuthSecret::ct_eq`] / [`auth_secret_eq`]. Objectif :
    /// une fuite de la base ne doit jamais permettre de rejouer
    /// l'authentification d'un utilisateur.
    pub auth_secret: AuthSecret,
}

/// Un coffre déverrouillé : détient la clé de coffre en clair (en mémoire,
/// effacée au drop) et peut chiffrer/déchiffrer les items.
pub struct Vault {
    vault_key: SecretKey,
}

impl Vault {
    /// Crée un nouveau compte à partir d'un mot de passe maître.
    ///
    /// Génère une [`AccountSecret`] (Secret Key) aléatoire et la **retourne** :
    /// l'appelant DOIT la montrer une seule fois (Emergency Kit) puis ne jamais
    /// la stocker côté serveur. Utilise les [`KdfParams`] par défaut.
    pub fn register(master_password: &[u8]) -> Result<(Self, Registration, AccountSecret)> {
        Self::register_with(master_password, KdfParams::default())
    }

    /// Variante de [`Vault::register`] avec des paramètres KDF explicites.
    pub fn register_with(
        master_password: &[u8],
        kdf_params: KdfParams,
    ) -> Result<(Self, Registration, AccountSecret)> {
        if master_password.is_empty() {
            return Err(CryptoError::EmptyPassword);
        }
        kdf_params.validate_for_new_vault()?;
        let salt = kdf::generate_salt();
        let master = kdf::derive_master_key(master_password, &salt, kdf_params)?;

        // Secret Key : deuxième facteur de dérivation, jamais transmis au serveur.
        let account_secret = AccountSecret::generate();
        let wrap_key = kdf::derive_wrap_key(&master, &account_secret);
        let auth_secret = kdf::derive_auth_secret(&master, &account_secret);

        // Clé de coffre = clé aléatoire indépendante du mot de passe.
        let vault_key = SecretKey::generate();
        let wrapped_vault_key = aead::encrypt(&wrap_key, vault_key.as_bytes(), AAD_VAULT_KEY)?;

        let registration = Registration {
            version: aead::FORMAT_VERSION,
            salt: B64.encode(salt),
            kdf: kdf_params,
            wrapped_vault_key,
            auth_secret: AuthSecret::from_b64(B64.encode(auth_secret.as_bytes())),
        };
        Ok((Self { vault_key }, registration, account_secret))
    }

    /// Déverrouille un coffre existant.
    ///
    /// Requiert le mot de passe maître **et** la [`AccountSecret`] (Secret Key) :
    /// les deux facteurs sont nécessaires. `salt`, `kdf`, `wrapped_vault_key`
    /// proviennent du serveur (récupérés via l'email avant la saisie). Retourne
    /// le coffre et le secret d'authentification à présenter au serveur.
    ///
    /// Un mot de passe OU une Secret Key erronés font échouer le déballage avec
    /// [`CryptoError::Aead`] — indistinguable d'une donnée altérée.
    pub fn unlock(
        master_password: &[u8],
        account_secret: &AccountSecret,
        salt: &str,
        kdf_params: KdfParams,
        wrapped_vault_key: &EncryptedBlob,
    ) -> Result<(Self, AuthSecret)> {
        if master_password.is_empty() {
            return Err(CryptoError::EmptyPassword);
        }
        // Plafond seul : on accepte des params « legacy » faibles (sinon on
        // verrouillerait l'utilisateur), mais on refuse des params absurdes
        // qui épuiseraient la mémoire avant tout déchiffrement utile.
        kdf_params.validate_for_unlock()?;
        // Borne sur le sel non fiable avant décodage (anti-allocation).
        if salt.len() > MAX_ENCODED_SALT_LEN {
            return Err(CryptoError::Malformed);
        }
        let salt_bytes = B64.decode(salt).map_err(|_| CryptoError::Malformed)?;
        let salt_arr: [u8; kdf::SALT_LEN] =
            salt_bytes.try_into().map_err(|_| CryptoError::Malformed)?;

        let master = kdf::derive_master_key(master_password, &salt_arr, kdf_params)?;
        let wrap_key = kdf::derive_wrap_key(&master, account_secret);
        let auth_secret = kdf::derive_auth_secret(&master, account_secret);

        // La clé de coffre en clair ne doit transiter que par des tampons
        // effacés : `Zeroizing` nettoie le Vec déchiffré, et on efface la copie
        // sur la pile une fois la clé déplacée dans le `SecretKey`.
        let key_bytes = Zeroizing::new(aead::decrypt(&wrap_key, wrapped_vault_key, AAD_VAULT_KEY)?);
        if key_bytes.len() != KEY_LEN {
            return Err(CryptoError::Malformed);
        }
        let mut key_arr = [0u8; KEY_LEN];
        key_arr.copy_from_slice(&key_bytes);
        let vault_key = SecretKey::from_bytes(key_arr);
        key_arr.zeroize();

        Ok((
            Self { vault_key },
            AuthSecret::from_b64(B64.encode(auth_secret.as_bytes())),
        ))
    }

    /// Chiffre le contenu d'un item. `item_id` est authentifié (AAD) pour
    /// qu'un chiffré ne puisse pas être déplacé vers un autre item.
    pub fn encrypt_item(&self, plaintext: &[u8], item_id: &str) -> Result<EncryptedBlob> {
        aead::encrypt(&self.vault_key, plaintext, item_id.as_bytes())
    }

    /// Déchiffre le contenu d'un item.
    ///
    /// Le clair retourné est du **matériel sensible** : il est enveloppé dans
    /// [`Zeroizing`] pour être effacé de la mémoire dès que l'appelant le drop.
    pub fn decrypt_item(&self, blob: &EncryptedBlob, item_id: &str) -> Result<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(aead::decrypt(
            &self.vault_key,
            blob,
            item_id.as_bytes(),
        )?))
    }

    /// Scelle un [`Manifest`] d'intégrité sous la clé de coffre. Le blob produit
    /// est opaque pour le serveur et n'est lisible que par ce coffre.
    pub fn seal_manifest(&self, manifest: &Manifest) -> Result<EncryptedBlob> {
        let bytes = serde_json::to_vec(manifest).map_err(|_| CryptoError::Malformed)?;
        aead::encrypt(&self.vault_key, &bytes, AAD_MANIFEST)
    }

    /// Ouvre un manifest scellé. Échoue si le blob est altéré ou ne provient pas
    /// de ce coffre ([`CryptoError::Aead`]), ou si le manifest est mal formé
    /// (entrées non triées / dupliquées → [`CryptoError::Malformed`]).
    ///
    /// ⚠️ Cette variante ne protège PAS du rollback : un serveur peut resservir
    /// un manifest plus ancien (mais authentique). Utilisez
    /// [`Vault::open_manifest_checked`] dès que vous connaissez le dernier `seq`.
    pub fn open_manifest(&self, blob: &EncryptedBlob) -> Result<Manifest> {
        let bytes = aead::decrypt(&self.vault_key, blob, AAD_MANIFEST)?;
        let manifest: Manifest =
            serde_json::from_slice(&bytes).map_err(|_| CryptoError::Malformed)?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Ouvre un manifest scellé en **refusant un rollback** : le `seq` du
    /// manifest doit être ≥ `last_seen_seq` (le dernier connu du client), sinon
    /// [`CryptoError::StaleManifest`]. C'est l'API à privilégier en synchro.
    pub fn open_manifest_checked(
        &self,
        blob: &EncryptedBlob,
        last_seen_seq: u64,
    ) -> Result<Manifest> {
        let manifest = self.open_manifest(blob)?;
        if manifest.seq() < last_seen_seq {
            return Err(CryptoError::StaleManifest);
        }
        Ok(manifest)
    }

    /// Ré-enveloppe la clé de coffre sous un nouveau mot de passe maître, sans
    /// re-chiffrer les items. Retourne les nouvelles [`Registration`].
    ///
    /// Les [`KdfParams`] sont fournis explicitement : la rotation ne doit jamais
    /// réinitialiser silencieusement des paramètres KDF choisis par l'appelant
    /// (ce qui pourrait les affaiblir). Passer [`KdfParams::default`] pour le
    /// comportement standard.
    ///
    /// La [`AccountSecret`] reste **inchangée** lors d'une rotation de mot de
    /// passe (c'est le secret du compte, pas du mot de passe) : on la repasse.
    pub fn rotate_master_password(
        &self,
        new_password: &[u8],
        account_secret: &AccountSecret,
        kdf_params: KdfParams,
    ) -> Result<Registration> {
        if new_password.is_empty() {
            return Err(CryptoError::EmptyPassword);
        }
        // La rotation est le moment naturel pour durcir : on applique la
        // politique courante (plancher + plafond), pas seulement le plafond.
        kdf_params.validate_for_new_vault()?;
        let salt = kdf::generate_salt();
        let master = kdf::derive_master_key(new_password, &salt, kdf_params)?;
        let wrap_key = kdf::derive_wrap_key(&master, account_secret);
        let auth_secret = kdf::derive_auth_secret(&master, account_secret);
        let wrapped_vault_key = aead::encrypt(&wrap_key, self.vault_key.as_bytes(), AAD_VAULT_KEY)?;
        Ok(Registration {
            version: aead::FORMAT_VERSION,
            salt: B64.encode(salt),
            kdf: kdf_params,
            wrapped_vault_key,
            auth_secret: AuthSecret::from_b64(B64.encode(auth_secret.as_bytes())),
        })
    }
}

/// Compare deux secrets d'authentification en temps constant (anti timing-attack).
/// Destiné au serveur lorsqu'il vérifie le secret présenté.
pub fn auth_secret_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}
