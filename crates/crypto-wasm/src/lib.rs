//! # crypto-wasm
//!
//! Liaisons WebAssembly autour de [`crypto_core`]. Expose une API simple,
//! orientée chaînes (JSON), utilisable depuis JavaScript — par l'app web et,
//! plus tard, l'extension Chrome (qui réutilisent ainsi exactement le même
//! cœur cryptographique zero-knowledge).
//!
//! Tout le chiffrement reste **côté client** : ces fonctions tournent dans le
//! navigateur, et l'aléa provient de `crypto.getRandomValues` via
//! `getrandom/js` (validé par le test `wasm32`, cf. `tests/web.rs`).
//!
//! ## ⚠️ Modèle de menace — secrets en mémoire JavaScript
//! Une fois déverrouillé, l'[`Account`] détient en mémoire la clé de coffre et
//! la Secret Key. Dans un navigateur, **tout script s'exécutant dans la même
//! origine peut lire cette mémoire** : une faille **XSS** (ou une extension/
//! dépendance malveillante) peut exfiltrer secrets et clairs. C'est une limite
//! *fondamentale* du modèle web, pas un défaut de ce crate. Mitigations à la
//! charge de l'app : CSP stricte, intégrité des ressources (SRI), zéro `eval`/
//! injection, et idéalement une cible **native (Tauri)** ou l'isolation d'une
//! extension pour les usages les plus sensibles. Les getters [`Account::secret_key`]
//! et [`Account::emergency_kit`] n'exposent la Secret Key que sur appel
//! **délibéré** (flux d'affichage unique) — ne les câblez pas à des logs.

use wasm_bindgen::prelude::*;

use crypto_core::{AccountSecret, EncryptedBlob, KdfParams, Manifest, Registration, Vault};
use std::collections::HashMap;

/// Convertit une erreur affichable en `JsError` (message opaque, sans secret).
fn js_err<E: core::fmt::Display>(e: E) -> JsError {
    JsError::new(&e.to_string())
}

/// Un compte déverrouillé côté navigateur : détient le coffre en mémoire et les
/// données de compte. Obtenu via [`register`] / [`register_with`] / [`unlock`].
#[wasm_bindgen]
pub struct Account {
    vault: Vault,
    registration_json: String,
    secret: AccountSecret,
}

#[wasm_bindgen]
impl Account {
    /// Données d'inscription à envoyer/stocker côté serveur (JSON). Opaques :
    /// le serveur ne peut rien déchiffrer avec.
    #[wasm_bindgen(getter)]
    pub fn registration_json(&self) -> String {
        self.registration_json.clone()
    }

    /// La Secret Key formatée (`A1-XXXXX-…`) — à montrer une seule fois.
    #[wasm_bindgen(getter)]
    pub fn secret_key(&self) -> String {
        self.secret.to_formatted()
    }

    /// Texte de l'Emergency Kit (Secret Key + emplacement mot de passe).
    pub fn emergency_kit(&self, account_label: &str) -> String {
        self.secret.emergency_kit(account_label)
    }

    /// Chiffre un item ; renvoie le blob chiffré en JSON (à stocker au serveur).
    pub fn encrypt_item(&self, plaintext: &str, item_id: &str) -> Result<String, JsError> {
        let blob = self
            .vault
            .encrypt_item(plaintext.as_bytes(), item_id)
            .map_err(js_err)?;
        serde_json::to_string(&blob).map_err(js_err)
    }

    /// Déchiffre un item (blob JSON) ; renvoie le clair en UTF-8.
    pub fn decrypt_item(&self, blob_json: &str, item_id: &str) -> Result<String, JsError> {
        let blob: EncryptedBlob = serde_json::from_str(blob_json).map_err(js_err)?;
        let plain = self.vault.decrypt_item(&blob, item_id).map_err(js_err)?;
        String::from_utf8(plain.to_vec()).map_err(js_err)
    }

    // ─── Manifest d'intégrité (vérif côté Rust/WASM, pas en JS) ───

    /// Scelle un manifest (JSON) sous la clé de coffre ; renvoie le blob JSON.
    pub fn seal_manifest(&self, manifest_json: &str) -> Result<String, JsError> {
        let manifest: Manifest = serde_json::from_str(manifest_json).map_err(js_err)?;
        let blob = self.vault.seal_manifest(&manifest).map_err(js_err)?;
        serde_json::to_string(&blob).map_err(js_err)
    }

    /// Ouvre un manifest scellé (blob JSON) → manifest JSON. Première synchro
    /// uniquement ; ensuite, préférez [`Account::open_manifest_checked`].
    pub fn open_manifest(&self, blob_json: &str) -> Result<String, JsError> {
        let blob: EncryptedBlob = serde_json::from_str(blob_json).map_err(js_err)?;
        let manifest = self.vault.open_manifest(&blob).map_err(js_err)?;
        serde_json::to_string(&manifest).map_err(js_err)
    }

    /// Ouvre un manifest en **refusant un rollback** : son `seq` doit être
    /// ≥ `last_seen_seq`. Erreur sinon (rollback détecté).
    pub fn open_manifest_checked(
        &self,
        blob_json: &str,
        last_seen_seq: u64,
    ) -> Result<String, JsError> {
        let blob: EncryptedBlob = serde_json::from_str(blob_json).map_err(js_err)?;
        let manifest = self
            .vault
            .open_manifest_checked(&blob, last_seen_seq)
            .map_err(js_err)?;
        serde_json::to_string(&manifest).map_err(js_err)
    }

    /// Confronte un manifest (JSON) aux items servis par le serveur
    /// (`items_json` = objet `{ id: blobChiffré }`). Renvoie un
    /// `IntegrityReport` JSON (missing / unexpected / corrupted / duplicates).
    pub fn check_manifest(&self, manifest_json: &str, items_json: &str) -> Result<String, JsError> {
        let manifest: Manifest = serde_json::from_str(manifest_json).map_err(js_err)?;
        let items: HashMap<String, EncryptedBlob> =
            serde_json::from_str(items_json).map_err(js_err)?;
        let present: Vec<(&str, &EncryptedBlob)> =
            items.iter().map(|(id, blob)| (id.as_str(), blob)).collect();
        let report = manifest.check(&present);
        serde_json::to_string(&report).map_err(js_err)
    }
}

/// Crée un nouveau compte avec les paramètres KDF par défaut (64 Mio).
#[wasm_bindgen]
pub fn register(master_password: &str) -> Result<Account, JsError> {
    let (vault, reg, secret) = Vault::register(master_password.as_bytes()).map_err(js_err)?;
    let registration_json = serde_json::to_string(&reg).map_err(js_err)?;
    Ok(Account {
        vault,
        registration_json,
        secret,
    })
}

/// Variante avec paramètres Argon2id explicites (utile pour des appareils
/// contraints ou les tests).
#[wasm_bindgen]
pub fn register_with(
    master_password: &str,
    mem_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<Account, JsError> {
    let params = KdfParams {
        mem_kib,
        iterations,
        parallelism,
    };
    let (vault, reg, secret) =
        Vault::register_with(master_password.as_bytes(), params).map_err(js_err)?;
    let registration_json = serde_json::to_string(&reg).map_err(js_err)?;
    Ok(Account {
        vault,
        registration_json,
        secret,
    })
}

/// Déverrouille un compte existant à partir du mot de passe maître, de la Secret
/// Key (formatée), et des données d'inscription (JSON renvoyé par le serveur).
#[wasm_bindgen]
pub fn unlock(
    master_password: &str,
    secret_key: &str,
    registration_json: &str,
) -> Result<Account, JsError> {
    let reg: Registration = serde_json::from_str(registration_json).map_err(js_err)?;
    let secret = AccountSecret::parse(secret_key).map_err(js_err)?;
    let (vault, _auth) = Vault::unlock(
        master_password.as_bytes(),
        &secret,
        &reg.salt,
        reg.kdf,
        &reg.wrapped_vault_key,
    )
    .map_err(js_err)?;
    Ok(Account {
        vault,
        registration_json: registration_json.to_string(),
        secret,
    })
}
