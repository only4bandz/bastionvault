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

use wasm_bindgen::prelude::*;

use crypto_core::{AccountSecret, EncryptedBlob, KdfParams, Registration, Vault};

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
