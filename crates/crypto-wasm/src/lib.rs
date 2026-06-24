//! # crypto-wasm
//!
//! WebAssembly bindings around [`crypto_core`]. Exposes a simple,
//! string-oriented (JSON) API usable from JavaScript — by the web app and,
//! later, the Chrome extension (which thus reuse exactly the same
//! zero-knowledge cryptographic core).
//!
//! All encryption stays **client-side**: these functions run in the
//! browser, and randomness comes from `crypto.getRandomValues` via
//! `getrandom/js` (validated by the `wasm32` test, see `tests/web.rs`).
//!
//! ## ⚠️ Threat model — secrets in JavaScript memory
//! Once unlocked, the [`Account`] holds the vault key in memory. In a browser,
//! **any script running in the same origin can read that memory**: an **XSS**
//! flaw (or a malicious extension/dependency) can exfiltrate secrets and
//! plaintext. This is a *fundamental* limitation of the web model, not a defect
//! of this crate. Mitigations are the app's responsibility: a strict CSP,
//! subresource integrity (SRI), zero `eval`/injection, and ideally a **native
//! target (Tauri)** or the isolation of an extension for the most sensitive use
//! cases.
//!
//! To **shrink that exposure window**, this crate keeps secrets alive no longer
//! than their use:
//! - [`Account::lock`] drops the in-memory vault key (and any unrevealed Secret
//!   Key) — proven by the fact that decryption fails afterwards. The web app
//!   should call it on inactivity / tab-hide.
//! - The Secret Key is exposed only through the **one-shot, consuming**
//!   [`Account::reveal_secret`]: after the single deliberate display call it is
//!   dropped (zeroized) and a second call fails. An [`Account`] obtained from
//!   [`unlock`] never holds the Secret Key at all (it is not needed past
//!   derivation).

use wasm_bindgen::prelude::*;

use crypto_core::{AccountSecret, EncryptedBlob, KdfParams, Manifest, Registration, Vault};
use std::collections::HashMap;

/// Converts a displayable error into a `JsError` (opaque message, no secret).
fn js_err<E: core::fmt::Display>(e: E) -> JsError {
    JsError::new(&e.to_string())
}

/// An unlocked account on the browser side: holds the vault in memory along
/// with the account data. Obtained via [`register`] / [`register_with`] / [`unlock`].
///
/// The vault and the Secret Key are held in `Option`s so their lifetime can be
/// bounded: [`Account::lock`] takes (and drops) them, and
/// [`Account::reveal_secret`] consumes the Secret Key on first use.
#[wasm_bindgen]
pub struct Account {
    vault: Option<Vault>,
    registration_json: String,
    secret: Option<AccountSecret>,
}

impl Account {
    /// Borrows the unlocked vault, or errors if the account is locked.
    fn vault(&self) -> Result<&Vault, JsError> {
        self.vault
            .as_ref()
            .ok_or_else(|| JsError::new("vault locked"))
    }
}

#[wasm_bindgen]
impl Account {
    /// Registration data to send/store on the server side (JSON). Opaque:
    /// the server cannot decrypt anything with it.
    #[wasm_bindgen(getter)]
    pub fn registration_json(&self) -> String {
        self.registration_json.clone()
    }

    /// `true` once [`Account::lock`] has dropped the in-memory vault key.
    #[wasm_bindgen(getter)]
    pub fn is_locked(&self) -> bool {
        self.vault.is_none()
    }

    /// Locks the account: drops the in-memory vault key (its `ZeroizeOnDrop`
    /// wipes it) and any **unrevealed** Secret Key. After this, encryption and
    /// decryption fail until a fresh [`unlock`]. Idempotent.
    ///
    /// The web app should call this on inactivity, tab-hide, or sign-out to
    /// shrink the window during which secrets live in browser memory.
    pub fn lock(&mut self) {
        self.vault = None;
        self.secret = None;
    }

    /// Reveals the Secret Key material **exactly once** (one-time display flow:
    /// Emergency Kit / first-run screen). Consumes the in-memory Secret Key,
    /// which is then dropped (zeroized): a second call fails, and the secret is
    /// no longer retained afterwards.
    ///
    /// Returns JSON `{ "secret_key": "A1-…", "emergency_kit": "…" }`.
    pub fn reveal_secret(&mut self, account_label: &str) -> Result<String, JsError> {
        let secret = self
            .secret
            .take()
            .ok_or_else(|| JsError::new("secret already revealed or unavailable"))?;
        let reveal = serde_json::json!({
            "secret_key": secret.to_formatted(),
            "emergency_kit": secret.emergency_kit(account_label),
        });
        serde_json::to_string(&reveal).map_err(js_err)
        // `secret` is dropped here → AccountSecret::ZeroizeOnDrop wipes it.
    }

    /// Encrypts an item; returns the encrypted blob as JSON (to be stored on the server).
    pub fn encrypt_item(&self, plaintext: &str, item_id: &str) -> Result<String, JsError> {
        let blob = self
            .vault()?
            .encrypt_item(plaintext.as_bytes(), item_id)
            .map_err(js_err)?;
        serde_json::to_string(&blob).map_err(js_err)
    }

    /// Decrypts an item (JSON blob); returns the plaintext as UTF-8.
    pub fn decrypt_item(&self, blob_json: &str, item_id: &str) -> Result<String, JsError> {
        let blob: EncryptedBlob = serde_json::from_str(blob_json).map_err(js_err)?;
        let plain = self.vault()?.decrypt_item(&blob, item_id).map_err(js_err)?;
        String::from_utf8(plain.to_vec()).map_err(js_err)
    }

    // ─── Integrity manifest (verification on the Rust/WASM side, not in JS) ───

    /// Seals a manifest (JSON) under the vault key; returns the JSON blob.
    pub fn seal_manifest(&self, manifest_json: &str) -> Result<String, JsError> {
        let manifest: Manifest = serde_json::from_str(manifest_json).map_err(js_err)?;
        let blob = self.vault()?.seal_manifest(&manifest).map_err(js_err)?;
        serde_json::to_string(&blob).map_err(js_err)
    }

    /// Opens a sealed manifest (JSON blob) -> manifest JSON. First sync only;
    /// afterwards, prefer [`Account::open_manifest_checked`].
    pub fn open_manifest(&self, blob_json: &str) -> Result<String, JsError> {
        let blob: EncryptedBlob = serde_json::from_str(blob_json).map_err(js_err)?;
        let manifest = self.vault()?.open_manifest(&blob).map_err(js_err)?;
        serde_json::to_string(&manifest).map_err(js_err)
    }

    /// Opens a manifest while **refusing a rollback**: its `seq` must be
    /// ≥ `last_seen_seq`. Error otherwise (rollback detected).
    pub fn open_manifest_checked(
        &self,
        blob_json: &str,
        last_seen_seq: u64,
    ) -> Result<String, JsError> {
        let blob: EncryptedBlob = serde_json::from_str(blob_json).map_err(js_err)?;
        let manifest = self
            .vault()?
            .open_manifest_checked(&blob, last_seen_seq)
            .map_err(js_err)?;
        serde_json::to_string(&manifest).map_err(js_err)
    }

    /// Checks a manifest (JSON) against the items served by the server
    /// (`items_json` = object `{ id: encryptedBlob }`). Returns an
    /// `IntegrityReport` as JSON (missing / unexpected / corrupted / duplicates).
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

/// Creates a new account with the default KDF parameters (64 MiB).
#[wasm_bindgen]
pub fn register(master_password: &str) -> Result<Account, JsError> {
    let (vault, reg, secret) = Vault::register(master_password.as_bytes()).map_err(js_err)?;
    let registration_json = serde_json::to_string(&reg).map_err(js_err)?;
    Ok(Account {
        vault: Some(vault),
        registration_json,
        secret: Some(secret),
    })
}

/// Variant with explicit Argon2id parameters (useful for constrained devices
/// or for tests).
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
        vault: Some(vault),
        registration_json,
        secret: Some(secret),
    })
}

/// Unlocks an existing account from the master password, the Secret Key
/// (formatted), and the registration data (JSON returned by the server).
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
    // The Secret Key is not retained after unlock: it is only a derivation
    // factor (HKDF salt), already consumed above. `secret: None` means
    // `reveal_secret` correctly fails on an unlocked account.
    Ok(Account {
        vault: Some(vault),
        registration_json: registration_json.to_string(),
        secret: None,
    })
}
