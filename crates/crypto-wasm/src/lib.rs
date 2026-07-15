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

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use crypto_core::pinlock::{self, LockedRecord};
use crypto_core::send::{self, IdentityKeys as SendIdentity, PublicIdentity, Sender};
use crypto_core::{kdf, AccountSecret, EncryptedBlob, KdfParams, Manifest, Registration, Vault};
use std::collections::HashMap;
use zeroize::Zeroize;

/// Converts a displayable error into a `JsError` (opaque message, no secret).
fn js_err<E: core::fmt::Display>(e: E) -> JsError {
    JsError::new(&e.to_string())
}

/// Decode a 16-byte lock salt from base64.
fn decode_salt(b64: &str) -> Result<[u8; kdf::SALT_LEN], JsError> {
    B64.decode(b64)
        .map_err(js_err)?
        .try_into()
        .map_err(|_| JsError::new("bad lock salt length"))
}

/// Reserved vault-item id under which the Bastion Send identity is stored
/// (encrypted under the vault key, synced like any other item).
const SEND_IDENTITY_ITEM_ID: &str = "bastion:send-identity";

/// Item id (for the app to store/sync the encrypted Send identity).
#[wasm_bindgen]
pub fn send_identity_item_id() -> String {
    SEND_IDENTITY_ITEM_ID.to_string()
}

/// Reserved-item prefix for a lock-phrase-protected (re-encrypted) message.
const SEND_LOCKED_ITEM_PREFIX: &str = "bastion:send-locked:";

/// The reserved vault-item id for a locked record. **P1 contract:** the id is
/// derived from the record's random `local_id`, NEVER the server-visible
/// `message_id` — so the sync server can't correlate a deleted inbox message
/// with a stored locked item (design §7).
#[wasm_bindgen]
pub fn send_locked_item_id(local_id: &str) -> String {
    format!("{SEND_LOCKED_ITEM_PREFIX}{local_id}")
}

/// Mint fresh lock-phrase params for a contact: a random 16-byte salt + the
/// WASM-safe default Argon2id params. Returns JSON `{ "salt": "<b64>", "kdf":
/// { mem_kib, iterations, parallelism } }` to store on the contact.
#[wasm_bindgen]
pub fn send_lock_new_params() -> Result<String, JsError> {
    let salt = kdf::generate_salt();
    let out = serde_json::json!({
        "salt": B64.encode(salt),
        "kdf": pinlock::default_lock_kdf(),
    });
    serde_json::to_string(&out).map_err(js_err)
}

/// Open a locked record with the lock phrase + the contact's salt/params.
/// Returns JSON `{ "plaintext": "...", "sender": { "state": ..., "id": ... } }`.
/// A wrong phrase fails closed (opaque error). Pure: needs no vault/identity.
#[wasm_bindgen]
pub fn send_lock_open(
    record_json: &str,
    lock_phrase: &str,
    lock_salt_b64: &str,
    lock_kdf_json: &str,
) -> Result<String, JsError> {
    let record: LockedRecord = serde_json::from_str(record_json).map_err(js_err)?;
    let salt = decode_salt(lock_salt_b64)?;
    let kdf_params: KdfParams = serde_json::from_str(lock_kdf_json).map_err(js_err)?;
    let opened =
        pinlock::lock_open(&record, lock_phrase.as_bytes(), &salt, kdf_params).map_err(js_err)?;
    let plaintext = String::from_utf8(opened.plaintext.to_vec()).map_err(js_err)?;
    let (state, id) = match opened.sender {
        Sender::Anonymous => ("anonymous", None),
        Sender::Unverified(id) => ("unverified", Some(id)),
        Sender::Verified(id) => ("verified", Some(id)),
    };
    let out = serde_json::json!({ "plaintext": plaintext, "sender": { "state": state, "id": id } });
    serde_json::to_string(&out).map_err(js_err)
}

/// Safety number to compare out-of-band with a contact — binds both Bastion
/// ids + encryption + signing keys + versions (Signal-style, 60 digits).
#[wasm_bindgen]
pub fn send_safety_number(
    id_a: &str,
    pub_a_json: &str,
    id_b: &str,
    pub_b_json: &str,
) -> Result<String, JsError> {
    let a: PublicIdentity = serde_json::from_str(pub_a_json).map_err(js_err)?;
    let b: PublicIdentity = serde_json::from_str(pub_b_json).map_err(js_err)?;
    Ok(send::safety_number(id_a, &a, id_b, &b))
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
    /// Server authentication secret (base64). Unlike the vault key / Secret Key,
    /// this cannot decrypt anything — it only authenticates to the server (it is
    /// re-hashed there with Argon2id). Held so the app can log in / re-login, and
    /// dropped on [`Account::lock`].
    auth_secret: Option<String>,
    /// Bastion Send identity (X25519 + Ed25519), once generated/loaded. Lives
    /// only while unlocked; dropped on [`Account::lock`]. Persisted encrypted in
    /// the vault under the reserved item id [`SEND_IDENTITY_ITEM_ID`].
    identity: Option<SendIdentity>,
}

impl Account {
    /// Borrows the unlocked vault, or errors if the account is locked.
    fn vault(&self) -> Result<&Vault, JsError> {
        self.vault
            .as_ref()
            .ok_or_else(|| JsError::new("vault locked"))
    }
    fn identity(&self) -> Result<&SendIdentity, JsError> {
        self.identity
            .as_ref()
            .ok_or_else(|| JsError::new("no Send identity (call create/load first)"))
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
        self.auth_secret = None;
        self.identity = None;
    }

    /// The server authentication secret (base64), or `""` if locked. Send this
    /// to the server's `/sessions` endpoint to obtain a bearer token. It cannot
    /// decrypt the vault.
    #[wasm_bindgen(getter)]
    pub fn auth_secret(&self) -> String {
        self.auth_secret.clone().unwrap_or_default()
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

    /// Exports the unlocked session as JSON `{ "vault_key": "<b64>",
    /// "registration_json": "…", "auth_secret": "<b64>" }`, for a caller that
    /// must survive being torn down and rebuilt (e.g. a Chrome MV3 service
    /// worker that Chrome evicts after seconds of inactivity).
    ///
    /// ⚠️ The `vault_key` is the crown decryption key. The ONLY acceptable home
    /// for this blob is RAM-backed, extension-private storage
    /// (`chrome.storage.session`) for a bounded lifetime — NEVER `localStorage`,
    /// IndexedDB, cookies, or any on-disk store, and never off the device. It
    /// lets [`rehydrate`] rebuild the account without re-deriving Argon2id.
    /// Errors if the account is locked.
    pub fn export_session(&self) -> Result<String, JsError> {
        let key = self.vault()?.export_key();
        let session = serde_json::json!({
            "vault_key": B64.encode(&*key),
            "registration_json": self.registration_json,
            "auth_secret": self.auth_secret.clone().unwrap_or_default(),
        });
        serde_json::to_string(&session).map_err(js_err)
    }

    // ─── Bastion Send (E2E encrypted notes between users) ───

    /// Generate a fresh Send identity, hold it in memory, and return the
    /// ENCRYPTED reserved vault item (JSON `EncryptedBlob`) to persist on the
    /// server under [`send_identity_item_id`]. Replaces any existing one.
    pub fn create_send_identity(&mut self) -> Result<String, JsError> {
        let ident = SendIdentity::generate(1);
        let stored = B64.encode(&*ident.to_bytes());
        let blob = {
            let vault = self.vault()?;
            vault
                .encrypt_item(stored.as_bytes(), SEND_IDENTITY_ITEM_ID)
                .map_err(js_err)?
        };
        self.identity = Some(ident);
        serde_json::to_string(&blob).map_err(js_err)
    }

    /// Load the Send identity from its encrypted reserved vault item (the
    /// `EncryptedBlob` JSON fetched from the server). Call on unlock if present.
    pub fn load_send_identity(&mut self, blob_json: &str) -> Result<(), JsError> {
        let blob: EncryptedBlob = serde_json::from_str(blob_json).map_err(js_err)?;
        let ident = {
            let vault = self.vault()?;
            let stored = vault
                .decrypt_item(&blob, SEND_IDENTITY_ITEM_ID)
                .map_err(js_err)?;
            let bytes = B64.decode(&*stored).map_err(js_err)?;
            SendIdentity::from_bytes(&bytes).map_err(js_err)?
        };
        self.identity = Some(ident);
        Ok(())
    }

    /// `true` if a Send identity is loaded in memory.
    #[wasm_bindgen(getter)]
    pub fn has_send_identity(&self) -> bool {
        self.identity.is_some()
    }

    /// The PUBLIC half of the Send identity (JSON `PublicIdentity`) — this is
    /// what gets published/shared so others can encrypt to you.
    pub fn send_identity_public(&self) -> Result<String, JsError> {
        serde_json::to_string(&self.identity()?.public()).map_err(js_err)
    }

    /// Encrypt a note to a recipient. `recipient_public_json` is their
    /// `PublicIdentity`. If `sender_id` is set, the note is signed by this
    /// identity (sender stays hidden from the server, verifiable by the
    /// recipient). Returns the `SendBlob` JSON to upload.
    pub fn send_seal(
        &self,
        plaintext: &str,
        recipient_id: &str,
        recipient_public_json: &str,
        passphrase: Option<String>,
        sender_id: Option<String>,
    ) -> Result<String, JsError> {
        let recip: PublicIdentity = serde_json::from_str(recipient_public_json).map_err(js_err)?;
        let signer = match &sender_id {
            Some(id) => Some((self.identity()?, id.as_str())),
            None => None,
        };
        let blob = send::seal(
            plaintext.as_bytes(),
            recipient_id,
            &recip,
            passphrase.as_deref().map(str::as_bytes),
            signer,
        )
        .map_err(js_err)?;
        serde_json::to_string(&blob).map_err(js_err)
    }

    /// Open a `SendBlob` addressed to this identity. If `verify_sender_json`
    /// (the claimed sender's `PublicIdentity`) is supplied, the signature is
    /// verified. Returns JSON `{ "plaintext": "...", "sender": { "state":
    /// "anonymous"|"unverified"|"verified", "id": "…"|null } }`.
    pub fn send_open(
        &self,
        blob_json: &str,
        passphrase: Option<String>,
        verify_sender_json: Option<String>,
    ) -> Result<String, JsError> {
        let blob: send::SendBlob = serde_json::from_str(blob_json).map_err(js_err)?;
        let verifier: Option<PublicIdentity> = match &verify_sender_json {
            Some(j) => Some(serde_json::from_str(j).map_err(js_err)?),
            None => None,
        };
        let opened = send::open(
            &blob,
            self.identity()?,
            passphrase.as_deref().map(str::as_bytes),
            verifier.as_ref(),
        )
        .map_err(js_err)?;
        let plaintext = String::from_utf8(opened.plaintext.to_vec()).map_err(js_err)?;
        let (state, id) = match opened.sender {
            Sender::Anonymous => ("anonymous", None),
            Sender::Unverified(id) => ("unverified", Some(id)),
            Sender::Verified(id) => ("verified", Some(id)),
        };
        let out = serde_json::json!({
            "plaintext": plaintext,
            "sender": { "state": state, "id": id },
        });
        serde_json::to_string(&out).map_err(js_err)
    }

    /// Open a received `SendBlob` with this identity and **immediately**
    /// re-encrypt the note under a contact's lock phrase, returning the
    /// `LockedRecord` JSON. The identity-decrypted plaintext never crosses into
    /// JS (the whole step runs in WASM) — see the lock-phrase design §5. The app
    /// then stores the record as a vault item id [`send_locked_item_id`] (from
    /// the record's `local_id`) and read-once-deletes the inbox blob.
    ///
    /// `verify_sender_json` (the pinned contact's `PublicIdentity`) records a
    /// Verified trust state at lock time; `send_passphrase` is forwarded to the
    /// underlying open if the message also carried a sender passphrase.
    #[allow(clippy::too_many_arguments)]
    pub fn send_lock_finalize(
        &self,
        blob_json: &str,
        contact_id: &str,
        created_at: f64,
        send_passphrase: Option<String>,
        verify_sender_json: Option<String>,
        lock_phrase: &str,
        lock_salt_b64: &str,
        lock_kdf_json: &str,
    ) -> Result<String, JsError> {
        let blob: send::SendBlob = serde_json::from_str(blob_json).map_err(js_err)?;
        let verifier: Option<PublicIdentity> = match &verify_sender_json {
            Some(j) => Some(serde_json::from_str(j).map_err(js_err)?),
            None => None,
        };
        let salt = decode_salt(lock_salt_b64)?;
        let kdf_params: KdfParams = serde_json::from_str(lock_kdf_json).map_err(js_err)?;
        let record = pinlock::lock_finalize(
            &blob,
            self.identity()?,
            send_passphrase.as_deref().map(str::as_bytes),
            verifier.as_ref(),
            contact_id,
            created_at as i64,
            lock_phrase.as_bytes(),
            &salt,
            kdf_params,
        )
        .map_err(js_err)?;
        serde_json::to_string(&record).map_err(js_err)
    }

    // ─── Integrity manifest (verification on the Rust/WASM side, not in JS) ───

    /// Builds a deterministic manifest from a complete item map
    /// (`items_json` = object `{ id: encryptedBlob }`). Digest computation and
    /// ordering stay inside the audited Rust implementation.
    pub fn manifest_from_items(&self, items_json: &str) -> Result<String, JsError> {
        let items: HashMap<String, EncryptedBlob> =
            serde_json::from_str(items_json).map_err(js_err)?;
        let present: Vec<(&str, &EncryptedBlob)> =
            items.iter().map(|(id, blob)| (id.as_str(), blob)).collect();
        let manifest = Manifest::from_items(&present).map_err(js_err)?;
        serde_json::to_string(&manifest).map_err(js_err)
    }

    /// Adds or updates one encrypted item in a validated manifest and returns
    /// the updated manifest JSON.
    pub fn manifest_set_item(
        &self,
        manifest_json: &str,
        item_id: &str,
        blob_json: &str,
    ) -> Result<String, JsError> {
        let mut manifest: Manifest = serde_json::from_str(manifest_json).map_err(js_err)?;
        manifest.validate().map_err(js_err)?;
        let blob: EncryptedBlob = serde_json::from_str(blob_json).map_err(js_err)?;
        manifest.set(item_id, &blob).map_err(js_err)?;
        serde_json::to_string(&manifest).map_err(js_err)
    }

    /// Removes one item from a validated manifest and returns the updated
    /// manifest JSON. Removing an absent item is an idempotent no-op.
    pub fn manifest_remove_item(
        &self,
        manifest_json: &str,
        item_id: &str,
    ) -> Result<String, JsError> {
        let mut manifest: Manifest = serde_json::from_str(manifest_json).map_err(js_err)?;
        manifest.validate().map_err(js_err)?;
        manifest.remove(item_id).map_err(js_err)?;
        serde_json::to_string(&manifest).map_err(js_err)
    }

    /// Returns the validated manifest sequence as a JavaScript `bigint`, so
    /// clients never lose precision by parsing a `u64` through JSON numbers.
    pub fn manifest_seq(&self, manifest_json: &str) -> Result<u64, JsError> {
        let manifest: Manifest = serde_json::from_str(manifest_json).map_err(js_err)?;
        manifest.validate().map_err(js_err)?;
        Ok(manifest.seq())
    }

    /// Seals a manifest (JSON) under the vault key; returns the JSON blob.
    pub fn seal_manifest(&self, manifest_json: &str) -> Result<String, JsError> {
        let manifest: Manifest = serde_json::from_str(manifest_json).map_err(js_err)?;
        manifest.validate().map_err(js_err)?;
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
        manifest.validate().map_err(js_err)?;
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
    let auth_secret = Some(reg.auth_secret.expose_b64().to_string());
    Ok(Account {
        vault: Some(vault),
        registration_json,
        secret: Some(secret),
        auth_secret,
        identity: None,
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
    let auth_secret = Some(reg.auth_secret.expose_b64().to_string());
    Ok(Account {
        vault: Some(vault),
        registration_json,
        secret: Some(secret),
        auth_secret,
        identity: None,
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
    let (vault, auth) = Vault::unlock(
        master_password.as_bytes(),
        &secret,
        &reg.salt,
        reg.kdf,
        &reg.wrapped_vault_key,
    )
    .map_err(js_err)?;
    // The Secret Key is not retained after unlock: it is only a derivation
    // factor (HKDF salt), already consumed above. `secret: None` means
    // `reveal_secret` correctly fails on an unlocked account. The auth secret is
    // kept (server credential only) so the app can establish a session.
    Ok(Account {
        vault: Some(vault),
        registration_json: registration_json.to_string(),
        secret: None,
        auth_secret: Some(auth.expose_b64().to_string()),
        identity: None,
    })
}

/// Rebuilds an [`Account`] from a session blob produced by
/// [`Account::export_session`] — no password / Secret Key, no Argon2id. Used to
/// restore an unlocked session after the host (e.g. an MV3 service worker) was
/// torn down. The Secret Key is never present on a rehydrated account, so
/// `reveal_secret` correctly fails on it.
#[wasm_bindgen]
pub fn rehydrate(session_json: &str) -> Result<Account, JsError> {
    let v: serde_json::Value = serde_json::from_str(session_json).map_err(js_err)?;
    let vault_key_b64 = v["vault_key"]
        .as_str()
        .ok_or_else(|| JsError::new("missing vault_key"))?;
    let registration_json = v["registration_json"]
        .as_str()
        .ok_or_else(|| JsError::new("missing registration_json"))?;
    let auth_secret = v["auth_secret"].as_str().unwrap_or_default();

    // Defense in depth: the registration must be well-formed (reject malformed /
    // attacker-mangled stored sessions instead of building a half-valid Account).
    serde_json::from_str::<Registration>(registration_json)
        .map_err(|_| JsError::new("invalid registration"))?;

    // Decode into a buffer we zeroize once the key has been copied into the Vault.
    let mut key_bytes = B64.decode(vault_key_b64).map_err(js_err)?;
    let vault = Vault::from_key(&key_bytes).map_err(js_err)?;
    key_bytes.zeroize();
    Ok(Account {
        vault: Some(vault),
        registration_json: registration_json.to_string(),
        secret: None,
        auth_secret: if auth_secret.is_empty() {
            None
        } else {
            Some(auth_secret.to_string())
        },
        identity: None,
    })
}
