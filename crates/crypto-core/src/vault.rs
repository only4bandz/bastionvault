//! High-level API: registration, unlocking, item encryption.
//!
//! This is the interface the web app and the Chrome extension will use (via
//! WASM). Everything happens client-side. The server only stores opaque data.
//!
//! Key model (inspired by Bitwarden / 1Password):
//!
//! ```text
//!   master password ──Argon2id(salt)──► master key
//!                                          │
//!                        ┌─────HKDF────────┼─────HKDF─────┐
//!                        ▼                                ▼
//!                    wrap key                        auth secret ──► server
//!                        │                          (verifies identity,
//!                        │ encrypts/decrypts          opens nothing)
//!                        ▼
//!     vault key (random) ──encrypts──► all the items
//! ```
//!
//! The vault key is a random key, *wrapped* by the wrap key. Benefit: changing
//! the master password only re-wraps the vault key — no need to re-encrypt all
//! the items.

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

/// AAD binding the wrapped vault key to its role.
const AAD_VAULT_KEY: &[u8] = b"pm:v1:wrapped-vault-key";

/// AAD binding the integrity manifest to its role.
const AAD_MANIFEST: &[u8] = b"pm:v1:manifest";

/// Bound on the received (untrusted) encoded salt, checked before decoding.
/// The salt is 16 bytes → ~24 base64 characters; 64 leaves margin.
const MAX_ENCODED_SALT_LEN: usize = 64;

/// Authentication secret presented to the server. A dedicated type rather than
/// a bare `String` to avoid leaks: `Debug` is **redacted**, it is not `Clone`,
/// and comparison is done in **constant time**.
///
/// Serializes/deserializes transparently as the underlying base64 string (the
/// wire format is unchanged).
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct AuthSecret(String);

impl AuthSecret {
    fn from_b64(value: String) -> Self {
        Self(value)
    }

    /// Exposes the base64 value — to be sent **only to the server**, never logged.
    pub fn expose_b64(&self) -> &str {
        &self.0
    }

    /// Bytes (base64) for controlled transmission/comparison.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Constant-time equality with another authentication secret.
    pub fn ct_eq(&self, other: &AuthSecret) -> bool {
        auth_secret_eq(self.0.as_bytes(), other.0.as_bytes())
    }
}

impl fmt::Debug for AuthSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthSecret(<redacted>)")
    }
}

/// Data to publish to the server during registration. None of it is secret in
/// the sense that the server cannot decrypt anything with it.
///
/// No `Clone`: `auth_secret` is a credential, so we avoid silent copies.
#[derive(Debug, Serialize, Deserialize)]
pub struct Registration {
    /// Version of the registration format, to migrate the schema without
    /// breaking existing accounts.
    pub version: u8,
    /// Argon2 salt (base64). Public by nature.
    pub salt: String,
    /// KDF parameters to reuse at login.
    pub kdf: KdfParams,
    /// Vault key wrapped by the wrap key.
    pub wrapped_vault_key: EncryptedBlob,
    /// Authentication secret (base64), presented to the server to prove
    /// identity — it opens **no** vault (independent of the wrap key).
    ///
    /// ⚠️ SERVER SECURITY (requirement): although this secret has 256 bits of
    /// entropy, the server must NEVER store it in the clear or with a fast hash
    /// (SHA-256, low-cost bcrypt, etc.). It MUST run it through a dedicated slow
    /// hash (Argon2id preferably) before storage, and compare it in constant
    /// time via [`AuthSecret::ct_eq`] / [`auth_secret_eq`]. Goal: a database
    /// leak must never allow replaying a user's authentication.
    pub auth_secret: AuthSecret,
}

/// An unlocked vault: holds the vault key in the clear (in memory, wiped on
/// drop) and can encrypt/decrypt items.
pub struct Vault {
    vault_key: SecretKey,
}

impl Vault {
    /// Creates a new account from a master password.
    ///
    /// Generates a random [`AccountSecret`] (Secret Key) and **returns** it: the
    /// caller MUST show it only once (Emergency Kit) and then never store it on
    /// the server side. Uses the default [`KdfParams`].
    pub fn register(master_password: &[u8]) -> Result<(Self, Registration, AccountSecret)> {
        Self::register_with(master_password, KdfParams::default())
    }

    /// Variant of [`Vault::register`] with explicit KDF parameters.
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

        // Secret Key: second derivation factor, never sent to the server.
        let account_secret = AccountSecret::generate();
        let wrap_key = kdf::derive_wrap_key(&master, &account_secret);
        let auth_secret = kdf::derive_auth_secret(&master, &account_secret);

        // Vault key = random key, independent of the password.
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

    /// Unlocks an existing vault.
    ///
    /// Requires the master password **and** the [`AccountSecret`] (Secret Key):
    /// both factors are necessary. `salt`, `kdf`, `wrapped_vault_key` come from
    /// the server (fetched via the email before input). Returns the vault and
    /// the authentication secret to present to the server.
    ///
    /// A wrong password OR a wrong Secret Key makes the unwrap fail with
    /// [`CryptoError::Aead`] — indistinguishable from tampered data.
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
        // Ceiling only: we accept weak "legacy" params (otherwise we would lock
        // the user out), but we reject absurd params that would exhaust memory
        // before any useful decryption.
        kdf_params.validate_for_unlock()?;
        // Bound on the untrusted salt before decoding (anti-allocation).
        if salt.len() > MAX_ENCODED_SALT_LEN {
            return Err(CryptoError::Malformed);
        }
        let salt_bytes = B64.decode(salt).map_err(|_| CryptoError::Malformed)?;
        let salt_arr: [u8; kdf::SALT_LEN] =
            salt_bytes.try_into().map_err(|_| CryptoError::Malformed)?;

        let master = kdf::derive_master_key(master_password, &salt_arr, kdf_params)?;
        let wrap_key = kdf::derive_wrap_key(&master, account_secret);
        let auth_secret = kdf::derive_auth_secret(&master, account_secret);

        // The plaintext vault key must only pass through wiped buffers:
        // `Zeroizing` clears the decrypted Vec, and we wipe the stack copy once
        // the key has been moved into the `SecretKey`.
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

    /// Exports the raw vault key for an **in-memory session handoff** — e.g. a
    /// browser extension whose MV3 service worker is evicted every few seconds
    /// and must rehydrate the unlocked vault without re-deriving Argon2id.
    ///
    /// ⚠️ These bytes ARE the crown decryption key: anyone holding them can
    /// decrypt the whole vault. They grant no *new* power in a browser context
    /// (a same-origin script can already read the key from memory — see the
    /// crypto-wasm threat model), but the caller MUST keep them in RAM only
    /// (e.g. `chrome.storage.session`, never `localStorage`/disk), for a bounded
    /// lifetime, and wipe them on lock/expiry. The returned buffer is
    /// `Zeroizing`, so it is wiped when dropped.
    pub fn export_key(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.vault_key.as_bytes().to_vec())
    }

    /// Rebuilds a vault from a key previously produced by [`Vault::export_key`].
    /// This is a **session-rehydration** path, not an authentication one: it
    /// performs no password/Secret Key derivation. Errors if the key is not
    /// exactly [`KEY_LEN`] bytes.
    pub fn from_key(key_bytes: &[u8]) -> Result<Self> {
        let mut key_arr: [u8; KEY_LEN] =
            key_bytes.try_into().map_err(|_| CryptoError::Malformed)?;
        let vault_key = SecretKey::from_bytes(key_arr);
        key_arr.zeroize();
        Ok(Self { vault_key })
    }

    /// Encrypts an item's content. `item_id` is authenticated (AAD) so that a
    /// ciphertext cannot be moved to another item.
    pub fn encrypt_item(&self, plaintext: &[u8], item_id: &str) -> Result<EncryptedBlob> {
        aead::encrypt(&self.vault_key, plaintext, item_id.as_bytes())
    }

    /// Decrypts an item's content.
    ///
    /// The returned plaintext is **sensitive material**: it is wrapped in
    /// [`Zeroizing`] so it is wiped from memory as soon as the caller drops it.
    pub fn decrypt_item(&self, blob: &EncryptedBlob, item_id: &str) -> Result<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(aead::decrypt(
            &self.vault_key,
            blob,
            item_id.as_bytes(),
        )?))
    }

    /// Seals an integrity [`Manifest`] under the vault key. The resulting blob
    /// is opaque to the server and readable only by this vault.
    pub fn seal_manifest(&self, manifest: &Manifest) -> Result<EncryptedBlob> {
        manifest.validate()?;
        let bytes = serde_json::to_vec(manifest).map_err(|_| CryptoError::Malformed)?;
        aead::encrypt(&self.vault_key, &bytes, AAD_MANIFEST)
    }

    /// Opens a sealed manifest. Fails if the blob is tampered with or does not
    /// come from this vault ([`CryptoError::Aead`]), or if the manifest is
    /// malformed (unsorted / duplicate entries → [`CryptoError::Malformed`]).
    ///
    /// ⚠️ This variant does NOT protect against rollback: a server can re-serve
    /// an older (but authentic) manifest. Use
    /// [`Vault::open_manifest_checked`] as soon as you know the latest `seq`.
    pub fn open_manifest(&self, blob: &EncryptedBlob) -> Result<Manifest> {
        let bytes = aead::decrypt(&self.vault_key, blob, AAD_MANIFEST)?;
        let manifest: Manifest =
            serde_json::from_slice(&bytes).map_err(|_| CryptoError::Malformed)?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Opens a sealed manifest while **refusing a rollback**: the manifest's
    /// `seq` must be ≥ `last_seen_seq` (the latest the client knows), otherwise
    /// [`CryptoError::StaleManifest`]. This is the preferred API for syncing.
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

    /// Re-wraps the vault key under a new master password, without re-encrypting
    /// the items. Returns the new [`Registration`].
    ///
    /// The [`KdfParams`] are provided explicitly: rotation must never silently
    /// reset KDF parameters chosen by the caller (which could weaken them). Pass
    /// [`KdfParams::default`] for the standard behavior.
    ///
    /// The [`AccountSecret`] stays **unchanged** during a master-password
    /// rotation (it is the account's secret, not the password's): pass it back in.
    pub fn rotate_master_password(
        &self,
        new_password: &[u8],
        account_secret: &AccountSecret,
        kdf_params: KdfParams,
    ) -> Result<Registration> {
        if new_password.is_empty() {
            return Err(CryptoError::EmptyPassword);
        }
        // Rotation is the natural moment to harden: we apply the current policy
        // (floor + ceiling), not just the ceiling.
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

/// Compares two authentication secrets in constant time (anti timing-attack).
/// Intended for the server when it verifies the presented secret.
pub fn auth_secret_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}
