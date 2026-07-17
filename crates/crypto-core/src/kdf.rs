//! Key derivation from the master password.
//!
//! Two stages:
//! 1. **Argon2id** (slow, memory-hard) turns the master password + salt into a
//!    256-bit *master key*. This is the only expensive step — it protects
//!    against offline brute-force.
//! 2. **HKDF-SHA256** (fast) derives several single-purpose sub-keys from the
//!    master key (vault encryption, authentication secret, etc.).
//!
//! The master key never leaves the device. The server only receives the
//! authentication secret (see [`crate::vault`]).

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::account_secret::AccountSecret;
use crate::error::{CryptoError, Result};
use crate::secret::{SecretKey, KEY_LEN};

/// Length of the Argon2 salt (128 bits).
pub const SALT_LEN: usize = 16;

/// Argon2id parameters, stored with the account so they can be hardened later
/// without breaking existing accounts.
///
/// Default values aligned with password-manager recommendations (stronger than
/// the OWASP minimum): 64 MiB, 3 passes, p=4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KdfParams {
    /// Memory cost in kibibytes.
    pub mem_kib: u32,
    /// Number of passes (time cost).
    pub iterations: u32,
    /// Degree of parallelism.
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            mem_kib: 64 * 1024, // 64 MiB
            iterations: 3,
            parallelism: 4,
        }
    }
}

impl KdfParams {
    // ─── KDF policy ───
    // Floors: the minimum acceptable to CREATE a new vault. Below this, offline
    // brute-force becomes too cheap.
    /// Minimum memory (19 MiB, the OWASP baseline for Argon2id).
    pub const MIN_MEM_KIB: u32 = 19 * 1024;
    /// Minimum passes.
    pub const MIN_ITERATIONS: u32 = 2;
    /// Minimum parallelism.
    pub const MIN_PARALLELISM: u32 = 1;
    // Ceilings: above this we refuse to even try — otherwise a malicious server
    // or a corrupted record could exhaust the client's RAM/CPU. WASM uses a
    // deliberately tighter budget because an oversized linear-memory growth or
    // long synchronous derivation can terminate the browser tab.
    #[cfg(not(target_arch = "wasm32"))]
    /// Maximum tolerated native memory (1 GiB).
    pub const MAX_MEM_KIB: u32 = 1024 * 1024;
    #[cfg(target_arch = "wasm32")]
    /// Maximum tolerated browser memory (128 MiB).
    pub const MAX_MEM_KIB: u32 = 128 * 1024;
    #[cfg(not(target_arch = "wasm32"))]
    /// Maximum native passes.
    pub const MAX_ITERATIONS: u32 = 20;
    #[cfg(target_arch = "wasm32")]
    /// Maximum browser passes.
    pub const MAX_ITERATIONS: u32 = 6;
    #[cfg(not(target_arch = "wasm32"))]
    /// Maximum native parallelism.
    pub const MAX_PARALLELISM: u32 = 16;
    #[cfg(target_arch = "wasm32")]
    /// Maximum browser parallelism.
    pub const MAX_PARALLELISM: u32 = 4;

    /// Policy for a **new** vault (registration / rotation):
    /// security floor AND anti-DoS ceiling.
    pub fn validate_for_new_vault(&self) -> Result<()> {
        if self.mem_kib < Self::MIN_MEM_KIB
            || self.iterations < Self::MIN_ITERATIONS
            || self.parallelism < Self::MIN_PARALLELISM
        {
            return Err(CryptoError::KdfPolicy);
        }
        self.validate_ceiling()
    }

    /// Policy for **opening** an existing vault: anti-DoS ceiling only.
    ///
    /// The floor is NOT applied here: a vault created under an older policy
    /// (weaker params) must remain unlockable. Hardening happens on rotation,
    /// not by locking the user out of their data.
    pub fn validate_for_unlock(&self) -> Result<()> {
        self.validate_ceiling()
    }

    /// `true` if the parameters are below the current floor — the caller should
    /// offer a rotation to harden the vault.
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

/// Generates a random 128-bit salt via the system CSPRNG.
pub fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Stage 1 — derives the 256-bit master key via Argon2id.
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
    // `out` is copied into the SecretKey; wipe the stack copy.
    use zeroize::Zeroize;
    out.zeroize();
    Ok(key)
}

/// Domain labels for HKDF — they guarantee that sub-keys for different purposes
/// are cryptographically independent.
const INFO_VAULT_WRAP: &[u8] = b"pm:v1:vault-wrap-key";
const INFO_AUTH: &[u8] = b"pm:v1:auth-secret";

/// Stage 2 — derives the key that encrypts (wraps) the vault key.
pub fn derive_wrap_key(master: &SecretKey, account_secret: &AccountSecret) -> SecretKey {
    expand(master, account_secret, INFO_VAULT_WRAP)
}

/// Stage 2 — derives the authentication secret sent to the server.
///
/// The server learns nothing about the master key: HKDF is one-way and this
/// secret is independent of the vault's encryption key.
///
/// ⚠️ Server-side, this secret MUST be slowly re-hashed (Argon2id) before
/// storage and compared in constant time — see [`crate::vault::Registration`].
pub fn derive_auth_secret(master: &SecretKey, account_secret: &AccountSecret) -> SecretKey {
    expand(master, account_secret, INFO_AUTH)
}

/// HKDF with the **Secret Key as the salt** (HKDF-Extract), then per-domain Expand.
///
/// Mixing the Secret Key in at the Extract stage makes it enter every sub-key:
/// without it, nothing can be derived even if the master key (hence the
/// password) is known. This is what makes offline brute-force infeasible.
fn expand(master: &SecretKey, account_secret: &AccountSecret, info: &[u8]) -> SecretKey {
    let hk = Hkdf::<Sha256>::new(Some(account_secret.as_bytes()), master.as_bytes());
    let mut out = [0u8; KEY_LEN];
    hk.expand(info, &mut out)
        .expect("32 bytes <= 255 * HashLen");
    let key = SecretKey::from_bytes(out);
    use zeroize::Zeroize;
    out.zeroize();
    key
}
