//! Account secret key ("Secret Key", 1Password model): a random 128-bit secret
//! held **only** by the user and NEVER sent to the server.
//!
//! It enters key derivation as the **HKDF salt** (see [`crate::kdf`]), which
//! mixes it into *every* sub-key (wrap + auth). As a result: an attacker who
//! steals all server-side data (salt, wrapped vault, auth secret) can derive
//! **nothing** without this Secret Key — offline brute-force becomes infeasible
//! even with a weak master password.
//!
//! It is shown only once (Emergency Kit) and re-entered/scanned on each new
//! device.

use data_encoding::BASE32_NOPAD;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{CryptoError, Result};

/// Length of the Secret Key (128 bits — the sweet spot for security/usability,
/// aligned with 1Password; combined with the password, 128 bits are more than
/// enough).
pub const ACCOUNT_SECRET_LEN: usize = 16;

/// Length of the checksum encoded with the key (16 bits → ~1/65536 chance of
/// letting a typo through).
const CHECKSUM_LEN: usize = 2;

/// Generous byte bound for a human-entered formatted Secret Key. The canonical
/// form is 37 ASCII bytes; extra room permits whitespace and separators while
/// rejecting attacker-controlled megabyte inputs before normalization allocates.
const MAX_FORMATTED_INPUT_LEN: usize = 128;

/// Version prefix of the encoded format, so the scheme can evolve later.
/// The "1" is not part of the base32 alphabet (A-Z2-7): no collision with the
/// encoded body is possible.
const VERSION_TAG: &str = "A1";

/// Truncated (16-bit) checksum of the key, to detect a mistyped entry
/// **locally**, before any expensive Argon2id derivation.
fn checksum(secret: &[u8; ACCOUNT_SECRET_LEN]) -> [u8; CHECKSUM_LEN] {
    let mut h = Sha256::new();
    h.update(b"pm:v1:secret-key-checksum");
    h.update(secret);
    let digest = h.finalize();
    [digest[0], digest[1]]
}

/// 128-bit account secret, wiped from memory on drop.
///
/// Does not derive `Clone`/`Debug`/`Serialize`: this secret must never be
/// copied, logged, or serialized by accident (it does not leave the device).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AccountSecret([u8; ACCOUNT_SECRET_LEN]);

impl AccountSecret {
    /// Generates a new Secret Key via the system CSPRNG.
    pub fn generate() -> Self {
        let mut bytes = [0u8; ACCOUNT_SECRET_LEN];
        OsRng.fill_bytes(&mut bytes);
        let secret = Self(bytes);
        bytes.zeroize();
        secret
    }

    /// Raw bytes — internal use (HKDF salt).
    pub(crate) fn as_bytes(&self) -> &[u8; ACCOUNT_SECRET_LEN] {
        &self.0
    }

    /// Human-readable representation: `A1-XXXXX-XXXXX-…` (uppercase base32,
    /// grouped in fives, 16-bit checksum included). To be stored in the
    /// Emergency Kit / QR code.
    pub fn to_formatted(&self) -> String {
        // Payload = secret ‖ checksum, in a buffer wiped on drop.
        let mut payload = Zeroizing::new(Vec::with_capacity(ACCOUNT_SECRET_LEN + CHECKSUM_LEN));
        payload.extend_from_slice(&self.0);
        payload.extend_from_slice(&checksum(&self.0));
        // The base32 body IS the secret (minus formatting); wipe it on drop.
        let body = Zeroizing::new(BASE32_NOPAD.encode(&payload));
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

    /// Parses a typed or scanned Secret Key. Tolerant: ignores dashes, spaces,
    /// and case, accepts the value with or without the version prefix. The
    /// checksum allows **rejecting a typo immediately** (without Argon2id).
    pub fn parse(input: &str) -> Result<Self> {
        if input.len() > MAX_FORMATTED_INPUT_LEN {
            return Err(CryptoError::Malformed);
        }
        // Normalize into a single wiped-on-drop buffer: the typed key is the
        // secret itself, so no unwiped copy of it may escape (`collect` +
        // `to_ascii_uppercase` used to leave two).
        let mut cleaned = Zeroizing::new(String::with_capacity(input.len()));
        for c in input.chars().filter(|c| c.is_ascii_alphanumeric()) {
            cleaned.push(c.to_ascii_uppercase());
        }
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
        // Constant-time compare: the checksum is derived from the secret, so a
        // variable-time `!=` on it would leak secret-dependent timing. Matches
        // the crate's discipline elsewhere (vault.rs / pinlock.rs use `subtle`).
        if checksum(&secret)
            .ct_eq(&bytes[ACCOUNT_SECRET_LEN..])
            .unwrap_u8()
            == 0
        {
            secret.zeroize();
            return Err(CryptoError::Malformed);
        }
        let out = Self(secret);
        secret.zeroize();
        Ok(out)
    }

    /// "Emergency Kit" text to print and keep offline.
    ///
    /// Contains the Secret Key (recoverable nowhere else) and a space to write
    /// down the master password by hand.
    pub fn emergency_kit(&self, account_label: &str) -> String {
        format!(
            "================ EMERGENCY KIT — VAULT ================\n\
             \n\
             Account     : {account_label}\n\
             Secret Key  : {secret}\n\
             \n\
             Master password : ______________________________\n\
             \n\
             - Keep this document offline, in a safe place.\n\
             - Without both the Secret Key AND the master password, the vault is\n\
             \x20 PERMANENTLY unrecoverable: no one, not even the server,\n\
             \x20 can recover them.\n\
             =======================================================\n",
            account_label = account_label,
            secret = self.to_formatted(),
        )
    }
}
