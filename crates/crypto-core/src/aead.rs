//! Authenticated encryption (AEAD) with XChaCha20-Poly1305.
//!
//! Why XChaCha20-Poly1305: a 192-bit nonce, so generating the nonce randomly is
//! safe (negligible collision probability), unlike AES-GCM whose 96-bit nonce
//! forces delicate state management.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};

use crate::error::{CryptoError, Result};
use crate::secret::SecretKey;

const NONCE_LEN: usize = 24;

/// Version of the AEAD envelope format. Allows migration (new algorithm, new
/// scheme) without making existing vaults unreadable.
pub const FORMAT_VERSION: u8 = 1;

// Bounds on UNTRUSTED inputs, checked BEFORE any base64 decoding or allocation:
// a blob supplied by a malicious server must not be able to trigger a massive
// allocation before authentication. The encoded nonce is ~32 bytes; we cap the
// encoded ciphertext at ~8 MiB (≈ 6 MiB of plaintext), generous for a secure
// note but an anti-DoS safeguard.
const MAX_ENCODED_NONCE_LEN: usize = 64;
const MAX_ENCODED_CT_LEN: usize = 8 * 1024 * 1024;

/// An encrypted envelope: version + nonce + ciphertext (which includes the auth
/// tag).
///
/// Serializable (base64) for server storage and transport. Contains no secret:
/// without the key, it is noise.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedBlob {
    /// Format version (see [`FORMAT_VERSION`]).
    pub v: u8,
    /// 192-bit nonce, base64-encoded.
    pub nonce: String,
    /// Ciphertext + Poly1305 tag, base64-encoded.
    pub ct: String,
}

/// Builds the effective AAD by prefixing it with the format version. This way
/// the version `v` (metadata outside the ciphertext) is **authenticated**:
/// flipping it invalidates the tag, instead of being just a free field on the
/// server side.
fn versioned_aad(version: u8, aad: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + aad.len());
    out.push(version);
    out.extend_from_slice(aad);
    out
}

/// Encrypts `plaintext` with `key`.
///
/// `aad` (additional authenticated data) is authenticated but not encrypted:
/// useful for binding the ciphertext to a context (e.g. the item id) and
/// preventing a blob from being moved elsewhere. The format version is bound to
/// it too. Pass `&[]` if there is no specific context.
pub(crate) fn encrypt(key: &SecretKey, plaintext: &[u8], aad: &[u8]) -> Result<EncryptedBlob> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let aad = versioned_aad(FORMAT_VERSION, aad);
    let ct = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::Aead)?;
    Ok(EncryptedBlob {
        v: FORMAT_VERSION,
        nonce: B64.encode(nonce),
        ct: B64.encode(ct),
    })
}

/// Decrypts an envelope. Fails if the key is wrong, the nonce/ciphertext is
/// malformed, or the ciphertext (or `aad`) has been tampered with.
pub(crate) fn decrypt(key: &SecretKey, blob: &EncryptedBlob, aad: &[u8]) -> Result<Vec<u8>> {
    // Known version?
    if blob.v != FORMAT_VERSION {
        return Err(CryptoError::Malformed);
    }
    // Input bounds BEFORE decoding/allocation (anti-DoS on untrusted input).
    if blob.nonce.len() > MAX_ENCODED_NONCE_LEN || blob.ct.len() > MAX_ENCODED_CT_LEN {
        return Err(CryptoError::Malformed);
    }
    let nonce_bytes = B64
        .decode(&blob.nonce)
        .map_err(|_| CryptoError::Malformed)?;
    if nonce_bytes.len() != NONCE_LEN {
        return Err(CryptoError::Malformed);
    }
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ct = B64.decode(&blob.ct).map_err(|_| CryptoError::Malformed)?;

    let aad = versioned_aad(blob.v, aad);
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: &ct,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::Aead)
}
