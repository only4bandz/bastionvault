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
const TAG_LEN: usize = 16;

/// Largest plaintext `encrypt` will seal. Derived from [`MAX_ENCODED_CT_LEN`]
/// so the bound holds on BOTH sides of the round trip: without it, an
/// oversized item would encrypt successfully, upload as a valid blob, and
/// only fail at decrypt time — silent, permanent data loss discovered on
/// read. Refusing at write time keeps every sealed blob readable.
pub const MAX_PLAINTEXT_LEN: usize = (MAX_ENCODED_CT_LEN / 4) * 3 - TAG_LEN;

/// An encrypted envelope: version + nonce + ciphertext (which includes the auth
/// tag).
///
/// Serializable (base64) for server storage and transport. Contains no secret:
/// without the key, it is noise.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
    // Symmetric to decrypt's ceiling: never seal what cannot be unsealed.
    if plaintext.len() > MAX_PLAINTEXT_LEN {
        return Err(CryptoError::Malformed);
    }
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

#[cfg(test)]
mod bounds {
    //! The encrypt-side ceiling must guarantee the decrypt-side ceiling: any
    //! blob `encrypt` produces has to remain decodable under decrypt's
    //! anti-DoS bound, and anything larger must be refused before sealing.
    use super::*;

    #[test]
    fn max_plaintext_round_trips_and_one_more_byte_is_refused() {
        let key = SecretKey::from_bytes([0x11u8; 32]);

        let max = vec![0u8; MAX_PLAINTEXT_LEN];
        let blob = encrypt(&key, &max, b"bounds").unwrap();
        assert!(
            blob.ct.len() <= MAX_ENCODED_CT_LEN,
            "encoded ct escapes the decrypt bound"
        );
        assert_eq!(decrypt(&key, &blob, b"bounds").unwrap(), max);

        let over = vec![0u8; MAX_PLAINTEXT_LEN + 1];
        assert!(matches!(
            encrypt(&key, &over, b"bounds"),
            Err(CryptoError::Malformed)
        ));
    }
}

#[cfg(test)]
mod kat {
    //! XChaCha20-Poly1305 known-answer test for the envelope's decrypt path.
    //! A ciphertext produced by an earlier build (fixed key/nonce/AAD) must
    //! still decrypt to the original plaintext, and any tamper must fail.
    use super::*;

    #[test]
    fn xchacha20poly1305_decrypt_vector() {
        let key = SecretKey::from_bytes([0x42u8; 32]);
        let blob = EncryptedBlob {
            v: FORMAT_VERSION,
            nonce: "JCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk".to_string(),
            ct: "zjC4EgAJLcjRWFpIuZcwYrtP0ZApxLg8YEhrvQ==".to_string(),
        };
        let out = decrypt(&key, &blob, b"item-42").unwrap();
        assert_eq!(out, b"known-answer");

        // Wrong AAD, wrong key, and a flipped version all fail (no plaintext).
        assert!(decrypt(&key, &blob, b"item-43").is_err());
        assert!(decrypt(&SecretKey::from_bytes([0x43u8; 32]), &blob, b"item-42").is_err());
        let mut bumped = blob.clone();
        bumped.v = FORMAT_VERSION + 1;
        assert!(decrypt(&key, &bumped, b"item-42").is_err());
    }
}
