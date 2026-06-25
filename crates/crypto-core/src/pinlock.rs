//! # Bastion Send — per-contact **lock phrase** (P0 core)
//!
//! Implements `docs/bastion-pin-lock-design.md` (v0.2, audit-incorporated). The
//! *recipient* re-encrypts a received [`SendBlob`] under a key derived from a
//! per-contact lock phrase, then drops the identity-decryptable original (server
//! delete is handled by later phases). Reading a locked record requires
//! `(vault key) AND (lock phrase)`.
//!
//! Honest scope (see the design §2): the lock phrase is a **glance defense /
//! local compartment**, not strong end-to-end secrecy — a low-entropy phrase is
//! offline-guessable from the locked blob, and a malicious server may still hold
//! the identity-decryptable original. Argon2id only *slows* guessing.
//!
//! Construction:
//! - `lock_key = HKDF(ikm = Argon2id(phrase, salt, kdf), info = "pm:v1:send/pin-lock")`.
//! - `lock_commit = HKDF(lock_key, info = "pm:v1:send/pin-lock/commit")` — a
//!   key-commitment checked in constant time *before* the AEAD (closes the
//!   partitioning-oracle class, mirrors Send's CEK commit).
//! - Inner `{ plaintext, sender_state, sender_id }` is sealed with
//!   XChaCha20-Poly1305 under `lock_key`, with a **length-prefixed AAD** binding
//!   `domain ‖ version ‖ contact_id ‖ message_id ‖ kdf ‖ salt` (defeats blob
//!   swapping across contacts/messages and param/salt tampering).
//!
//! [`lock_finalize`] opens the Send blob and produces the locked record in one
//! call, so the identity-decrypted plaintext **never leaves this crate**.

use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::aead::{self, EncryptedBlob};
use crate::error::{CryptoError, Result};
use crate::kdf::{self, KdfParams, SALT_LEN};
use crate::secret::SecretKey;
use crate::send::{self, IdentityKeys, PublicIdentity, SendBlob, Sender};

const D_PIN: &[u8] = b"pm:v1:send/pin-lock";
const D_PIN_COMMIT: &[u8] = b"pm:v1:send/pin-lock/commit";
const PIN_V: u8 = 1;
const MSG_ID_LEN: usize = 16;
const LOCAL_ID_LEN: usize = 16;
const COMMIT_LEN: usize = 32;

/// WASM-safe default Argon2id params for a lock phrase (design §4.1): high
/// memory (the only anti-GPU lever) and **parallelism = 1** — browser WASM is
/// effectively single-threaded, so `p>1` would help only a multi-core attacker.
/// Within `KdfParams::MAX_*`, so [`KdfParams::validate_for_unlock`] accepts it.
pub fn default_lock_kdf() -> KdfParams {
    KdfParams {
        mem_kib: 128 * 1024, // 128 MiB
        iterations: 3,
        parallelism: 1,
    }
}

// ── small helpers (kept local so this module is self-contained) ──

fn b64(bytes: &[u8]) -> String {
    use base64::{engine::general_purpose::STANDARD as B, Engine};
    B.encode(bytes)
}
/// Decode base64 with no size bound — only for already-authenticated data.
fn unb64(s: &str) -> Result<Vec<u8>> {
    use base64::{engine::general_purpose::STANDARD as B, Engine};
    B.decode(s).map_err(|_| CryptoError::Malformed)
}
/// Decode a field that must be exactly `n` bytes, rejecting oversized input
/// before allocating.
fn unb64_exact(s: &str, n: usize) -> Result<Vec<u8>> {
    if s.len() > n.saturating_mul(4).saturating_div(3).saturating_add(8) {
        return Err(CryptoError::Malformed);
    }
    let v = unb64(s)?;
    if v.len() != n {
        return Err(CryptoError::Malformed);
    }
    Ok(v)
}
fn hkdf32(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut out = [0u8; 32];
    hk.expand(info, &mut out)
        .expect("32 within HKDF output limit");
    out
}

/// Length-prefixed framing so concatenated AAD fields are unambiguous.
fn put(buf: &mut Vec<u8>, field: &[u8]) {
    buf.extend_from_slice(&(field.len() as u32).to_be_bytes());
    buf.extend_from_slice(field);
}

fn ct_ne(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.ct_eq(b).unwrap_u8() == 0
}

// ── record format ──

/// A message locked under a contact's lock phrase. Stored (by later phases) as
/// the value of a reserved vault item `bastion:send-locked:<local_id>`, which is
/// itself vault-encrypted — so the final plaintext needs both the vault key and
/// the lock phrase. The vault item *id* uses the random `local_id`, never the
/// server-visible `message_id` (design §7), so the sync server can't correlate a
/// deleted inbox message with a stored locked item.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LockedRecord {
    pub v: u8,
    pub local_id: String,    // base64, 16 random bytes (vault item id)
    pub contact_id: String,  // stable, unique per contact
    pub message_id: String,  // base64, 16 bytes (vault-encrypted; not server-visible)
    pub lock_commit: String, // base64, 32 bytes
    pub body: EncryptedBlob, // inner payload under lock_key
    pub created_at: i64,     // display hint (server timestamp; not security-bearing)
}

/// Inner payload, sealed under `lock_key` (AAD-bound).
#[derive(Serialize, Deserialize)]
struct LockedInner {
    plaintext: String, // base64
    sender_state: u8,  // 0 = anonymous, 1 = unverified, 2 = verified
    #[serde(skip_serializing_if = "Option::is_none")]
    sender_id: Option<String>,
}

/// Result of opening a locked record.
pub struct LockedOpened {
    pub plaintext: Zeroizing<Vec<u8>>,
    pub sender: Sender,
}

fn derive_lock_key(phrase: &[u8], salt: &[u8; SALT_LEN], kdf: KdfParams) -> Result<SecretKey> {
    let ikm = kdf::derive_master_key(phrase, salt, kdf)?; // Argon2id (SecretKey, zeroized on drop)
    Ok(SecretKey::from_bytes(hkdf32(ikm.as_bytes(), D_PIN)))
}

fn lock_aad(
    contact_id: &str,
    message_id: &[u8],
    kdf: &KdfParams,
    salt: &[u8; SALT_LEN],
) -> Vec<u8> {
    let mut b = Vec::new();
    put(&mut b, D_PIN);
    b.push(PIN_V);
    put(&mut b, contact_id.as_bytes());
    put(&mut b, message_id);
    let mut k = Vec::with_capacity(12);
    k.extend_from_slice(&kdf.mem_kib.to_be_bytes());
    k.extend_from_slice(&kdf.iterations.to_be_bytes());
    k.extend_from_slice(&kdf.parallelism.to_be_bytes());
    put(&mut b, &k);
    put(&mut b, salt);
    b
}

fn sender_state(s: &Sender) -> (u8, Option<String>) {
    match s {
        Sender::Anonymous => (0, None),
        Sender::Unverified(id) => (1, Some(id.clone())),
        Sender::Verified(id) => (2, Some(id.clone())),
    }
}

// ── lock / open ──

/// Open a received [`SendBlob`] with the recipient identity and immediately
/// re-encrypt the plaintext under the contact's lock phrase, returning the
/// locked record. The identity-decrypted plaintext never leaves this function.
///
/// `send_passphrase` / `verify_sender` are forwarded to [`send::open`] (a
/// message may *also* carry a sender-set passphrase, and the caller may pin the
/// sender's identity to record a Verified trust state). `created_at` is the
/// server timestamp, kept only as a display hint.
#[allow(clippy::too_many_arguments)]
pub fn lock_finalize(
    blob: &SendBlob,
    identity: &IdentityKeys,
    send_passphrase: Option<&[u8]>,
    verify_sender: Option<&PublicIdentity>,
    contact_id: &str,
    created_at: i64,
    lock_phrase: &[u8],
    lock_salt: &[u8; SALT_LEN],
    lock_kdf: KdfParams,
) -> Result<LockedRecord> {
    lock_kdf.validate_for_unlock()?; // ceiling check (anti-DoS)

    // Identity-decrypt in-crate only.
    let opened = send::open(blob, identity, send_passphrase, verify_sender)?;
    let message_id = unb64_exact(&blob.message_id, MSG_ID_LEN)?;

    let lock_key = derive_lock_key(lock_phrase, lock_salt, lock_kdf)?;
    let commit = hkdf32(lock_key.as_bytes(), D_PIN_COMMIT);

    let (state, sid) = sender_state(&opened.sender);
    let mut inner = LockedInner {
        plaintext: b64(&opened.plaintext),
        sender_state: state,
        sender_id: sid,
    };
    let inner_bytes =
        Zeroizing::new(serde_json::to_vec(&inner).map_err(|_| CryptoError::Malformed)?);
    inner.plaintext.zeroize(); // wipe the lingering base64-plaintext String

    let aad = lock_aad(contact_id, &message_id, &lock_kdf, lock_salt);
    let body = aead::encrypt(&lock_key, &inner_bytes, &aad)?;

    let mut local_id = [0u8; LOCAL_ID_LEN];
    OsRng.fill_bytes(&mut local_id);

    Ok(LockedRecord {
        v: PIN_V,
        local_id: b64(&local_id),
        contact_id: contact_id.to_string(),
        message_id: b64(&message_id),
        lock_commit: b64(&commit),
        body,
        created_at,
    })
}

/// Open a locked record with the lock phrase + the contact's salt/params. A
/// wrong phrase fails closed (commitment mismatch, then AEAD tag) with an opaque
/// error — no partial plaintext, and no oracle cheaper than one Argon2id.
pub fn lock_open(
    record: &LockedRecord,
    lock_phrase: &[u8],
    lock_salt: &[u8; SALT_LEN],
    lock_kdf: KdfParams,
) -> Result<LockedOpened> {
    if record.v != PIN_V {
        return Err(CryptoError::Malformed);
    }
    lock_kdf.validate_for_unlock()?;
    let message_id = unb64_exact(&record.message_id, MSG_ID_LEN)?;

    let lock_key = derive_lock_key(lock_phrase, lock_salt, lock_kdf)?;

    // key-commitment check (constant time) before trusting the AEAD
    let expect = hkdf32(lock_key.as_bytes(), D_PIN_COMMIT);
    let got = unb64_exact(&record.lock_commit, COMMIT_LEN)?
        .try_into()
        .map_err(|_| CryptoError::Malformed)?;
    if ct_ne(&expect, &got) {
        return Err(CryptoError::Aead); // wrong phrase
    }

    let aad = lock_aad(&record.contact_id, &message_id, &lock_kdf, lock_salt);
    let inner_bytes = Zeroizing::new(aead::decrypt(&lock_key, &record.body, &aad)?);
    let mut inner: LockedInner =
        serde_json::from_slice(&inner_bytes).map_err(|_| CryptoError::Malformed)?;
    let plaintext = Zeroizing::new(unb64(&inner.plaintext)?);
    inner.plaintext.zeroize();

    let sender = match (inner.sender_state, inner.sender_id.take()) {
        (0, None) => Sender::Anonymous,
        (1, Some(id)) => Sender::Unverified(id),
        (2, Some(id)) => Sender::Verified(id),
        _ => return Err(CryptoError::Malformed), // tampered/unknown combo → fail closed
    };

    Ok(LockedOpened { plaintext, sender })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tiny KDF so the Argon2id in tests stays fast; the real default is 128 MiB.
    fn test_kdf() -> KdfParams {
        KdfParams {
            mem_kib: 8 * 1024,
            iterations: 1,
            parallelism: 1,
        }
    }
    const SALT: [u8; SALT_LEN] = [7u8; SALT_LEN];

    // Build a signed Send blob from a fresh sender to a fresh recipient.
    fn signed_blob(note: &[u8]) -> (SendBlob, IdentityKeys, IdentityKeys) {
        let recipient = IdentityKeys::generate(1);
        let sender = IdentityKeys::generate(1);
        let blob = send::seal(
            note,
            "RECIP-ID",
            &recipient.public(),
            None,
            Some((&sender, "SENDER-ID")),
        )
        .unwrap();
        (blob, recipient, sender)
    }

    #[test]
    fn round_trip_verified() {
        let (blob, recipient, sender) = signed_blob(b"meet at 9pm");
        let rec = lock_finalize(
            &blob,
            &recipient,
            None,
            Some(&sender.public()),
            "CONTACT-1",
            1234,
            b"correct horse",
            &SALT,
            test_kdf(),
        )
        .unwrap();
        assert_eq!(rec.message_id, blob.message_id); // bound, vault-encrypted (not server id)
        assert_ne!(rec.local_id, blob.message_id); // vault item id is random
        assert_eq!(rec.created_at, 1234);

        let out = lock_open(&rec, b"correct horse", &SALT, test_kdf()).unwrap();
        assert_eq!(&out.plaintext[..], b"meet at 9pm");
        assert_eq!(out.sender, Sender::Verified("SENDER-ID".into()));
    }

    #[test]
    fn anonymous_preserved() {
        let recipient = IdentityKeys::generate(1);
        let blob = send::seal(b"hi", "RECIP-ID", &recipient.public(), None, None).unwrap();
        let rec = lock_finalize(
            &blob,
            &recipient,
            None,
            None,
            "C",
            0,
            b"phrase one",
            &SALT,
            test_kdf(),
        )
        .unwrap();
        let out = lock_open(&rec, b"phrase one", &SALT, test_kdf()).unwrap();
        assert_eq!(out.sender, Sender::Anonymous);
        assert_eq!(&out.plaintext[..], b"hi");
    }

    #[test]
    fn wrong_phrase_fails_closed() {
        let (blob, recipient, _s) = signed_blob(b"secret");
        let rec = lock_finalize(
            &blob,
            &recipient,
            None,
            None,
            "C",
            0,
            b"right phrase",
            &SALT,
            test_kdf(),
        )
        .unwrap();
        assert!(lock_open(&rec, b"wrong phrase", &SALT, test_kdf()).is_err());
        // also a wrong salt (≠ contact salt) must fail
        assert!(lock_open(&rec, b"right phrase", &[9u8; SALT_LEN], test_kdf()).is_err());
    }

    #[test]
    fn commit_tamper_rejected() {
        let (blob, recipient, _s) = signed_blob(b"x");
        let mut rec = lock_finalize(
            &blob,
            &recipient,
            None,
            None,
            "C",
            0,
            b"phrase here",
            &SALT,
            test_kdf(),
        )
        .unwrap();
        // flip the commitment
        let mut c = unb64_exact(&rec.lock_commit, 32).unwrap();
        c[0] ^= 1;
        rec.lock_commit = b64(&c);
        assert!(lock_open(&rec, b"phrase here", &SALT, test_kdf()).is_err());
    }

    #[test]
    fn aad_swap_rejected() {
        let (blob, recipient, _s) = signed_blob(b"x");
        let rec = lock_finalize(
            &blob,
            &recipient,
            None,
            None,
            "CONTACT-A",
            0,
            b"phrase here",
            &SALT,
            test_kdf(),
        )
        .unwrap();
        // swap the contact_id → AAD mismatch → decrypt fails
        let mut swapped = rec.clone();
        swapped.contact_id = "CONTACT-B".into();
        assert!(lock_open(&swapped, b"phrase here", &SALT, test_kdf()).is_err());
        // tamper the bound message_id → AAD mismatch
        let mut swapped2 = rec.clone();
        swapped2.message_id = b64(&[0u8; MSG_ID_LEN]);
        assert!(lock_open(&swapped2, b"phrase here", &SALT, test_kdf()).is_err());
    }

    #[test]
    fn params_must_match() {
        let (blob, recipient, _s) = signed_blob(b"x");
        let rec = lock_finalize(
            &blob,
            &recipient,
            None,
            None,
            "C",
            0,
            b"phrase here",
            &SALT,
            test_kdf(),
        )
        .unwrap();
        // different KDF params are AAD-bound → opening with other params fails
        let other = KdfParams {
            mem_kib: 16 * 1024,
            iterations: 1,
            parallelism: 1,
        };
        assert!(lock_open(&rec, b"phrase here", &SALT, other).is_err());
    }

    #[test]
    fn domain_and_defaults() {
        assert!(D_PIN.starts_with(b"pm:v1:send/pin-lock"));
        assert_ne!(D_PIN, D_PIN_COMMIT);
        let k = default_lock_kdf();
        assert_eq!(k.parallelism, 1); // WASM single-threaded
        assert!(k.validate_for_unlock().is_ok());
    }
}
