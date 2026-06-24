//! # Bastion Send — end-to-end encrypted notes between users (P0 core)
//!
//! Implements the cryptographic construction in `docs/bastion-send-design.md`
//! (v0.2, audit-incorporated). This module is the *only* place the Send
//! envelope is built/opened; the server, WASM bindings and UI are separate
//! phases. No networking, no key storage here — pure crypto + tests.
//!
//! Construction (envelope encryption):
//! - A random **CEK** encrypts the note body (XChaCha20-Poly1305, via [`aead`]).
//! - The CEK is wrapped to the recipient with an **X25519 sealed box** (age's
//!   recipient stanza): `wrap_key = HKDF(ikm = shared ‖ pw_material,
//!   salt = eph_pub ‖ recipient_enc_pub, info = "pm:v1:send/recipient")`.
//!   `recipient_enc_pub` in the salt binds the blob to one recipient key (a
//!   malicious server can't re-point it).
//! - The **optional passphrase is folded into the wrap KDF** (`pw_material`),
//!   not a separate outer layer: guessing it requires `shared`, i.e. the
//!   recipient's private key, so the server has *no* offline oracle.
//! - A **key-commitment** (`cek_commit`) closes the partitioning-oracle class.
//! - Optional **sign-then-encrypt**: the sender id + Ed25519 signature live
//!   *inside* the encrypted body, so the server never learns the sender.
//!
//! Mandatory validations (see the dalek call sites): reject a non-contributory
//! X25519 shared secret, `verify_strict` for Ed25519, and ceiling-validate any
//! attacker-supplied Argon2 params before deriving from them.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use x25519_dalek::{EphemeralSecret, PublicKey as XPublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::aead::{self, EncryptedBlob};
use crate::error::{CryptoError, Result};
use crate::kdf::{self, KdfParams, SALT_LEN};
use crate::secret::{SecretKey, KEY_LEN};

// ── domain labels (disjoint from the pm:v1 vault family) ──
const D_RECIP: &[u8] = b"pm:v1:send/recipient";
const D_WRAP: &[u8] = b"pm:v1:send/wrap";
const D_BODY: &[u8] = b"pm:v1:send/body";
const D_SIG: &[u8] = b"pm:v1:send/sig";
const D_COMMIT: &[u8] = b"pm:v1:send/commit";
const D_FP: &[u8] = b"pm:v1:send/fp/v1";

const SEND_V: u8 = 1;
const SEND_TYPE: &[u8] = b"send";
const MSG_ID_LEN: usize = 16;
const SAFETY_ITERS: usize = 5200; // Signal-style: taxes short-compare grinding
/// Size buckets for body padding (hide content length / signed-vs-anon).
const BUCKETS: [usize; 6] = [256, 1024, 4096, 16384, 65536, 262144];
/// A "note" is capped well below the AEAD's ~8 MiB ceiling.
const MAX_PLAINTEXT: usize = 1024 * 1024;

fn b64(bytes: &[u8]) -> String {
    use base64::{engine::general_purpose::STANDARD as B, Engine};
    B.encode(bytes)
}
/// Decode base64 with NO size bound — only for already-authenticated data
/// (e.g. the note plaintext inside the AEAD'd body).
fn unb64(s: &str) -> Result<Vec<u8>> {
    use base64::{engine::general_purpose::STANDARD as B, Engine};
    B.decode(s).map_err(|_| CryptoError::Malformed)
}
/// Decode an attacker-supplied base64 field, rejecting oversized input *before*
/// allocating (anti-DoS; mirrors aead.rs's MAX_ENCODED_* caps). `max` is the
/// max decoded byte length.
fn unb64_cap(s: &str, max: usize) -> Result<Vec<u8>> {
    use base64::{engine::general_purpose::STANDARD as B, Engine};
    if s.len() > max.saturating_mul(4).saturating_div(3).saturating_add(8) {
        return Err(CryptoError::Malformed);
    }
    let v = B.decode(s).map_err(|_| CryptoError::Malformed)?;
    if v.len() > max {
        return Err(CryptoError::Malformed);
    }
    Ok(v)
}
/// Decode a field that must be exactly `n` bytes (e.g. keys, nonces, ids).
fn unb64_exact(s: &str, n: usize) -> Result<Vec<u8>> {
    let v = unb64_cap(s, n)?;
    if v.len() != n {
        return Err(CryptoError::Malformed);
    }
    Ok(v)
}
fn unb64_32(s: &str) -> Result<[u8; 32]> {
    unb64_exact(s, 32)?
        .try_into()
        .map_err(|_| CryptoError::Malformed)
}

fn hkdf32(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut out = [0u8; 32];
    hk.expand(info, &mut out)
        .expect("32 within HKDF output limit");
    out
}

/// Length-prefixed framing so concatenated fields are unambiguous.
fn put(buf: &mut Vec<u8>, field: &[u8]) {
    buf.extend_from_slice(&(field.len() as u32).to_be_bytes());
    buf.extend_from_slice(field);
}

/// Canonical encoding of the passphrase mode + KDF params, bound into the AAD
/// so a server can't strip/alter the passphrase factor (it's also implicitly
/// bound via the wrap KDF, but the spec mandates explicit header binding).
fn pw_aad(pw: Option<&PwParams>) -> Vec<u8> {
    let mut b = Vec::new();
    match pw {
        None => b.push(0),
        Some(p) => {
            b.push(1);
            put(&mut b, p.salt.as_bytes());
            b.extend_from_slice(&p.mem_kib.to_be_bytes());
            b.extend_from_slice(&p.iterations.to_be_bytes());
            b.extend_from_slice(&p.parallelism.to_be_bytes());
        }
    }
    b
}

/// Canonical protected header bound into every AEAD AAD (domain-separated).
/// Note: the AEAD nonce is authenticated by the AEAD itself, and the padding
/// length lives inside the authenticated body, so neither needs separate AAD
/// binding here.
#[allow(clippy::too_many_arguments)]
fn header_aad(
    domain: &[u8],
    message_id: &[u8],
    recipient_id: &str,
    recipient_enc_pub: &[u8; 32],
    key_version: u32,
    eph_pub: &[u8; 32],
    pw: &[u8],
) -> Vec<u8> {
    let mut b = Vec::new();
    put(&mut b, domain);
    b.push(SEND_V);
    put(&mut b, SEND_TYPE);
    put(&mut b, message_id);
    put(&mut b, recipient_id.as_bytes());
    put(&mut b, recipient_enc_pub);
    b.extend_from_slice(&key_version.to_be_bytes());
    put(&mut b, eph_pub);
    put(&mut b, pw);
    b
}

// ── identity ──

/// A user's long-lived Send identity: an X25519 key (encryption) + an Ed25519
/// key (signatures), kept independent. Stored (later) inside the vault.
pub struct IdentityKeys {
    x_priv: StaticSecret,
    sig: SigningKey,
    key_version: u32,
}

/// The published, non-secret half of an identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicIdentity {
    pub enc_pub: [u8; 32],
    pub sig_pub: [u8; 32],
    pub key_version: u32,
}

impl IdentityKeys {
    /// Generate a fresh identity (system CSPRNG).
    pub fn generate(key_version: u32) -> Self {
        Self {
            x_priv: StaticSecret::random_from_rng(OsRng),
            sig: SigningKey::generate(&mut OsRng),
            key_version,
        }
    }

    pub fn public(&self) -> PublicIdentity {
        PublicIdentity {
            enc_pub: XPublicKey::from(&self.x_priv).to_bytes(),
            sig_pub: self.sig.verifying_key().to_bytes(),
            key_version: self.key_version,
        }
    }

    pub fn key_version(&self) -> u32 {
        self.key_version
    }

    /// Serialize for storage in the vault: `x_priv(32) ‖ ed_seed(32) ‖ ver(4)`.
    /// The returned buffer is wiped on drop.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Vec::with_capacity(68);
        out.extend_from_slice(&self.x_priv.to_bytes());
        out.extend_from_slice(&self.sig.to_bytes());
        out.extend_from_slice(&self.key_version.to_be_bytes());
        Zeroizing::new(out)
    }

    /// Rebuild from [`IdentityKeys::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 68 {
            return Err(CryptoError::Malformed);
        }
        let x: [u8; 32] = bytes[0..32].try_into().unwrap();
        let s: [u8; 32] = bytes[32..64].try_into().unwrap();
        let ver = u32::from_be_bytes(bytes[64..68].try_into().unwrap());
        Ok(Self {
            x_priv: StaticSecret::from(x),
            sig: SigningKey::from_bytes(&s),
            key_version: ver,
        })
    }
}

// ── blob format ──

/// The opaque, serializable Send envelope (what the server stores).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SendBlob {
    pub v: u8,
    #[serde(rename = "type")]
    pub typ: String,
    pub message_id: String, // base64, 16 bytes
    pub recipient_id: String,
    pub recipient_enc_pub: String, // base64, 32 bytes
    pub recipient_key_version: u32,
    pub eph_pub: String,            // base64, 32 bytes
    pub wrapped_cek: EncryptedBlob, // CEK under wrap_key (AAD = header/wrap)
    pub cek_commit: String,         // base64, 32 bytes — key-commitment
    pub body: EncryptedBlob,        // padded inner payload under CEK (AAD = header/body)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pw: Option<PwParams>, // present iff a passphrase was used
}

/// Argon2id parameters + salt for the optional passphrase factor.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PwParams {
    pub salt: String, // base64, 16 bytes
    pub mem_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

/// Inner payload, encrypted under the CEK (sender identity hidden from server).
#[derive(Serialize, Deserialize)]
struct Inner {
    plaintext: String, // base64
    #[serde(skip_serializing_if = "Option::is_none")]
    sender_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sig: Option<String>, // base64 Ed25519 signature
}

/// Who sent the message. The type makes it impossible to read a sender name
/// without also seeing its trust state — a consumer (P1 WASM/UI) cannot render
/// an attacker-chosen, unverified `sender_id` as if it were authentic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Sender {
    /// No sender identity was claimed (anonymous sealed box).
    Anonymous,
    /// A sender id was claimed but NOT cryptographically verified (either no
    /// verification key was supplied, or the contact isn't trusted yet).
    Unverified(String),
    /// Signature verified (`verify_strict`) against the supplied sender identity.
    Verified(String),
}

/// Result of opening a Send blob.
pub struct OpenedMessage {
    pub plaintext: Zeroizing<Vec<u8>>,
    pub sender: Sender,
}

// ── padding ──

fn pad(inner: &[u8]) -> Zeroizing<Vec<u8>> {
    let need = inner.len() + 4;
    let target = BUCKETS
        .iter()
        .copied()
        .find(|&b| b >= need)
        .unwrap_or_else(|| need.div_ceil(BUCKETS[BUCKETS.len() - 1]) * BUCKETS[BUCKETS.len() - 1]);
    let mut out = Zeroizing::new(Vec::with_capacity(target));
    out.extend_from_slice(&(inner.len() as u32).to_be_bytes());
    out.extend_from_slice(inner);
    out.resize(target, 0);
    out
}

fn unpad(p: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if p.len() < 4 {
        return Err(CryptoError::Malformed);
    }
    let len = u32::from_be_bytes(p[0..4].try_into().unwrap()) as usize;
    if 4usize.checked_add(len).map(|n| n > p.len()).unwrap_or(true) {
        return Err(CryptoError::Malformed);
    }
    Ok(Zeroizing::new(p[4..4 + len].to_vec()))
}

// ── signature transcript ──

fn transcript(
    message_id: &[u8],
    recipient_id: &str,
    recipient_enc_pub: &[u8; 32],
    eph_pub: &[u8; 32],
    sender_id: &str,
    sender_sig_pub: &[u8; 32],
    plaintext: &[u8],
) -> Vec<u8> {
    let mut t = Vec::new();
    put(&mut t, D_SIG);
    t.push(SEND_V);
    put(&mut t, message_id);
    put(&mut t, recipient_id.as_bytes());
    put(&mut t, recipient_enc_pub);
    put(&mut t, eph_pub);
    put(&mut t, sender_id.as_bytes());
    put(&mut t, sender_sig_pub);
    put(&mut t, plaintext);
    t
}

// ── seal / open ──

/// Encrypt a note to `recipient`, optionally adding a passphrase factor and/or
/// signing it as `signer` (sender keys + sender id).
pub fn seal(
    plaintext: &[u8],
    recipient_id: &str,
    recipient: &PublicIdentity,
    passphrase: Option<&[u8]>,
    signer: Option<(&IdentityKeys, &str)>,
) -> Result<SendBlob> {
    if plaintext.len() > MAX_PLAINTEXT {
        return Err(CryptoError::Malformed);
    }

    let mut message_id = [0u8; MSG_ID_LEN];
    OsRng.fill_bytes(&mut message_id);

    let cek = SecretKey::generate();
    let eph_secret = EphemeralSecret::random_from_rng(OsRng);
    let eph_pub = XPublicKey::from(&eph_secret).to_bytes();

    // Decide passphrase params up front so they can be bound into BOTH AADs.
    let pw_params = passphrase.map(|_| {
        let salt = kdf::generate_salt();
        let params = KdfParams::default();
        PwParams {
            salt: b64(&salt),
            mem_kib: params.mem_kib,
            iterations: params.iterations,
            parallelism: params.parallelism,
        }
    });
    let pw_bytes = pw_aad(pw_params.as_ref());

    // ── inner payload (sender id + signature live inside the ciphertext) ──
    let mut inner = Inner {
        plaintext: b64(plaintext),
        sender_id: None,
        sig: None,
    };
    if let Some((keys, sender_id)) = signer {
        let pubid = keys.public();
        let t = transcript(
            &message_id,
            recipient_id,
            &recipient.enc_pub,
            &eph_pub,
            sender_id,
            &pubid.sig_pub,
            plaintext,
        );
        let sig: Signature = keys.sig.sign(&t);
        inner.sender_id = Some(sender_id.to_string());
        inner.sig = Some(b64(&sig.to_bytes()));
    }
    let inner_bytes =
        Zeroizing::new(serde_json::to_vec(&inner).map_err(|_| CryptoError::Malformed)?);
    let body_aad = header_aad(
        D_BODY,
        &message_id,
        recipient_id,
        &recipient.enc_pub,
        recipient.key_version,
        &eph_pub,
        &pw_bytes,
    );
    let body = aead::encrypt(&cek, &pad(&inner_bytes), &body_aad)?;

    // ── wrap CEK to recipient, passphrase folded into the KDF ──
    let shared = eph_secret.diffie_hellman(&XPublicKey::from(recipient.enc_pub));
    if !shared.was_contributory() {
        return Err(CryptoError::Malformed); // low-order recipient key → server-known zero shared
    }

    let mut ikm = Zeroizing::new(Vec::with_capacity(64));
    ikm.extend_from_slice(shared.as_bytes());
    if let (Some(pw), Some(p)) = (passphrase, pw_params.as_ref()) {
        let salt: [u8; SALT_LEN] = unb64_exact(&p.salt, SALT_LEN)?
            .try_into()
            .map_err(|_| CryptoError::Malformed)?;
        let pw_key = kdf::derive_master_key(pw, &salt, KdfParams::default())?;
        ikm.extend_from_slice(pw_key.as_bytes());
    }

    let mut salt = Vec::with_capacity(64);
    salt.extend_from_slice(&eph_pub);
    salt.extend_from_slice(&recipient.enc_pub);
    let mut wk = hkdf32(&ikm, &salt, D_RECIP);
    let wrap_key = SecretKey::from_bytes(wk);
    wk.zeroize();
    let cek_commit = hkdf32(wrap_key.as_bytes(), &[], D_COMMIT);

    let wrap_aad = header_aad(
        D_WRAP,
        &message_id,
        recipient_id,
        &recipient.enc_pub,
        recipient.key_version,
        &eph_pub,
        &pw_bytes,
    );
    let wrapped_cek = aead::encrypt(&wrap_key, cek.as_bytes(), &wrap_aad)?;

    Ok(SendBlob {
        v: SEND_V,
        typ: String::from_utf8_lossy(SEND_TYPE).into_owned(),
        message_id: b64(&message_id),
        recipient_id: recipient_id.to_string(),
        recipient_enc_pub: b64(&recipient.enc_pub),
        recipient_key_version: recipient.key_version,
        eph_pub: b64(&eph_pub),
        wrapped_cek,
        cek_commit: b64(&cek_commit),
        body,
        pw: pw_params,
    })
}

/// Open a Send blob with the recipient's identity (must match the blob's
/// `recipient_key_version`). If `verify_sender` is given and the blob is signed,
/// the signature is checked with `verify_strict`; `verified` reflects the result.
pub fn open(
    blob: &SendBlob,
    recipient_keys: &IdentityKeys,
    passphrase: Option<&[u8]>,
    verify_sender: Option<&PublicIdentity>,
) -> Result<OpenedMessage> {
    if blob.v != SEND_V || blob.typ.as_bytes() != SEND_TYPE {
        return Err(CryptoError::Malformed);
    }
    if blob.recipient_key_version != recipient_keys.key_version {
        return Err(CryptoError::Malformed);
    }
    let message_id = unb64_exact(&blob.message_id, MSG_ID_LEN)?;
    let recipient_enc_pub = unb64_32(&blob.recipient_enc_pub)?;
    let eph_pub = unb64_32(&blob.eph_pub)?;
    let my_enc_pub = recipient_keys.public().enc_pub;
    if recipient_enc_pub != my_enc_pub {
        return Err(CryptoError::Malformed);
    }

    // ── recover CEK ──
    let shared = recipient_keys
        .x_priv
        .diffie_hellman(&XPublicKey::from(eph_pub));
    if !shared.was_contributory() {
        return Err(CryptoError::Malformed); // low-order ephemeral
    }
    let mut ikm = Zeroizing::new(Vec::with_capacity(64));
    ikm.extend_from_slice(shared.as_bytes());
    if let Some(pw) = passphrase {
        let p = blob.pw.as_ref().ok_or(CryptoError::Malformed)?;
        let params = KdfParams {
            mem_kib: p.mem_kib,
            iterations: p.iterations,
            parallelism: p.parallelism,
        };
        params.validate_for_unlock()?; // ceiling check on attacker-supplied params (anti-DoS)
        let salt: [u8; SALT_LEN] = unb64_exact(&p.salt, SALT_LEN)?
            .try_into()
            .map_err(|_| CryptoError::Malformed)?;
        let pw_key = kdf::derive_master_key(pw, &salt, params)?;
        ikm.extend_from_slice(pw_key.as_bytes());
    } else if blob.pw.is_some() {
        return Err(CryptoError::Malformed); // blob needs a passphrase but none given
    }

    let mut salt = Vec::with_capacity(64);
    salt.extend_from_slice(&eph_pub);
    salt.extend_from_slice(&recipient_enc_pub);
    let mut wk = hkdf32(&ikm, &salt, D_RECIP);
    let wrap_key = SecretKey::from_bytes(wk);
    wk.zeroize();

    // key-commitment check before trusting the wrap
    let expect_commit = hkdf32(wrap_key.as_bytes(), &[], D_COMMIT);
    let got_commit = unb64_32(&blob.cek_commit)?;
    if expect_commit.ct_ne(&got_commit) {
        return Err(CryptoError::Aead);
    }

    let pw_bytes = pw_aad(blob.pw.as_ref());
    let wrap_aad = header_aad(
        D_WRAP,
        &message_id,
        &blob.recipient_id,
        &recipient_enc_pub,
        blob.recipient_key_version,
        &eph_pub,
        &pw_bytes,
    );
    let cek_bytes = Zeroizing::new(aead::decrypt(&wrap_key, &blob.wrapped_cek, &wrap_aad)?);
    let cek = SecretKey::from_bytes(
        (&cek_bytes[..])
            .try_into()
            .map_err(|_| CryptoError::Malformed)?,
    );

    // ── decrypt body ──
    let body_aad = header_aad(
        D_BODY,
        &message_id,
        &blob.recipient_id,
        &recipient_enc_pub,
        blob.recipient_key_version,
        &eph_pub,
        &pw_bytes,
    );
    let padded = Zeroizing::new(aead::decrypt(&cek, &blob.body, &body_aad)?);
    let inner_bytes = unpad(&padded)?;
    let inner: Inner = serde_json::from_slice(&inner_bytes).map_err(|_| CryptoError::Malformed)?;
    let plaintext = Zeroizing::new(unb64(&inner.plaintext)?);

    // ── determine sender trust state ──
    let sender = match (&inner.sender_id, &inner.sig) {
        (Some(sid), Some(sig_b64)) => match verify_sender {
            Some(s) => {
                let sig_bytes: [u8; 64] = unb64_exact(sig_b64, 64)?
                    .try_into()
                    .map_err(|_| CryptoError::Malformed)?;
                let sig = Signature::from_bytes(&sig_bytes);
                let vk =
                    VerifyingKey::from_bytes(&s.sig_pub).map_err(|_| CryptoError::Malformed)?;
                let t = transcript(
                    &message_id,
                    &blob.recipient_id,
                    &recipient_enc_pub,
                    &eph_pub,
                    sid,
                    &s.sig_pub,
                    &plaintext,
                );
                if vk.verify_strict(&t, &sig).is_err() {
                    return Err(CryptoError::Aead); // signed but verification failed → reject
                }
                Sender::Verified(sid.clone())
            }
            // A signature is present but the caller gave no key to check it.
            None => Sender::Unverified(sid.clone()),
        },
        // A claimed sender id with no signature is never trustworthy.
        (Some(sid), None) => Sender::Unverified(sid.clone()),
        _ => Sender::Anonymous,
    };

    Ok(OpenedMessage { plaintext, sender })
}

/// Signal-style safety number binding both users' ids + enc + sig keys +
/// versions; compare it out-of-band to defeat a key-substituting server.
/// Returns 60 decimal digits (two 30-digit fingerprints, sorted).
pub fn safety_number(id_a: &str, a: &PublicIdentity, id_b: &str, b: &PublicIdentity) -> String {
    let fa = fingerprint(id_a, a);
    let fb = fingerprint(id_b, b);
    let (lo, hi) = if fa <= fb { (fa, fb) } else { (fb, fa) };
    format!("{lo}{hi}")
}

fn fingerprint(bastion_id: &str, id: &PublicIdentity) -> String {
    let mut input = Vec::new();
    put(&mut input, D_FP);
    put(&mut input, bastion_id.as_bytes());
    put(&mut input, &id.enc_pub);
    put(&mut input, &id.sig_pub);
    input.extend_from_slice(&id.key_version.to_be_bytes());

    let mut h = Sha512::digest(&input);
    for _ in 0..SAFETY_ITERS {
        let mut hasher = Sha512::new();
        hasher.update(h);
        hasher.update(&input); // keep the material mixed in each round
        h = hasher.finalize();
    }
    // 6 groups of 5 digits = 30 digits (Signal-style, from 5-byte windows).
    let mut digits = String::with_capacity(30);
    for i in 0..6 {
        let w = &h[i * 5..i * 5 + 5];
        let mut acc: u64 = 0;
        for &byte in w {
            acc = (acc << 8) | byte as u64;
        }
        digits.push_str(&format!("{:05}", acc % 100_000));
    }
    digits
}

// constant-time inequality for the commitment (avoid a timing side-channel)
trait CtNe {
    fn ct_ne(&self, other: &Self) -> bool;
}
impl CtNe for [u8; 32] {
    fn ct_ne(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.ct_eq(other).unwrap_u8() == 0
    }
}

// CEK / wrap_key are 32 bytes by construction.
const _: () = assert!(KEY_LEN == 32);
