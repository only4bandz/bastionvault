//! Integration tests for Bastion Send (X25519 sealed box + folded passphrase
//! + CEK commitment + Ed25519 sign-then-encrypt + safety number).

use crypto_core::send::{open, safety_number, seal, IdentityKeys, PublicIdentity, Sender};
use crypto_core::CryptoError;

fn alice() -> IdentityKeys {
    IdentityKeys::generate(1)
}
fn bob() -> IdentityKeys {
    IdentityKeys::generate(1)
}

#[test]
fn anonymous_roundtrip() {
    let b = bob();
    let blob = seal(b"hello bob", "BOB-ID", &b.public(), None, None).unwrap();
    let opened = open(&blob, &b, None, None).unwrap();
    assert_eq!(opened.plaintext.as_slice(), b"hello bob");
    assert_eq!(opened.sender, Sender::Anonymous);
}

#[test]
fn wrong_recipient_cannot_open() {
    let b = bob();
    let mallory = IdentityKeys::generate(1);
    let blob = seal(b"secret", "BOB-ID", &b.public(), None, None).unwrap();
    // Mallory has a different key → recipient_enc_pub mismatch / AEAD fail.
    assert!(open(&blob, &mallory, None, None).is_err());
}

#[test]
fn redirection_is_blocked() {
    // A blob sealed to Bob, then the server rewrites recipient_id/enc_pub to
    // Mallory's: must not open for Mallory (CEK is bound to Bob's key via salt).
    let b = bob();
    let m = IdentityKeys::generate(1);
    let mut blob = seal(b"for bob only", "BOB-ID", &b.public(), None, None).unwrap();
    blob.recipient_id = "MALLORY-ID".into();
    blob.recipient_enc_pub = {
        use base64::{engine::general_purpose::STANDARD as B, Engine};
        B.encode(m.public().enc_pub)
    };
    assert!(open(&blob, &m, None, None).is_err());
}

#[test]
fn passphrase_is_required_when_set() {
    let b = bob();
    let blob = seal(
        b"top secret",
        "BOB-ID",
        &b.public(),
        Some(b"correct horse"),
        None,
    )
    .unwrap();
    assert!(blob.pw.is_some());
    // Right key + right passphrase: opens.
    let ok = open(&blob, &b, Some(b"correct horse"), None).unwrap();
    assert_eq!(ok.plaintext.as_slice(), b"top secret");
    // Right key, WRONG passphrase: fails (the second factor is real).
    assert!(open(&blob, &b, Some(b"wrong"), None).is_err());
    // Right key, NO passphrase though one is required: fails.
    assert!(open(&blob, &b, None, None).is_err());
}

#[test]
fn signed_message_verifies_and_detects_tampering() {
    let a = alice();
    let b = bob();
    let blob = seal(
        b"signed note",
        "BOB-ID",
        &b.public(),
        None,
        Some((&a, "ALICE-ID")),
    )
    .unwrap();

    // Verified against Alice's real public identity.
    let opened = open(&blob, &b, None, Some(&a.public())).unwrap();
    assert_eq!(opened.sender, Sender::Verified("ALICE-ID".into()));
    assert_eq!(opened.plaintext.as_slice(), b"signed note");

    // Verified against a DIFFERENT identity (impersonation): must reject.
    let imposter = IdentityKeys::generate(1);
    assert!(matches!(
        open(&blob, &b, None, Some(&imposter.public())),
        Err(CryptoError::Aead)
    ));

    // No sender key supplied: opens but the sender is only Unverified, never
    // Verified — the type makes the trust state impossible to ignore.
    let unchecked = open(&blob, &b, None, None).unwrap();
    assert_eq!(unchecked.sender, Sender::Unverified("ALICE-ID".into()));
}

#[test]
fn tampered_commitment_or_body_is_rejected() {
    let b = bob();
    let mut blob = seal(b"data", "BOB-ID", &b.public(), None, None).unwrap();
    let mut bad = blob.clone();
    // Flip the key-commitment.
    bad.cek_commit = {
        use base64::{engine::general_purpose::STANDARD as B, Engine};
        B.encode([0u8; 32])
    };
    assert!(open(&bad, &b, None, None).is_err());
    // Flip a byte of the body ciphertext.
    let mut raw = {
        use base64::{engine::general_purpose::STANDARD as B, Engine};
        B.decode(&blob.body.ct).unwrap()
    };
    raw[0] ^= 1;
    blob.body.ct = {
        use base64::{engine::general_purpose::STANDARD as B, Engine};
        B.encode(&raw)
    };
    assert!(open(&blob, &b, None, None).is_err());
}

#[test]
fn low_order_recipient_key_is_rejected() {
    // All-zero X25519 public key is low-order → non-contributory shared secret.
    let zero = PublicIdentity {
        enc_pub: [0u8; 32],
        sig_pub: [0u8; 32],
        key_version: 1,
    };
    assert!(seal(b"x", "ID", &zero, None, None).is_err());
}

#[test]
fn key_version_mismatch_is_rejected() {
    let b = bob(); // version 1
    let blob = seal(b"x", "BOB-ID", &b.public(), None, None).unwrap();
    let b_v2 = IdentityKeys::from_bytes(&{
        let mut bytes = b.to_bytes().to_vec();
        // bump the stored key_version to 2
        bytes[64..68].copy_from_slice(&2u32.to_be_bytes());
        bytes
    })
    .unwrap();
    assert!(open(&blob, &b_v2, None, None).is_err());
}

#[test]
fn safety_number_is_symmetric_and_binds_sig_key() {
    let a = alice();
    let b = bob();
    let sn_ab = safety_number("ALICE", &a.public(), "BOB", &b.public());
    let sn_ba = safety_number("BOB", &b.public(), "ALICE", &a.public());
    assert_eq!(sn_ab, sn_ba, "safety number must be order-independent");
    assert_eq!(sn_ab.len(), 60);
    assert!(sn_ab.chars().all(|c| c.is_ascii_digit()));

    // Swapping only the signing key must change the safety number (v0.1 bug:
    // hashing only enc_pub let a server swap sig_pub undetected).
    let mut tampered = a.public();
    tampered.sig_pub = IdentityKeys::generate(1).public().sig_pub;
    let sn_tampered = safety_number("ALICE", &tampered, "BOB", &b.public());
    assert_ne!(sn_ab, sn_tampered);
}

#[test]
fn tampered_pw_params_are_rejected() {
    // pw params are bound in the AAD: a server that mutates them must break open
    // even with the correct passphrase.
    let b = bob();
    let mut blob = seal(b"x", "BOB-ID", &b.public(), Some(b"pw123456"), None).unwrap();
    let pw = blob.pw.as_mut().unwrap();
    pw.iterations += 1; // tamper a param
    assert!(open(&blob, &b, Some(b"pw123456"), None).is_err());
}

#[test]
fn oversized_base64_field_is_rejected_cleanly() {
    // A malicious blob with a huge encoded field must error, not OOM/panic.
    let b = bob();
    let mut blob = seal(b"x", "BOB-ID", &b.public(), None, None).unwrap();
    blob.cek_commit = "A".repeat(10_000_000); // ~10 MB of base64 for a 32-byte field
    assert!(matches!(
        open(&blob, &b, None, None),
        Err(CryptoError::Malformed)
    ));
}

#[test]
fn identity_serialization_roundtrips() {
    let a = alice();
    let restored = IdentityKeys::from_bytes(&a.to_bytes()).unwrap();
    assert_eq!(a.public(), restored.public());
    // And a message sealed to it still opens after a serialize/restore cycle.
    let blob = seal(b"persisted", "A", &a.public(), None, None).unwrap();
    assert_eq!(
        open(&blob, &restored, None, None)
            .unwrap()
            .plaintext
            .as_slice(),
        b"persisted"
    );
}
