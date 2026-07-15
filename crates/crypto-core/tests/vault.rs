//! Integration tests for the full zero-knowledge encryption flow.

use crypto_core::aead::EncryptedBlob;
use crypto_core::kdf::KdfParams;
use crypto_core::vault::{auth_secret_eq, Vault};
use crypto_core::{AccountSecret, CryptoError};

/// KDF parameters for the tests: exactly the policy floor (the minimum
/// acceptable security level), to stay fast while still passing the
/// `validate_for_new_vault` validation.
fn fast_kdf() -> KdfParams {
    KdfParams {
        mem_kib: KdfParams::MIN_MEM_KIB,
        iterations: KdfParams::MIN_ITERATIONS,
        parallelism: KdfParams::MIN_PARALLELISM,
    }
}

#[test]
fn register_then_unlock_roundtrip() {
    let pw = b"correct horse battery staple";
    let (vault, reg, sk) = Vault::register_with(pw, fast_kdf()).unwrap();

    let blob = vault.encrypt_item(b"hunter2", "login-1").unwrap();

    // Unlock with password + Secret Key + "server" data.
    let (vault2, _auth) =
        Vault::unlock(pw, &sk, &reg.salt, reg.kdf, &reg.wrapped_vault_key).unwrap();
    let plain = vault2.decrypt_item(&blob, "login-1").unwrap();
    assert_eq!(plain.as_slice(), b"hunter2");
}

#[test]
fn export_key_then_from_key_roundtrip() {
    // Session rehydration: a vault rebuilt from an exported key decrypts items
    // sealed by the original, and seals items the original can read back.
    let (vault, _reg, _sk) =
        Vault::register_with(b"correct horse battery staple", fast_kdf()).unwrap();
    let blob = vault.encrypt_item(b"hunter2", "login-1").unwrap();

    let key = vault.export_key();
    let rebuilt = Vault::from_key(&key).unwrap();
    assert_eq!(
        rebuilt.decrypt_item(&blob, "login-1").unwrap().as_slice(),
        b"hunter2"
    );

    let blob2 = rebuilt.encrypt_item(b"second", "login-2").unwrap();
    assert_eq!(
        vault.decrypt_item(&blob2, "login-2").unwrap().as_slice(),
        b"second"
    );
}

#[test]
fn from_key_rejects_wrong_length() {
    assert!(matches!(
        Vault::from_key(&[0u8; 16]),
        Err(CryptoError::Malformed)
    ));
}

#[test]
fn wrong_password_cannot_unlock() {
    let (_, reg, sk) = Vault::register_with(b"the right one", fast_kdf()).unwrap();
    let result = Vault::unlock(
        b"the WRONG one",
        &sk,
        &reg.salt,
        reg.kdf,
        &reg.wrapped_vault_key,
    );
    assert!(result.is_err(), "a wrong password must not unlock");
}

#[test]
fn wrong_account_secret_cannot_unlock() {
    let pw = b"correct horse battery staple";
    let (_, reg, _sk) = Vault::register_with(pw, fast_kdf()).unwrap();
    // Correct password but WRONG Secret Key -> unwrapping is impossible.
    let other = AccountSecret::generate();
    assert!(matches!(
        Vault::unlock(pw, &other, &reg.salt, reg.kdf, &reg.wrapped_vault_key),
        Err(CryptoError::Aead)
    ));
}

#[test]
fn item_id_is_authenticated_aad() {
    let (vault, _, _) = Vault::register_with(b"pw", fast_kdf()).unwrap();
    let blob = vault.encrypt_item(b"secret", "item-A").unwrap();
    // Decrypting under a different id must fail (the blob is bound to its item).
    assert!(vault.decrypt_item(&blob, "item-B").is_err());
    assert!(vault.decrypt_item(&blob, "item-A").is_ok());
}

#[test]
fn tampered_ciphertext_is_rejected() {
    let (vault, _, _) = Vault::register_with(b"pw", fast_kdf()).unwrap();
    let mut blob = vault.encrypt_item(b"secret", "x").unwrap();
    // We tamper with one byte of the ciphertext -> the Poly1305 tag must cause a failure.
    let mut raw = base64_decode(&blob.ct);
    raw[0] ^= 0x01;
    blob.ct = base64_encode(&raw);
    assert!(vault.decrypt_item(&blob, "x").is_err());
}

#[test]
fn tampered_wrapped_vault_key_is_rejected() {
    let pw = b"master pw";
    let (_, mut reg, sk) = Vault::register_with(pw, fast_kdf()).unwrap();
    // We tamper with one byte of the wrapped vault key supplied by the server.
    // The AEAD tag must cause the unwrapping to fail -- no silent unlock on a
    // key that has been corrupted or substituted by a malicious server.
    let mut raw = base64_decode(&reg.wrapped_vault_key.ct);
    raw[0] ^= 0x01;
    reg.wrapped_vault_key.ct = base64_encode(&raw);
    assert!(matches!(
        Vault::unlock(pw, &sk, &reg.salt, reg.kdf, &reg.wrapped_vault_key),
        Err(CryptoError::Aead)
    ));
}

#[test]
fn auth_secret_is_stable_and_secret() {
    let pw = b"my master password";
    let (_, reg1, sk) = Vault::register_with(pw, fast_kdf()).unwrap();
    // Re-unlocking yields the SAME auth secret (deterministic from salt/pw/sk).
    let (_, auth_a) =
        Vault::unlock(pw, &sk, &reg1.salt, reg1.kdf, &reg1.wrapped_vault_key).unwrap();
    let (_, auth_b) =
        Vault::unlock(pw, &sk, &reg1.salt, reg1.kdf, &reg1.wrapped_vault_key).unwrap();
    // Constant-time comparisons (the newtype does not expose PartialEq).
    assert!(auth_a.ct_eq(&auth_b));
    // And it must equal the secret recorded at signup.
    assert!(auth_a.ct_eq(&reg1.auth_secret));
    assert!(auth_secret_eq(
        auth_a.as_bytes(),
        reg1.auth_secret.as_bytes()
    ));
}

#[test]
fn auth_secret_debug_is_redacted() {
    let (_, reg, _sk) = Vault::register_with(b"pw", fast_kdf()).unwrap();
    let secret = reg.auth_secret.expose_b64().to_string();
    // The secret's Debug output must not reveal its value.
    let dbg = format!("{:?}", reg.auth_secret);
    assert!(dbg.contains("redacted"));
    assert!(!dbg.contains(&secret));
    // Registration's Debug output must not leak the secret either.
    assert!(!format!("{:?}", reg).contains(&secret));
}

#[test]
fn unknown_blob_version_is_rejected() {
    let (vault, _, _) = Vault::register_with(b"pw", fast_kdf()).unwrap();
    let mut blob = vault.encrypt_item(b"x", "i").unwrap();
    blob.v = 2; // unknown version
    assert!(matches!(
        vault.decrypt_item(&blob, "i"),
        Err(CryptoError::Malformed)
    ));
}

#[test]
fn oversized_ciphertext_is_rejected_before_decode() {
    let (vault, _, _) = Vault::register_with(b"pw", fast_kdf()).unwrap();
    let mut blob = vault.encrypt_item(b"x", "i").unwrap();
    // ~12 MiB encoded > 8 MiB cap -> rejected without allocating for decryption.
    blob.ct = base64_encode(&vec![0u8; 9 * 1024 * 1024]);
    assert!(matches!(
        vault.decrypt_item(&blob, "i"),
        Err(CryptoError::Malformed)
    ));
}

#[test]
fn oversized_salt_is_rejected_before_decode() {
    let (_, reg, sk) = Vault::register_with(b"pw", fast_kdf()).unwrap();
    let huge_salt = "A".repeat(100); // > 64 characters
    assert!(matches!(
        Vault::unlock(b"pw", &sk, &huge_salt, reg.kdf, &reg.wrapped_vault_key),
        Err(CryptoError::Malformed)
    ));
}

#[test]
fn rotate_master_password_keeps_items_readable() {
    let (vault, _reg, sk) = Vault::register_with(b"old pw", fast_kdf()).unwrap();
    let blob = vault.encrypt_item(b"data", "i1").unwrap();

    // The Secret Key is unchanged when the password is rotated.
    let new_reg = vault
        .rotate_master_password(b"new pw", &sk, fast_kdf())
        .unwrap();
    let (vault_new, _) = Vault::unlock(
        b"new pw",
        &sk,
        &new_reg.salt,
        new_reg.kdf,
        &new_reg.wrapped_vault_key,
    )
    .unwrap();
    assert_eq!(
        vault_new.decrypt_item(&blob, "i1").unwrap().as_slice(),
        b"data"
    );
}

#[test]
fn empty_master_password_is_rejected() {
    // At signup.
    assert!(matches!(
        Vault::register_with(b"", fast_kdf()),
        Err(CryptoError::EmptyPassword)
    ));
    // At unlock.
    let (_, reg, sk) = Vault::register_with(b"pw", fast_kdf()).unwrap();
    assert!(matches!(
        Vault::unlock(b"", &sk, &reg.salt, reg.kdf, &reg.wrapped_vault_key),
        Err(CryptoError::EmptyPassword)
    ));
    // At rotation.
    let (vault, _, sk2) = Vault::register_with(b"pw", fast_kdf()).unwrap();
    assert!(matches!(
        vault.rotate_master_password(b"", &sk2, fast_kdf()),
        Err(CryptoError::EmptyPassword)
    ));
}

#[test]
fn rotation_preserves_supplied_kdf_params() {
    let (vault, _, sk) = Vault::register_with(b"old", fast_kdf()).unwrap();
    // Valid params distinct from the default (within the policy bounds).
    let custom = KdfParams {
        mem_kib: 24 * 1024,
        iterations: 3,
        parallelism: 2,
    };
    let reg = vault.rotate_master_password(b"new", &sk, custom).unwrap();
    // The requested params are preserved, not reset to the default.
    assert_eq!(reg.kdf, custom);
    assert!(Vault::unlock(b"new", &sk, &reg.salt, reg.kdf, &reg.wrapped_vault_key).is_ok());
}

#[test]
fn weak_kdf_rejected_for_new_vault() {
    let weak = KdfParams {
        mem_kib: 1024, // 1 MiB, well below the floor
        iterations: 1,
        parallelism: 1,
    };
    assert!(matches!(
        Vault::register_with(b"pw", weak),
        Err(CryptoError::KdfPolicy)
    ));
}

#[test]
fn excessive_kdf_rejected_for_new_vault() {
    let huge = KdfParams {
        mem_kib: KdfParams::MAX_MEM_KIB + 1,
        iterations: 3,
        parallelism: 1,
    };
    assert!(matches!(
        Vault::register_with(b"pw", huge),
        Err(CryptoError::KdfPolicy)
    ));
}

#[test]
fn rotation_enforces_kdf_floor() {
    let (vault, _, sk) = Vault::register_with(b"pw", fast_kdf()).unwrap();
    let weak = KdfParams {
        mem_kib: 1024,
        iterations: 1,
        parallelism: 1,
    };
    assert!(matches!(
        vault.rotate_master_password(b"new", &sk, weak),
        Err(CryptoError::KdfPolicy)
    ));
}

#[test]
fn unlock_caps_excessive_kdf_params() {
    // Anti-DoS cap: absurd params at unlock are rejected BEFORE any costly
    // derivation, without locking out weak legacy vaults.
    let (_, reg, sk) = Vault::register_with(b"pw", fast_kdf()).unwrap();
    let huge = KdfParams {
        mem_kib: KdfParams::MAX_MEM_KIB + 1,
        ..reg.kdf
    };
    assert!(matches!(
        Vault::unlock(b"pw", &sk, &reg.salt, huge, &reg.wrapped_vault_key),
        Err(CryptoError::KdfPolicy)
    ));
}

#[test]
fn encrypted_blob_serializes_to_json() {
    let (vault, _, _) = Vault::register_with(b"pw", fast_kdf()).unwrap();
    let blob = vault.encrypt_item(b"x", "i").unwrap();
    let json = serde_json::to_string(&blob).unwrap();
    let back: EncryptedBlob = serde_json::from_str(&json).unwrap();
    assert_eq!(blob, back);
}

// ─── Secret Key (encoding, parsing, Emergency Kit) ───

#[test]
fn account_secret_format_roundtrip() {
    let s = AccountSecret::generate();
    let formatted = s.to_formatted();
    assert!(formatted.starts_with("A1-"));
    // Re-parsing the displayed form yields the same key (compared via the format).
    let parsed = AccountSecret::parse(&formatted).unwrap();
    assert_eq!(parsed.to_formatted(), formatted);
}

#[test]
fn account_secret_parse_is_tolerant() {
    let s = AccountSecret::generate();
    let formatted = s.to_formatted();
    // Mixed case + spaces + dashes removed: must yield the same key.
    let messy = format!("  {}  ", formatted.to_lowercase().replace('-', " "));
    let parsed = AccountSecret::parse(&messy).unwrap();
    assert_eq!(parsed.to_formatted(), formatted);
}

#[test]
fn account_secret_rejects_typo() {
    let s = AccountSecret::generate();
    let formatted = s.to_formatted();
    // Modify two characters of the body (secret + checksum zones) -> checksum fails.
    let mut bytes = formatted.into_bytes(); // ASCII
    bytes[3] = if bytes[3] == b'A' { b'B' } else { b'A' };
    let last = bytes.len() - 1;
    bytes[last] = if bytes[last] == b'A' { b'B' } else { b'A' };
    let corrupted = String::from_utf8(bytes).unwrap();
    assert!(matches!(
        AccountSecret::parse(&corrupted),
        Err(CryptoError::Malformed)
    ));
}

#[test]
fn account_secret_parse_rejects_invalid() {
    // Too short / empty after cleanup -> incorrect length.
    assert!(matches!(
        AccountSecret::parse("A1"),
        Err(CryptoError::Malformed)
    ));
    assert!(AccountSecret::parse("").is_err());
}

#[test]
fn account_secret_rejects_oversized_input_before_normalizing() {
    let oversized = "A".repeat(1024 * 1024);
    assert!(matches!(
        AccountSecret::parse(&oversized),
        Err(CryptoError::Malformed)
    ));
}

#[test]
fn emergency_kit_contains_secret_and_label() {
    let s = AccountSecret::generate();
    let kit = s.emergency_kit("alice@example.com");
    assert!(kit.contains(&s.to_formatted()));
    assert!(kit.contains("alice@example.com"));
}

// Small base64 helpers for the tests.
fn base64_decode(s: &str) -> Vec<u8> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD.decode(s).unwrap()
}
fn base64_encode(b: &[u8]) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD.encode(b)
}
