//! Tests d'intégration du flux complet de chiffrement zero-knowledge.

use crypto_core::aead::EncryptedBlob;
use crypto_core::kdf::KdfParams;
use crypto_core::vault::{auth_secret_eq, Vault};
use crypto_core::CryptoError;

/// Paramètres KDF pour les tests : exactement le plancher de la politique
/// (sécurité minimale acceptable), pour rester rapide tout en passant la
/// validation `validate_for_new_vault`.
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
    let (vault, reg) = Vault::register_with(pw, fast_kdf()).unwrap();

    let blob = vault.encrypt_item(b"hunter2", "login-1").unwrap();

    // Déverrouillage avec les données « renvoyées par le serveur ».
    let (vault2, _auth) = Vault::unlock(pw, &reg.salt, reg.kdf, &reg.wrapped_vault_key).unwrap();
    let plain = vault2.decrypt_item(&blob, "login-1").unwrap();
    assert_eq!(plain.as_slice(), b"hunter2");
}

#[test]
fn wrong_password_cannot_unlock() {
    let (_, reg) = Vault::register_with(b"the right one", fast_kdf()).unwrap();
    let result = Vault::unlock(b"the WRONG one", &reg.salt, reg.kdf, &reg.wrapped_vault_key);
    assert!(
        result.is_err(),
        "un mauvais mot de passe ne doit pas déverrouiller"
    );
}

#[test]
fn item_id_is_authenticated_aad() {
    let (vault, _) = Vault::register_with(b"pw", fast_kdf()).unwrap();
    let blob = vault.encrypt_item(b"secret", "item-A").unwrap();
    // Déchiffrer sous un autre id doit échouer (le blob est lié à son item).
    assert!(vault.decrypt_item(&blob, "item-B").is_err());
    assert!(vault.decrypt_item(&blob, "item-A").is_ok());
}

#[test]
fn tampered_ciphertext_is_rejected() {
    let (vault, _) = Vault::register_with(b"pw", fast_kdf()).unwrap();
    let mut blob = vault.encrypt_item(b"secret", "x").unwrap();
    // On altère un octet du chiffré → le tag Poly1305 doit faire échouer.
    let mut raw = base64_decode(&blob.ct);
    raw[0] ^= 0x01;
    blob.ct = base64_encode(&raw);
    assert!(vault.decrypt_item(&blob, "x").is_err());
}

#[test]
fn tampered_wrapped_vault_key_is_rejected() {
    let pw = b"master pw";
    let (_, mut reg) = Vault::register_with(pw, fast_kdf()).unwrap();
    // On altère un octet de la clé de coffre enveloppée fournie par le serveur.
    // Le tag AEAD doit faire échouer le déballage — pas de déverrouillage
    // silencieux sur une clé corrompue ou substituée par un serveur malveillant.
    let mut raw = base64_decode(&reg.wrapped_vault_key.ct);
    raw[0] ^= 0x01;
    reg.wrapped_vault_key.ct = base64_encode(&raw);
    assert!(matches!(
        Vault::unlock(pw, &reg.salt, reg.kdf, &reg.wrapped_vault_key),
        Err(CryptoError::Aead)
    ));
}

#[test]
fn auth_secret_is_stable_and_secret() {
    let pw = b"my master password";
    let (_, reg1) = Vault::register_with(pw, fast_kdf()).unwrap();
    // Re-déverrouiller redonne le MÊME secret d'auth (déterministe par sel/pw).
    let (_, auth_a) = Vault::unlock(pw, &reg1.salt, reg1.kdf, &reg1.wrapped_vault_key).unwrap();
    let (_, auth_b) = Vault::unlock(pw, &reg1.salt, reg1.kdf, &reg1.wrapped_vault_key).unwrap();
    assert_eq!(auth_a, auth_b);
    // Mais il diffère du secret enregistré au signup ? Non : il doit l'égaler.
    assert_eq!(auth_a, reg1.auth_secret);
    assert!(auth_secret_eq(
        auth_a.as_bytes(),
        reg1.auth_secret.as_bytes()
    ));
}

#[test]
fn rotate_master_password_keeps_items_readable() {
    let (vault, _reg) = Vault::register_with(b"old pw", fast_kdf()).unwrap();
    let blob = vault.encrypt_item(b"data", "i1").unwrap();

    let new_reg = vault.rotate_master_password(b"new pw", fast_kdf()).unwrap();
    // L'ancien chiffré reste lisible avec le coffre re-déverrouillé via le NOUVEAU mdp.
    let (vault_new, _) = Vault::unlock(
        b"new pw",
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
    // À l'inscription.
    assert!(matches!(
        Vault::register_with(b"", fast_kdf()),
        Err(CryptoError::EmptyPassword)
    ));
    // Au déverrouillage.
    let (_, reg) = Vault::register_with(b"pw", fast_kdf()).unwrap();
    assert!(matches!(
        Vault::unlock(b"", &reg.salt, reg.kdf, &reg.wrapped_vault_key),
        Err(CryptoError::EmptyPassword)
    ));
    // À la rotation.
    let (vault, _) = Vault::register_with(b"pw", fast_kdf()).unwrap();
    assert!(matches!(
        vault.rotate_master_password(b"", fast_kdf()),
        Err(CryptoError::EmptyPassword)
    ));
}

#[test]
fn rotation_preserves_supplied_kdf_params() {
    let (vault, _) = Vault::register_with(b"old", fast_kdf()).unwrap();
    // Params valides distincts du défaut (dans les bornes de la politique).
    let custom = KdfParams {
        mem_kib: 24 * 1024,
        iterations: 3,
        parallelism: 2,
    };
    let reg = vault.rotate_master_password(b"new", custom).unwrap();
    // Les params demandés sont conservés, pas réinitialisés au défaut.
    assert_eq!(reg.kdf, custom);
    assert!(Vault::unlock(b"new", &reg.salt, reg.kdf, &reg.wrapped_vault_key).is_ok());
}

#[test]
fn weak_kdf_rejected_for_new_vault() {
    let weak = KdfParams {
        mem_kib: 1024, // 1 Mio, bien sous le plancher
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
    let (vault, _) = Vault::register_with(b"pw", fast_kdf()).unwrap();
    let weak = KdfParams {
        mem_kib: 1024,
        iterations: 1,
        parallelism: 1,
    };
    assert!(matches!(
        vault.rotate_master_password(b"new", weak),
        Err(CryptoError::KdfPolicy)
    ));
}

#[test]
fn unlock_caps_excessive_kdf_params() {
    // Plafond anti-DoS : des params absurdes au unlock sont rejetés AVANT toute
    // dérivation coûteuse, sans verrouiller les coffres legacy faibles.
    let (_, reg) = Vault::register_with(b"pw", fast_kdf()).unwrap();
    let huge = KdfParams {
        mem_kib: KdfParams::MAX_MEM_KIB + 1,
        ..reg.kdf
    };
    assert!(matches!(
        Vault::unlock(b"pw", &reg.salt, huge, &reg.wrapped_vault_key),
        Err(CryptoError::KdfPolicy)
    ));
}

#[test]
fn malformed_salt_is_rejected() {
    let (_, reg) = Vault::register_with(b"pw", fast_kdf()).unwrap();
    let bad = Vault::unlock(b"pw", "!!!not-base64!!!", reg.kdf, &reg.wrapped_vault_key);
    assert!(matches!(bad, Err(CryptoError::Malformed)));
}

#[test]
fn encrypted_blob_serializes_to_json() {
    let (vault, _) = Vault::register_with(b"pw", fast_kdf()).unwrap();
    let blob = vault.encrypt_item(b"x", "i").unwrap();
    let json = serde_json::to_string(&blob).unwrap();
    let back: EncryptedBlob = serde_json::from_str(&json).unwrap();
    assert_eq!(blob, back);
}

// Petits utilitaires base64 pour les tests.
fn base64_decode(s: &str) -> Vec<u8> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD.decode(s).unwrap()
}
fn base64_encode(b: &[u8]) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD.encode(b)
}
