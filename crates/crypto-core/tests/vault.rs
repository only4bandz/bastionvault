//! Tests d'intégration du flux complet de chiffrement zero-knowledge.

use crypto_core::aead::{self, EncryptedBlob};
use crypto_core::kdf::KdfParams;
use crypto_core::vault::{auth_secret_eq, Vault};
use crypto_core::CryptoError;

/// Paramètres KDF rapides pour les tests (sinon Argon2id ralentit la suite).
fn fast_kdf() -> KdfParams {
    KdfParams {
        mem_kib: 8 * 1024,
        iterations: 1,
        parallelism: 1,
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
    let custom = KdfParams {
        mem_kib: 16 * 1024,
        iterations: 2,
        parallelism: 1,
    };
    let reg = vault.rotate_master_password(b"new", custom).unwrap();
    // Les params demandés sont conservés, pas réinitialisés au défaut.
    assert_eq!(reg.kdf, custom);
    assert!(Vault::unlock(b"new", &reg.salt, reg.kdf, &reg.wrapped_vault_key).is_ok());
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

// Garde une référence à `aead` pour éviter un warning d'import inutilisé si les
// tests ci-dessus évoluent.
#[allow(dead_code)]
fn _uses_aead(k: &crypto_core::secret::SecretKey) -> Option<EncryptedBlob> {
    aead::encrypt(k, b"", b"").ok()
}
