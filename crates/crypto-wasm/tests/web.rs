//! Tests run INSIDE a WebAssembly environment (`wasm-pack test --node`).
//!
//! Their main purpose: to prove that entropy is correctly wired up on the
//! wasm target (otherwise `register`/`unlock`, which generate salt/keys/nonces
//! via `OsRng` -> `getrandom/js`, would panic or fail). This is the
//! "actually validate WASM" debt we had noted.

#![cfg(target_arch = "wasm32")]

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use crypto_core::{default_lock_kdf, KdfParams};
use crypto_wasm::{register_with, rehydrate, unlock};
use wasm_bindgen_test::*;

// KDF policy floor, for a fast test that still stays compliant.
const MEM_KIB: u32 = 19 * 1024;
const ITERS: u32 = 2;
const PAR: u32 = 1;

#[wasm_bindgen_test]
fn browser_kdf_policy_rejects_unbounded_work_before_derivation() {
    assert_eq!(KdfParams::MAX_MEM_KIB, 128 * 1024);
    assert_eq!(KdfParams::MAX_ITERATIONS, 6);
    assert_eq!(KdfParams::MAX_PARALLELISM, 4);
    assert!(KdfParams::default().validate_for_new_vault().is_ok());
    assert!(default_lock_kdf().validate_for_unlock().is_ok());

    assert!(register_with(
        "pw".to_string(),
        KdfParams::MAX_MEM_KIB + 1,
        KdfParams::MIN_ITERATIONS,
        KdfParams::MIN_PARALLELISM,
    )
    .is_err());
    assert!(register_with(
        "pw".to_string(),
        KdfParams::MIN_MEM_KIB,
        KdfParams::MAX_ITERATIONS + 1,
        KdfParams::MIN_PARALLELISM,
    )
    .is_err());
    assert!(register_with(
        "pw".to_string(),
        KdfParams::MIN_MEM_KIB,
        KdfParams::MIN_ITERATIONS,
        KdfParams::MAX_PARALLELISM + 1,
    )
    .is_err());
}

#[wasm_bindgen_test]
fn pinned_send_open_never_returns_plaintext_after_verification_failure() {
    let mut recipient = register_with("recipient".to_string(), MEM_KIB, ITERS, PAR).unwrap();
    recipient.create_send_identity().unwrap();
    let recipient_public = recipient.send_identity_public().unwrap();

    let mut sender = register_with("sender".to_string(), MEM_KIB, ITERS, PAR).unwrap();
    sender.create_send_identity().unwrap();
    let sender_public = sender.send_identity_public().unwrap();
    let blob = sender
        .send_seal(
            "classified".to_string(),
            "RECIPIENT",
            &recipient_public,
            None,
            Some("ALICE".to_string()),
        )
        .unwrap();

    let pinned = format!("{{\"ALICE\":{sender_public}}}");
    let verified: serde_json::Value =
        serde_json::from_str(&recipient.send_open_with_pins(&blob, None, &pinned).unwrap())
            .unwrap();
    assert_eq!(verified["plaintext"], "classified");
    assert_eq!(verified["sender"]["state"], "verified");
    assert!(verified.get("keyChanged").is_none());

    let wrong_pin = format!("{{\"ALICE\":{recipient_public}}}");
    let rejected: serde_json::Value = serde_json::from_str(
        &recipient
            .send_open_with_pins(&blob, None, &wrong_pin)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(rejected["keyChanged"], true);
    assert_eq!(rejected["sender"]["id"], "ALICE");
    assert!(rejected.get("plaintext").is_none());
}

/// Pulls the formatted Secret Key out of the one-shot `reveal_secret` JSON
/// (`{ "secret_key": "A1-…", "emergency_kit": "…" }`).
fn reveal_sk(reveal_json: &str) -> String {
    let v: serde_json::Value = serde_json::from_str(reveal_json).unwrap();
    v["secret_key"].as_str().unwrap().to_string()
}

#[wasm_bindgen_test]
fn entropy_and_roundtrip_in_wasm() {
    // register_with generates a salt, a vault key, and a Secret Key via the
    // CSPRNG: running without panicking proves that getrandom/js works.
    let mut account = register_with("master pw".to_string(), MEM_KIB, ITERS, PAR).unwrap();
    let reg = account.registration_json();
    let sk = reveal_sk(&account.reveal_secret("alice@example.com").unwrap());
    assert!(sk.starts_with("A1-"));

    let blob = account.encrypt_item("hunter2", "login-1").unwrap();

    // Unlock within the same wasm context.
    let reopened = unlock("master pw".to_string(), sk.clone(), &reg).unwrap();
    let plain = reopened.decrypt_item(&blob, "login-1").unwrap();
    assert_eq!(plain, "hunter2");
}

#[wasm_bindgen_test]
fn wrong_secret_key_fails_in_wasm() {
    let account = register_with("pw".to_string(), MEM_KIB, ITERS, PAR).unwrap();
    let reg = account.registration_json();
    // Another valid but different Secret Key must not unlock.
    let mut other_acct = register_with("pw".to_string(), MEM_KIB, ITERS, PAR).unwrap();
    let other = reveal_sk(&other_acct.reveal_secret("bob@example.com").unwrap());
    assert!(unlock("pw".to_string(), other.clone(), &reg).is_err());
}

#[wasm_bindgen_test]
fn lock_zeroizes_vault_so_decryption_fails() {
    let mut account = register_with("pw".to_string(), MEM_KIB, ITERS, PAR).unwrap();
    let blob = account.encrypt_item("hunter2", "login-1").unwrap();
    assert!(!account.is_locked());
    assert!(!account.registration_json().is_empty());
    assert!(!account.auth_secret().is_empty());

    account.lock();
    assert!(account.is_locked());
    assert!(account.registration_json().is_empty());
    assert!(account.auth_secret().is_empty());
    // The vault key is gone: decryption (and encryption) must fail.
    assert!(account.decrypt_item(&blob, "login-1").is_err());
    assert!(account.encrypt_item("x", "login-2").is_err());
    // lock() is idempotent.
    account.lock();
    assert!(account.is_locked());
}

#[wasm_bindgen_test]
fn session_rehydrate_and_private_identity_import_roundtrip() {
    let mut account = register_with("pw".to_string(), MEM_KIB, ITERS, PAR).unwrap();
    let item = account.encrypt_item("hunter2", "login-1").unwrap();
    let identity_blob = account.create_send_identity().unwrap();
    let public = account.send_identity_public().unwrap();
    let session = account.export_session().unwrap();

    let mut restored = rehydrate(session.clone()).unwrap();
    assert_eq!(restored.decrypt_item(&item, "login-1").unwrap(), "hunter2");
    restored.load_send_identity(&identity_blob).unwrap();
    assert_eq!(restored.send_identity_public().unwrap(), public);

    let mut malformed: serde_json::Value = serde_json::from_str(&session).unwrap();
    malformed["vault_key"] = serde_json::Value::String(B64.encode([0u8; 31]));
    assert!(rehydrate(serde_json::to_string(&malformed).unwrap()).is_err());
}

#[wasm_bindgen_test]
fn reveal_secret_is_one_shot() {
    let mut account = register_with("pw".to_string(), MEM_KIB, ITERS, PAR).unwrap();
    // First reveal succeeds and returns both fields.
    let first = account.reveal_secret("alice@example.com").unwrap();
    assert!(reveal_sk(&first).starts_with("A1-"));
    // Second reveal fails: the Secret Key has been consumed/zeroized.
    assert!(account.reveal_secret("alice@example.com").is_err());
}

#[wasm_bindgen_test]
fn unlocked_account_retains_no_secret() {
    let mut account = register_with("pw".to_string(), MEM_KIB, ITERS, PAR).unwrap();
    let reg = account.registration_json();
    let sk = reveal_sk(&account.reveal_secret("alice@example.com").unwrap());

    // An Account obtained from unlock never holds the Secret Key.
    let mut reopened = unlock("pw".to_string(), sk.clone(), &reg).unwrap();
    assert!(reopened.reveal_secret("alice@example.com").is_err());
}

#[wasm_bindgen_test]
fn manifest_bindings_roundtrip_and_rollback_in_wasm() {
    let account = register_with("pw".to_string(), MEM_KIB, ITERS, PAR).unwrap();
    let a = account.encrypt_item("a", "a").unwrap();
    let b = account.encrypt_item("b", "b").unwrap();
    let items = format!("{{\"b\":{b},\"a\":{a}}}");
    let manifest = account.manifest_from_items(&items).unwrap();
    assert!(manifest.contains("\"seq\":2"));
    assert_eq!(account.manifest_seq(&manifest).unwrap(), 2);
    assert!(manifest.find("\"id\":\"a\"").unwrap() < manifest.find("\"id\":\"b\"").unwrap());

    let updated_a = account.encrypt_item("updated", "a").unwrap();
    let manifest = account
        .manifest_set_item(&manifest, "a", &updated_a)
        .unwrap();
    assert!(manifest.contains("\"seq\":3"));
    let manifest = account.manifest_remove_item(&manifest, "b").unwrap();
    assert!(manifest.contains("\"seq\":4"));
    let unchanged = account.manifest_remove_item(&manifest, "absent").unwrap();
    assert_eq!(unchanged, manifest);

    // Seal the Rust-produced manifest, reopen it, and reject a rollback.
    let sealed = account.seal_manifest(&manifest).unwrap();
    let opened = account.open_manifest_checked(&sealed, 2).unwrap();
    assert_eq!(opened, manifest);
    assert!(account.open_manifest_checked(&sealed, 5).is_err());

    // Mutation and sealing reject malformed caller-provided manifests.
    let malformed = "{\"seq\":1,\"entries\":[{\"id\":\"a\",\"digest\":\"bad\"}]}";
    assert!(account
        .manifest_set_item(malformed, "a", &updated_a)
        .is_err());
    assert!(account.seal_manifest(malformed).is_err());
    let exhausted = "{\"seq\":18446744073709551615,\"entries\":[]}";
    assert!(account
        .manifest_set_item(exhausted, "a", &updated_a)
        .is_err());
}

#[wasm_bindgen_test]
fn create_send_identity_refuses_to_overwrite() {
    let mut account = register_with("pw".to_string(), MEM_KIB, ITERS, PAR).unwrap();
    account.create_send_identity().unwrap();
    let first_public = account.send_identity_public().unwrap();

    // A second create must fail — silently regenerating the X25519 key would
    // orphan every inbound message and locked record bound to the old key.
    assert!(account.create_send_identity().is_err());
    assert_eq!(account.send_identity_public().unwrap(), first_public);

    // Explicit rotation is allowed and bumps the key version.
    account.replace_send_identity().unwrap();
    let rotated_public = account.send_identity_public().unwrap();
    assert_ne!(rotated_public, first_public);
}
