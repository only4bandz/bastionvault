//! Tests run INSIDE a WebAssembly environment (`wasm-pack test --node`).
//!
//! Their main purpose: to prove that entropy is correctly wired up on the
//! wasm target (otherwise `register`/`unlock`, which generate salt/keys/nonces
//! via `OsRng` -> `getrandom/js`, would panic or fail). This is the
//! "actually validate WASM" debt we had noted.

#![cfg(target_arch = "wasm32")]

use crypto_wasm::{register_with, unlock};
use wasm_bindgen_test::*;

// KDF policy floor, for a fast test that still stays compliant.
const MEM_KIB: u32 = 19 * 1024;
const ITERS: u32 = 2;
const PAR: u32 = 1;

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
    let mut account = register_with("master pw", MEM_KIB, ITERS, PAR).unwrap();
    let reg = account.registration_json();
    let sk = reveal_sk(&account.reveal_secret("alice@example.com").unwrap());
    assert!(sk.starts_with("A1-"));

    let blob = account.encrypt_item("hunter2", "login-1").unwrap();

    // Unlock within the same wasm context.
    let reopened = unlock("master pw", &sk, &reg).unwrap();
    let plain = reopened.decrypt_item(&blob, "login-1").unwrap();
    assert_eq!(plain, "hunter2");
}

#[wasm_bindgen_test]
fn wrong_secret_key_fails_in_wasm() {
    let account = register_with("pw", MEM_KIB, ITERS, PAR).unwrap();
    let reg = account.registration_json();
    // Another valid but different Secret Key must not unlock.
    let mut other_acct = register_with("pw", MEM_KIB, ITERS, PAR).unwrap();
    let other = reveal_sk(&other_acct.reveal_secret("bob@example.com").unwrap());
    assert!(unlock("pw", &other, &reg).is_err());
}

#[wasm_bindgen_test]
fn lock_zeroizes_vault_so_decryption_fails() {
    let mut account = register_with("pw", MEM_KIB, ITERS, PAR).unwrap();
    let blob = account.encrypt_item("hunter2", "login-1").unwrap();
    assert!(!account.is_locked());

    account.lock();
    assert!(account.is_locked());
    // The vault key is gone: decryption (and encryption) must fail.
    assert!(account.decrypt_item(&blob, "login-1").is_err());
    assert!(account.encrypt_item("x", "login-2").is_err());
    // lock() is idempotent.
    account.lock();
    assert!(account.is_locked());
}

#[wasm_bindgen_test]
fn reveal_secret_is_one_shot() {
    let mut account = register_with("pw", MEM_KIB, ITERS, PAR).unwrap();
    // First reveal succeeds and returns both fields.
    let first = account.reveal_secret("alice@example.com").unwrap();
    assert!(reveal_sk(&first).starts_with("A1-"));
    // Second reveal fails: the Secret Key has been consumed/zeroized.
    assert!(account.reveal_secret("alice@example.com").is_err());
}

#[wasm_bindgen_test]
fn unlocked_account_retains_no_secret() {
    let mut account = register_with("pw", MEM_KIB, ITERS, PAR).unwrap();
    let reg = account.registration_json();
    let sk = reveal_sk(&account.reveal_secret("alice@example.com").unwrap());

    // An Account obtained from unlock never holds the Secret Key.
    let mut reopened = unlock("pw", &sk, &reg).unwrap();
    assert!(reopened.reveal_secret("alice@example.com").is_err());
}

#[wasm_bindgen_test]
fn manifest_bindings_roundtrip_and_rollback_in_wasm() {
    let account = register_with("pw", MEM_KIB, ITERS, PAR).unwrap();
    // Seal a manifest, reopen it (anti-rollback), and reject a rollback.
    let sealed = account.seal_manifest("{\"seq\":2,\"entries\":[]}").unwrap();
    let opened = account.open_manifest_checked(&sealed, 2).unwrap();
    assert!(opened.contains("\"seq\":2"));
    // last_seen_seq=5 > 2 -> rollback detected.
    assert!(account.open_manifest_checked(&sealed, 5).is_err());
}
