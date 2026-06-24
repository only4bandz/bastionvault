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

#[wasm_bindgen_test]
fn entropy_and_roundtrip_in_wasm() {
    // register_with generates a salt, a vault key, and a Secret Key via the
    // CSPRNG: running without panicking proves that getrandom/js works.
    let account = register_with("master pw", MEM_KIB, ITERS, PAR).unwrap();
    let reg = account.registration_json();
    let sk = account.secret_key();
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
    let other = register_with("pw", MEM_KIB, ITERS, PAR)
        .unwrap()
        .secret_key();
    assert!(unlock("pw", &other, &reg).is_err());
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
