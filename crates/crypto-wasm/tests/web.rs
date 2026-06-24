//! Tests exécutés DANS un environnement WebAssembly (`wasm-pack test --node`).
//!
//! Leur rôle principal : prouver que l'entropie est correctement câblée sur la
//! cible wasm (sinon `register`/`unlock`, qui génèrent sel/clés/nonces via
//! `OsRng` → `getrandom/js`, paniqueraient ou échoueraient). C'est la dette
//! « valider WASM réellement » qu'on s'était notée.

#![cfg(target_arch = "wasm32")]

use crypto_wasm::{register_with, unlock};
use wasm_bindgen_test::*;

// Plancher de la politique KDF, pour un test rapide tout en restant conforme.
const MEM_KIB: u32 = 19 * 1024;
const ITERS: u32 = 2;
const PAR: u32 = 1;

#[wasm_bindgen_test]
fn entropy_and_roundtrip_in_wasm() {
    // register_with génère un sel, une clé de coffre et une Secret Key via le
    // CSPRNG : s'exécuter sans paniquer prouve que getrandom/js fonctionne.
    let account = register_with("master pw", MEM_KIB, ITERS, PAR).unwrap();
    let reg = account.registration_json();
    let sk = account.secret_key();
    assert!(sk.starts_with("A1-"));

    let blob = account.encrypt_item("hunter2", "login-1").unwrap();

    // Déverrouillage dans le même contexte wasm.
    let reopened = unlock("master pw", &sk, &reg).unwrap();
    let plain = reopened.decrypt_item(&blob, "login-1").unwrap();
    assert_eq!(plain, "hunter2");
}

#[wasm_bindgen_test]
fn wrong_secret_key_fails_in_wasm() {
    let account = register_with("pw", MEM_KIB, ITERS, PAR).unwrap();
    let reg = account.registration_json();
    // Une autre Secret Key valide mais différente ne doit pas déverrouiller.
    let other = register_with("pw", MEM_KIB, ITERS, PAR)
        .unwrap()
        .secret_key();
    assert!(unlock("pw", &other, &reg).is_err());
}
