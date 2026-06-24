//! Tests d'intégration du manifest d'intégrité du coffre.

use crypto_core::kdf::KdfParams;
use crypto_core::{CryptoError, EncryptedBlob, Manifest, ManifestEntry, Vault};

fn fast_kdf() -> KdfParams {
    KdfParams {
        mem_kib: KdfParams::MIN_MEM_KIB,
        iterations: KdfParams::MIN_ITERATIONS,
        parallelism: KdfParams::MIN_PARALLELISM,
    }
}

fn fresh_vault() -> Vault {
    Vault::register_with(b"pw", fast_kdf()).unwrap().0
}

/// Construit un manifest à partir d'items chiffrés, comme le ferait le client.
fn build(vault: &Vault, items: &[(&str, &[u8])]) -> (Manifest, Vec<(String, EncryptedBlob)>) {
    let mut manifest = Manifest::new();
    let mut blobs = Vec::new();
    for (id, plain) in items {
        let blob = vault.encrypt_item(plain, id).unwrap();
        manifest.set(id, &blob);
        blobs.push((id.to_string(), blob));
    }
    (manifest, blobs)
}

fn present(blobs: &[(String, EncryptedBlob)]) -> Vec<(&str, &EncryptedBlob)> {
    blobs.iter().map(|(id, b)| (id.as_str(), b)).collect()
}

#[test]
fn seal_open_roundtrip() {
    let vault = fresh_vault();
    let (manifest, _) = build(&vault, &[("a", b"1"), ("b", b"2")]);
    let sealed = vault.seal_manifest(&manifest).unwrap();
    let opened = vault.open_manifest(&sealed).unwrap();
    assert_eq!(opened, manifest);
}

#[test]
fn intact_when_server_matches_manifest() {
    let vault = fresh_vault();
    let (manifest, blobs) = build(&vault, &[("a", b"1"), ("b", b"2"), ("c", b"3")]);
    let report = manifest.check(&present(&blobs));
    assert!(report.is_intact(), "report inattendu : {report:?}");
}

#[test]
fn detects_deleted_item() {
    let vault = fresh_vault();
    let (manifest, blobs) = build(&vault, &[("a", b"1"), ("b", b"2")]);
    // Le serveur « oublie » l'item b.
    let served = vec![(blobs[0].0.as_str(), &blobs[0].1)];
    let report = manifest.check(&served);
    assert_eq!(report.missing, vec!["b".to_string()]);
    assert!(report.unexpected.is_empty() && report.corrupted.is_empty());
    assert!(!report.is_intact());
}

#[test]
fn detects_injected_item() {
    let vault = fresh_vault();
    let (manifest, mut blobs) = build(&vault, &[("a", b"1")]);
    // Le serveur injecte un item « z » jamais enregistré dans le manifest.
    let rogue = vault.encrypt_item(b"evil", "z").unwrap();
    blobs.push(("z".to_string(), rogue));
    let report = manifest.check(&present(&blobs));
    assert_eq!(report.unexpected, vec!["z".to_string()]);
    assert!(report.missing.is_empty() && report.corrupted.is_empty());
}

#[test]
fn detects_rolled_back_or_substituted_item() {
    let vault = fresh_vault();
    let (mut manifest, mut blobs) = build(&vault, &[("a", b"v1")]);
    // L'item « a » est mis à jour (nouveau chiffré) et le manifest suit.
    let updated = vault.encrypt_item(b"v2", "a").unwrap();
    manifest.set("a", &updated);
    // Mais le serveur resert l'ANCIEN chiffré (rollback) → digest différent.
    // blobs[0].1 contient toujours la v1.
    let _ = &mut blobs;
    let report = manifest.check(&[(blobs[0].0.as_str(), &blobs[0].1)]);
    assert_eq!(report.corrupted, vec!["a".to_string()]);
    assert!(!report.is_intact());
}

#[test]
fn seq_increments_on_change() {
    let vault = fresh_vault();
    let mut manifest = Manifest::new();
    assert_eq!(manifest.seq(), 0);
    let blob = vault.encrypt_item(b"x", "a").unwrap();
    manifest.set("a", &blob);
    assert_eq!(manifest.seq(), 1);
    manifest.set("a", &blob); // mise à jour de la même entrée compte aussi
    assert_eq!(manifest.seq(), 2);
    assert!(manifest.remove("a"));
    assert_eq!(manifest.seq(), 3);
    assert!(!manifest.remove("absent")); // pas d'incrément si rien retiré
    assert_eq!(manifest.seq(), 3);
}

#[test]
fn manifest_from_another_vault_cannot_be_opened() {
    let v1 = fresh_vault();
    let v2 = fresh_vault();
    let (manifest, _) = build(&v1, &[("a", b"1")]);
    let sealed = v1.seal_manifest(&manifest).unwrap();
    // Un autre coffre ne peut pas déchiffrer le manifest.
    assert!(matches!(v2.open_manifest(&sealed), Err(CryptoError::Aead)));
}

#[test]
fn open_manifest_checked_rejects_rollback() {
    let vault = fresh_vault();
    let mut manifest = Manifest::new();
    let blob = vault.encrypt_item(b"x", "a").unwrap();
    manifest.set("a", &blob); // seq = 1
    manifest.set("a", &blob); // seq = 2
    let sealed = vault.seal_manifest(&manifest).unwrap();

    // Le client a vu seq=2 ; resservir seq=2 est accepté.
    assert!(vault.open_manifest_checked(&sealed, 2).is_ok());
    // S'il a déjà vu seq=5, un manifest seq=2 est un rollback.
    assert!(matches!(
        vault.open_manifest_checked(&sealed, 5),
        Err(CryptoError::StaleManifest)
    ));
}

#[test]
fn check_detects_duplicate_ids() {
    let vault = fresh_vault();
    let (manifest, blobs) = build(&vault, &[("a", b"1")]);
    // Le serveur sert deux fois le même id.
    let served = vec![
        (blobs[0].0.as_str(), &blobs[0].1),
        (blobs[0].0.as_str(), &blobs[0].1),
    ];
    let report = manifest.check(&served);
    assert_eq!(report.duplicates, vec!["a".to_string()]);
    assert!(!report.is_intact());
}

#[test]
fn open_manifest_rejects_duplicate_entries() {
    let vault = fresh_vault();
    // Manifest mal formé : deux entrées avec le même id.
    let bogus = Manifest {
        seq: 1,
        entries: vec![
            ManifestEntry {
                id: "a".into(),
                digest: "x".into(),
            },
            ManifestEntry {
                id: "a".into(),
                digest: "y".into(),
            },
        ],
    };
    let sealed = vault.seal_manifest(&bogus).unwrap();
    assert!(matches!(
        vault.open_manifest(&sealed),
        Err(CryptoError::Malformed)
    ));
}

#[test]
fn tampered_manifest_blob_is_rejected() {
    let vault = fresh_vault();
    let (manifest, _) = build(&vault, &[("a", b"1")]);
    let mut sealed = vault.seal_manifest(&manifest).unwrap();
    // Altère le chiffré du manifest.
    use base64::{engine::general_purpose::STANDARD, Engine};
    let mut raw = STANDARD.decode(&sealed.ct).unwrap();
    raw[0] ^= 0x01;
    sealed.ct = STANDARD.encode(&raw);
    assert!(matches!(
        vault.open_manifest(&sealed),
        Err(CryptoError::Aead)
    ));
}
