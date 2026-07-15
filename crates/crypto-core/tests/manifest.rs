//! Integration tests for the vault's integrity manifest.

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

/// Builds a manifest from encrypted items, the way the client would.
fn build(vault: &Vault, items: &[(&str, &[u8])]) -> (Manifest, Vec<(String, EncryptedBlob)>) {
    let mut manifest = Manifest::new();
    let mut blobs = Vec::new();
    for (id, plain) in items {
        let blob = vault.encrypt_item(plain, id).unwrap();
        manifest.set(id, &blob).unwrap();
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
    assert!(report.is_intact(), "unexpected report: {report:?}");
}

#[test]
fn detects_deleted_item() {
    let vault = fresh_vault();
    let (manifest, blobs) = build(&vault, &[("a", b"1"), ("b", b"2")]);
    // The server "forgets" item b.
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
    // The server injects an item "z" that was never recorded in the manifest.
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
    // Item "a" is updated (new ciphertext) and the manifest follows.
    let updated = vault.encrypt_item(b"v2", "a").unwrap();
    manifest.set("a", &updated).unwrap();
    // But the server serves the OLD ciphertext again (rollback) -> different digest.
    // blobs[0].1 still holds v1.
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
    manifest.set("a", &blob).unwrap();
    assert_eq!(manifest.seq(), 1);
    manifest.set("a", &blob).unwrap(); // updating the same entry counts too
    assert_eq!(manifest.seq(), 2);
    assert!(manifest.remove("a").unwrap());
    assert_eq!(manifest.seq(), 3);
    assert!(!manifest.remove("absent").unwrap()); // no increment if nothing was removed
    assert_eq!(manifest.seq(), 3);
}

#[test]
fn manifest_from_another_vault_cannot_be_opened() {
    let v1 = fresh_vault();
    let v2 = fresh_vault();
    let (manifest, _) = build(&v1, &[("a", b"1")]);
    let sealed = v1.seal_manifest(&manifest).unwrap();
    // A different vault cannot decrypt the manifest.
    assert!(matches!(v2.open_manifest(&sealed), Err(CryptoError::Aead)));
}

#[test]
fn open_manifest_checked_rejects_rollback() {
    let vault = fresh_vault();
    let mut manifest = Manifest::new();
    let blob = vault.encrypt_item(b"x", "a").unwrap();
    manifest.set("a", &blob).unwrap(); // seq = 1
    manifest.set("a", &blob).unwrap(); // seq = 2
    let sealed = vault.seal_manifest(&manifest).unwrap();

    // The client saw seq=2; serving seq=2 again is accepted.
    assert!(vault.open_manifest_checked(&sealed, 2).is_ok());
    // If it has already seen seq=5, a seq=2 manifest is a rollback.
    assert!(matches!(
        vault.open_manifest_checked(&sealed, 5),
        Err(CryptoError::StaleManifest)
    ));
}

#[test]
fn check_detects_duplicate_ids() {
    let vault = fresh_vault();
    let (manifest, blobs) = build(&vault, &[("a", b"1")]);
    // The server serves the same id twice.
    let served = vec![
        (blobs[0].0.as_str(), &blobs[0].1),
        (blobs[0].0.as_str(), &blobs[0].1),
    ];
    let report = manifest.check(&served);
    assert_eq!(report.duplicates, vec!["a".to_string()]);
    assert!(!report.is_intact());
}

#[test]
fn seal_manifest_rejects_duplicate_entries() {
    let vault = fresh_vault();
    // Malformed manifest: two entries with the same id.
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
    assert!(matches!(
        vault.seal_manifest(&bogus),
        Err(CryptoError::Malformed)
    ));
}

#[test]
fn manifest_from_items_is_deterministic_and_rejects_duplicates() {
    let vault = fresh_vault();
    let a = vault.encrypt_item(b"a", "a").unwrap();
    let b = vault.encrypt_item(b"b", "b").unwrap();

    let forward = Manifest::from_items(&[("a", &a), ("b", &b)]).unwrap();
    let reverse = Manifest::from_items(&[("b", &b), ("a", &a)]).unwrap();
    assert_eq!(forward, reverse);
    assert_eq!(forward.seq(), 2);
    assert_eq!(forward.entries[0].id, "a");
    assert_eq!(forward.entries[1].id, "b");
    assert!(matches!(
        Manifest::from_items(&[("a", &a), ("a", &b)]),
        Err(CryptoError::Malformed)
    ));
}

#[test]
fn manifest_rejects_invalid_digests_and_sequence_overflow() {
    let vault = fresh_vault();
    let blob = vault.encrypt_item(b"a", "a").unwrap();
    let malformed = Manifest {
        seq: 1,
        entries: vec![ManifestEntry {
            id: "a".into(),
            digest: "not-a-sha256-digest".into(),
        }],
    };
    assert!(matches!(malformed.validate(), Err(CryptoError::Malformed)));
    assert!(matches!(
        vault.seal_manifest(&malformed),
        Err(CryptoError::Malformed)
    ));

    let mut exhausted = Manifest {
        seq: u64::MAX,
        entries: Vec::new(),
    };
    assert!(matches!(
        exhausted.set("a", &blob),
        Err(CryptoError::Malformed)
    ));
    assert!(exhausted.entries.is_empty());
}

#[test]
fn tampered_manifest_blob_is_rejected() {
    let vault = fresh_vault();
    let (manifest, _) = build(&vault, &[("a", b"1")]);
    let mut sealed = vault.seal_manifest(&manifest).unwrap();
    // Tamper with the manifest's ciphertext.
    use base64::{engine::general_purpose::STANDARD, Engine};
    let mut raw = STANDARD.decode(&sealed.ct).unwrap();
    raw[0] ^= 0x01;
    sealed.ct = STANDARD.encode(&raw);
    assert!(matches!(
        vault.open_manifest(&sealed),
        Err(CryptoError::Aead)
    ));
}
