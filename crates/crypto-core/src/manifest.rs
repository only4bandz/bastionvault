//! Vault integrity manifest.
//!
//! Per-item AEAD protects the *content* of each item (any tampering with a
//! ciphertext is detected). It does NOT protect the **set as a whole**: a
//! malicious server can still
//! - delete an item (the client no longer sees it),
//! - inject an item,
//! - re-serve an **older** version of an item (rollback) — a stale ciphertext
//!   is still a valid ciphertext.
//!
//! The manifest fills this gap. It is an index encrypted under the `vault_key`
//! that records, for each item, a **digest** of its ciphertext, plus a
//! monotonic `seq` counter. On sync, the client compares what the server
//! returns against the manifest: any discrepancy (missing / unexpected /
//! corrupted) betrays tampering. Since it is encrypted under the `vault_key`,
//! only this vault can read it — a manifest from another account will not
//! decrypt.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

use crate::aead::EncryptedBlob;
use crate::error::{CryptoError, Result};

/// Hashing domain for an item's digest (cryptographic separation).
const ITEM_DIGEST_DOMAIN: &[u8] = b"pm:v1:item-digest";

/// Stable digest of an item's ciphertext: `SHA-256(domain || v || nonce || 0 || ct)`.
/// Includes the format version; the separator `0` is not part of the base64
/// alphabet, so the concatenation is unambiguous.
fn item_digest(blob: &EncryptedBlob) -> String {
    let mut h = Sha256::new();
    h.update(ITEM_DIGEST_DOMAIN);
    h.update([blob.v]);
    h.update(blob.nonce.as_bytes());
    h.update([0u8]);
    h.update(blob.ct.as_bytes());
    B64.encode(h.finalize())
}

/// A manifest entry: an item's id and the digest of its current ciphertext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestEntry {
    /// Opaque identifier of the item.
    pub id: String,
    /// Base64 digest of the ciphertext expected for this item.
    pub digest: String,
}

/// Vault integrity index. Entries sorted by id (determinism).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// Monotonic counter, incremented on each change. The client remembers the
    /// last known `seq` to detect a server re-serving an old manifest (global
    /// rollback).
    pub seq: u64,
    /// Entries, sorted by `id`.
    pub entries: Vec<ManifestEntry>,
}

impl Manifest {
    /// Empty manifest (seq = 0).
    pub fn new() -> Self {
        Self::default()
    }

    /// Current version counter.
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// Adds or updates an item's entry from its ciphertext, and increments
    /// `seq`.
    pub fn set(&mut self, id: &str, blob: &EncryptedBlob) {
        let digest = item_digest(blob);
        match self.entries.binary_search_by(|e| e.id.as_str().cmp(id)) {
            Ok(i) => self.entries[i].digest = digest,
            Err(i) => self.entries.insert(
                i,
                ManifestEntry {
                    id: id.to_string(),
                    digest,
                },
            ),
        }
        self.seq += 1;
    }

    /// Removes an item. Increments `seq` and returns `true` if the item existed.
    pub fn remove(&mut self, id: &str) -> bool {
        if let Ok(i) = self.entries.binary_search_by(|e| e.id.as_str().cmp(id)) {
            self.entries.remove(i);
            self.seq += 1;
            true
        } else {
            false
        }
    }

    /// Checks the internal invariant: entries **sorted by id and without
    /// duplicates**. Called when opening a sealed manifest — a defense against a
    /// corrupted/malformed manifest whose duplicate ids would hide items.
    pub fn validate(&self) -> Result<()> {
        for pair in self.entries.windows(2) {
            if pair[0].id >= pair[1].id {
                return Err(CryptoError::Malformed);
            }
        }
        Ok(())
    }

    /// Compares the manifest against the set of items actually served by the
    /// server. Returns a report listing the discrepancies.
    ///
    /// `present` = `(id, ciphertext)` pairs received from the server.
    pub fn check(&self, present: &[(&str, &EncryptedBlob)]) -> IntegrityReport {
        let expected: BTreeMap<&str, &str> = self
            .entries
            .iter()
            .map(|e| (e.id.as_str(), e.digest.as_str()))
            .collect();
        let present_digests: BTreeMap<&str, String> = present
            .iter()
            .map(|(id, blob)| (*id, item_digest(blob)))
            .collect();

        // IDs served twice: the server may be trying to hide an item behind a
        // namesake. We report them instead of merging them.
        let mut seen = BTreeSet::new();
        let mut duplicates = Vec::new();
        for (id, _) in present {
            if !seen.insert(*id) && !duplicates.iter().any(|d: &String| d == id) {
                duplicates.push((*id).to_string());
            }
        }

        let mut missing = Vec::new();
        let mut corrupted = Vec::new();
        for (id, dig) in &expected {
            match present_digests.get(id) {
                None => missing.push((*id).to_string()),
                Some(actual) if actual != dig => corrupted.push((*id).to_string()),
                _ => {}
            }
        }
        let unexpected = present_digests
            .keys()
            .filter(|id| !expected.contains_key(**id))
            .map(|id| (*id).to_string())
            .collect();

        IntegrityReport {
            missing,
            unexpected,
            corrupted,
            duplicates,
        }
    }
}

/// Result of a [`Manifest::check`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrityReport {
    /// Items expected (in the manifest) but absent on the server → deletion.
    pub missing: Vec<String>,
    /// Items served but absent from the manifest → injection.
    pub unexpected: Vec<String>,
    /// Items present on both sides but with a different digest → tampering,
    /// substitution, or rollback of an item.
    pub corrupted: Vec<String>,
    /// IDs served multiple times by the server → malformed/hostile response.
    pub duplicates: Vec<String>,
}

impl IntegrityReport {
    /// `true` if there is no discrepancy: the served vault matches the manifest exactly.
    pub fn is_intact(&self) -> bool {
        self.missing.is_empty()
            && self.unexpected.is_empty()
            && self.corrupted.is_empty()
            && self.duplicates.is_empty()
    }
}
