//! Manifest d'intégrité du coffre.
//!
//! L'AEAD par-item protège le *contenu* de chaque item (toute altération d'un
//! chiffré est détectée). Il ne protège PAS l'**ensemble** : un serveur
//! malveillant peut toujours
//! - supprimer un item (le client ne le voit plus),
//! - injecter un item,
//! - resservir une **ancienne** version d'un item (rollback) — un chiffré
//!   périmé reste un chiffré valide.
//!
//! Le manifest comble ce trou. C'est un index chiffré sous la `vault_key` qui
//! mémorise, pour chaque item, un **digest** de son chiffré, plus un compteur
//! `seq` monotone. À la synchro, le client compare ce que renvoie le serveur au
//! manifest : tout écart (manquant / inattendu / corrompu) trahit une
//! manipulation. Comme il est chiffré sous la `vault_key`, seul ce coffre peut
//! le lire — un manifest d'un autre compte ne déchiffre pas.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use crate::aead::EncryptedBlob;

/// Domaine de hachage du digest d'un item (séparation cryptographique).
const ITEM_DIGEST_DOMAIN: &[u8] = b"pm:v1:item-digest";

/// Digest stable d'un chiffré d'item : `SHA-256(domaine || v || nonce || 0 || ct)`.
/// Inclut la version de format ; le séparateur `0` n'appartient pas à l'alphabet
/// base64, donc la concaténation est non ambiguë.
fn item_digest(blob: &EncryptedBlob) -> String {
    let mut h = Sha256::new();
    h.update(ITEM_DIGEST_DOMAIN);
    h.update([blob.v]);
    h.update(blob.nonce.as_bytes());
    h.update([0u8]);
    h.update(blob.ct.as_bytes());
    B64.encode(h.finalize())
}

/// Une entrée du manifest : l'id d'un item et le digest de son chiffré courant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestEntry {
    /// Identifiant opaque de l'item.
    pub id: String,
    /// Digest base64 du chiffré attendu pour cet item.
    pub digest: String,
}

/// Index d'intégrité du coffre. Entrées triées par id (déterminisme).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// Compteur monotone, incrémenté à chaque modification. Le client mémorise
    /// le dernier `seq` connu pour détecter qu'un serveur resert un vieux
    /// manifest (rollback global).
    pub seq: u64,
    /// Entrées, triées par `id`.
    pub entries: Vec<ManifestEntry>,
}

impl Manifest {
    /// Manifest vide (seq = 0).
    pub fn new() -> Self {
        Self::default()
    }

    /// Compteur de version courant.
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// Ajoute ou met à jour l'entrée d'un item à partir de son chiffré, et
    /// incrémente `seq`.
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

    /// Retire un item. Incrémente `seq` et renvoie `true` si l'item existait.
    pub fn remove(&mut self, id: &str) -> bool {
        if let Ok(i) = self.entries.binary_search_by(|e| e.id.as_str().cmp(id)) {
            self.entries.remove(i);
            self.seq += 1;
            true
        } else {
            false
        }
    }

    /// Confronte le manifest à l'ensemble d'items réellement servis par le
    /// serveur. Renvoie un rapport listant les écarts.
    ///
    /// `present` = couples `(id, chiffré)` reçus du serveur.
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
        }
    }
}

/// Résultat d'un [`Manifest::check`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IntegrityReport {
    /// Items attendus (dans le manifest) mais absents côté serveur → suppression.
    pub missing: Vec<String>,
    /// Items servis mais absents du manifest → injection.
    pub unexpected: Vec<String>,
    /// Items présents des deux côtés mais au digest différent → altération,
    /// substitution ou rollback d'un item.
    pub corrupted: Vec<String>,
}

impl IntegrityReport {
    /// `true` si aucun écart : le coffre servi correspond exactement au manifest.
    pub fn is_intact(&self) -> bool {
        self.missing.is_empty() && self.unexpected.is_empty() && self.corrupted.is_empty()
    }
}
