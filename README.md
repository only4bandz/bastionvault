# 🔐 Gestionnaire de mots de passe (zero-knowledge)

Gestionnaire de mots de passe **zero-knowledge** en Rust : le serveur ne voit
jamais ton mot de passe maître ni un seul secret en clair. Tout le chiffrement
se fait côté client. Conçu pour une app web aujourd'hui, et une **extension
Chrome** plus tard — les deux partagent le même cœur crypto (Rust → WASM).

## Modèle de sécurité

```
mot de passe maître ──Argon2id(sel, 64Mio)──► clé maître
                                                 │
              Secret Key (128 bits, user) ──────►│ HKDF-Extract (sel)
                                                 │
                            ┌──────HKDF──────────┼──────HKDF──────┐
                            ▼                                     ▼
                       clé de wrap                          secret d'auth ──► serveur
                            │                                (prouve l'identité,
                            │ enveloppe                       ne déchiffre rien)
                            ▼
        clé de coffre (aléatoire 256 bits) ──chiffre──► tous les items
```

- **Argon2id** (64 Mio, 3 passes) protège contre le brute-force hors-ligne.
- **Secret Key** (128 bits, modèle 1Password) : un second facteur détenu par
  l'utilisateur, mélangé comme sel HKDF. Le brute-force hors-ligne devient
  infaisable **même avec un mot de passe faible** — le serveur ne la voit jamais.
  Montrée une fois via un **Emergency Kit**, ressaisie sur chaque appareil.
- **XChaCha20-Poly1305** chiffre chaque item (AEAD, nonce 192 bits aléatoire).
- La **clé de coffre** est aléatoire et *enveloppée* : changer de mot de passe
  maître ne re-chiffre pas tous les items.
- **Manifest d'intégrité** : un index chiffré sous la clé de coffre liste le
  digest de chaque item. À la synchro, on détecte si un serveur malveillant a
  supprimé, injecté, ou rollbacké un item (ce que l'AEAD par-item seul ne voit
  pas). Un compteur `seq` monotone bloque le rollback du manifest lui-même.
- Le serveur ne stocke que des **blobs opaques** + un hash lent du secret d'auth.
  Une fuite serveur ne révèle aucun mot de passe.

## Structure

```
crates/crypto-core/   ✅ Cœur crypto, Rust pur, 8 tests. Compile natif + WASM.
crates/crypto-wasm/   ⬜ Liaisons wasm-bindgen (étape 2)
crates/server/        ⬜ API Axum, stockage de blobs chiffrés (étape 3)
web/                  ⬜ Interface navigateur (étape 4)
```

## Feuille de route

| # | Étape | État |
|---|-------|------|
| 1 | Cœur crypto (Argon2id + AEAD + key wrapping), testé | ✅ Fait |
| 2 | Liaisons WASM + démo navigateur | ⬜ |
| 3 | API serveur Axum (comptes, stockage chiffré) | ⬜ |
| 4 | Interface web (coffre, ajout/lecture d'items) | ⬜ |
| 5 | 2FA TOTP (authenticator) | ⬜ |
| 6 | Clés FIDO2 / WebAuthn (YubiKey, Trustkey) | ⬜ |
| 7 | Vérification SMS | ⬜ |
| 8 | Extension Chrome (réutilise crypto-core via WASM) | ⬜ |

## Développement

```bash
cargo test -p crypto-core      # lance les tests du cœur crypto
```
