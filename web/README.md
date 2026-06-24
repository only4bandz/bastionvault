# Démo navigateur — coffre zero-knowledge en WASM

Petite page qui fait tourner le cœur cryptographique (`crypto-core`) **dans le
navigateur**, compilé en WebAssembly via `crypto-wasm`. Tout le chiffrement est
côté client ; le panneau « Serveur » ne montre que des blobs opaques.

## Lancer

```bash
# 1. Pré-requis (une fois)
rustup target add wasm32-unknown-unknown
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh

# 2. Compiler le module WASM (génère web/pkg/, non versionné)
./web/build.sh

# 3. Servir (les modules ES imposent http://, pas file://)
cd web && python3 -m http.server 8080
# → ouvrir http://localhost:8080
```

## Ce que la démo montre

1. **Créer le coffre** depuis un mot de passe maître → la **Secret Key** s'affiche
   (montrée une fois) + l'Emergency Kit.
2. **Chiffrer des items** : ils partent au « serveur » uniquement sous forme
   chiffrée — visible dans le panneau de droite.
3. **Déverrouiller** sur un « autre appareil » : il faut le mot de passe maître
   **ET** la Secret Key. Sans les deux, le coffre est illisible.

Le même `crypto-core` alimentera l'app web complète et l'extension Chrome.
