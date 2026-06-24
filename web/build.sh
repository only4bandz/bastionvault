#!/usr/bin/env bash
# Compile crypto-wasm en WebAssembly + glue JS dans web/pkg/.
# Pré-requis : rustup target add wasm32-unknown-unknown ; wasm-pack.
set -euo pipefail
cd "$(dirname "$0")/.."
wasm-pack build crates/crypto-wasm --target web --out-dir ../../web/pkg --no-typescript
echo "✅ web/pkg prêt. Servez la démo :  (cd web && python3 -m http.server 8080)  puis http://localhost:8080"
