#!/usr/bin/env bash
# Compiles crypto-wasm to WebAssembly + JS glue into web/pkg/.
# Prerequisites: rustup target add wasm32-unknown-unknown ; wasm-pack.
set -euo pipefail
cd "$(dirname "$0")/.."
wasm-pack build crates/crypto-wasm --target web --out-dir ../../web/pkg --no-typescript
echo "✅ web/pkg ready. Serve the demo:  (cd web && python3 -m http.server 8080)  then http://localhost:8080"
