#!/usr/bin/env bash
# Compile the Rust crypto-core to WebAssembly + TS bindings into app/src/pkg/.
# Prerequisites: rustup target add wasm32-unknown-unknown ; wasm-pack.
set -euo pipefail
cd "$(dirname "$0")"
rm -rf src/pkg
wasm-pack build ../crates/crypto-wasm --target web --out-dir ../../app/src/pkg
echo "✅ app/src/pkg ready. Now: npm install && npm run dev"
