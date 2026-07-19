#!/usr/bin/env bash
# Build the extension's generated assets:
#   1. the Rust crypto-core compiled to WebAssembly (shared with the web app),
#   2. PNG toolbar/store icons rendered from the shield SVG.
# Everything else in extension/ is plain ESM and loads as-is — no bundler.
#
# Prerequisites: rustup target add wasm32-unknown-unknown ; wasm-pack ;
# ImageMagick (`convert`) for the icons.
set -euo pipefail
cd "$(dirname "$0")"

echo "▸ Building crypto-wasm → extension/pkg"
rm -rf pkg
wasm-pack build ../crates/crypto-wasm --target web --out-dir ../../extension/pkg

echo "▸ Rendering icons → extension/icons"
for s in 16 32 48 128; do
  convert -background none icons/icon.svg -resize "${s}x${s}" -strip "icons/icon${s}.png"
done

echo "✅ Done. Load it in Chrome:"
echo "   chrome://extensions → Developer mode → Load unpacked → select this 'extension/' folder."
