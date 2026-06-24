# Browser demo — zero-knowledge vault in WASM

A small page that runs the cryptographic core (`crypto-core`) **in the
browser**, compiled to WebAssembly via `crypto-wasm`. All encryption happens
client-side; the "Server" panel only shows opaque blobs.

## Run

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

## What the demo shows

1. **Create the vault** from a master password → the **Secret Key** is displayed
   (shown once) + the Emergency Kit.
2. **Encrypt items**: they go to the "server" only in encrypted form — visible in
   the right-hand panel.
3. **Unlock** on "another device": you need both the master password **AND** the
   Secret Key. Without both, the vault is unreadable.

The same `crypto-core` will power the full web app and the Chrome extension.
