# Bastion — web app

The Bastion vault UI: a React + Vite + TypeScript front end on top of the
zero-knowledge `crypto-core` (compiled to WebAssembly). All cryptography runs in
the browser; secrets live in WASM memory only and never touch browser storage
(enforced by `scripts/check-no-browser-secret-storage.sh`).

## Run

```bash
rustup target add wasm32-unknown-unknown          # once
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh   # once

./build-wasm.sh        # compile crypto-core → src/pkg (gitignored)
npm install
npm run dev            # http://localhost:5173
```

## What works today

- **Onboarding**: create a vault from a master password → one-time **Secret Key**
  + printable Emergency Kit (the two-secret model).
- **Unlock / auto-lock**: master password + Secret Key; auto-locks on inactivity
  and when the tab is hidden (`Account.lock()` zeroizes the vault key).
- **Vault**: create/edit/delete items (logins, secure notes, cards), search,
  type tabs, copy-to-clipboard with reveal.
- **Password Generator** (browser CSPRNG) and **Password Health** (weak/reused).

## Next

- Wire to the Axum server (`crates/server`) for encrypted, multi-device sync.
- Folders, sharing, breach scanner, email masking.
