# Bastion — web app

The Bastion vault UI: a React + Vite + TypeScript front end on top of the
zero-knowledge `crypto-core` (compiled to WebAssembly). All cryptography runs in
the browser; secrets live in WASM memory only and never touch browser storage
(enforced by `scripts/check-no-browser-secret-storage.sh`).

Vault items are exposed only after the encrypted integrity manifest matches the
complete server response. Existing vaults receive a one-time trust-on-first-use
manifest after every encrypted payload decrypts and validates. The trusted
manifest sequence lives only in memory: rollback is detected within an unlocked
session, but not across a complete browser restart without an independent
persistent checkpoint.

The document CSP denies all resources by default. It permits same-origin
scripts, API calls, fonts and images plus the minimum `wasm-unsafe-eval`
capability required to compile WebAssembly. JavaScript eval and inline scripts
remain forbidden. Inline styles are temporarily allowed because the current
React components use style props; this exception does not permit script
execution. `scripts/check-app-csp.sh` enforces these directives in CI.

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
