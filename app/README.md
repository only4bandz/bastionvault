# Bastion — web app

The Bastion vault UI: a React + Vite + TypeScript front end on top of the
zero-knowledge `crypto-core` (compiled to WebAssembly). Cryptographic key
operations run in WASM, but decrypted items necessarily enter JavaScript and
React memory while the vault is unlocked. Secrets are never persisted to
browser storage (enforced by `scripts/check-no-browser-secret-storage.sh`).

Vault items are exposed only after the encrypted integrity manifest matches the
complete server response. Existing vaults receive a one-time trust-on-first-use
manifest after every encrypted payload decrypts and validates. The trusted
manifest sequence and revision are anchored as non-secret metadata in browser
storage, so later sessions reject rollback and same-sequence substitution for
the same server/account scope.

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
- **Vault**: create/edit items (logins, secure notes, cards), encrypted folders,
  restorable trash, search, type tabs, copy-to-clipboard with reveal.
- **Password Generator** (browser CSPRNG) and **Password Health** (weak/reused).
- **Data Breach Scanner**: explicit, in-memory Pwned Passwords checks using
  padded k-anonymous range requests; plaintext and full hashes never leave the
  browser.

## Next

- Email masking requires a separately reviewed alias/forwarding provider or
  Bastion-operated mail relay; plus-addressing is not treated as masking.
