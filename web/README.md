# Browser demo — zero-knowledge vault in WASM

A small page that runs the cryptographic core (`crypto-core`) **in the
browser**, compiled to WebAssembly via `crypto-wasm`. All encryption happens
client-side; the "Server" panel only shows opaque blobs.

## Run

```bash
# 1. Prerequisites (once)
rustup target add wasm32-unknown-unknown
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh

# 2. Build the WASM module (generates web/pkg/, which is gitignored)
./web/build.sh

# 3. Serve it (ES modules require http://, not file://)
cd web && python3 -m http.server 8080
# then open http://localhost:8080
```

## What the demo shows

1. **Create the vault** from a master password → the **Secret Key** is displayed
   (shown once) + the Emergency Kit.
2. **Encrypt items**: they go to the "server" only in encrypted form — visible in
   the right-hand panel.
3. **Unlock** on "another device": you need both the master password **AND** the
   Secret Key. Without both, the vault is unreadable.

The same `crypto-core` powers the full web app ([`app/`](../app)) and the
Chrome extension ([`extension/`](../extension)).

## Browser isolation

The demo loads JavaScript and CSS only from external same-origin files. Its CSP
allows same-origin modules and the minimum `wasm-unsafe-eval` capability needed
to compile WebAssembly, while refusing inline script/style, JavaScript eval,
objects, base-tag changes, and form submission. Dynamic status and recovery-key
content is inserted with `textContent`, never as HTML. The invariant is enforced
by `scripts/check-web-demo-csp.sh` in the `web-guards` workflow.

## Invariant — no browser-side secret storage

Secrets live in WASM memory only, and only as briefly as possible (the demo
auto-locks on inactivity / tab-hide; the Secret Key is revealed one-shot). The
app must **never** persist secrets to `localStorage`, `sessionStorage`,
`IndexedDB`, or cookies — these are trivially readable by an infostealer or an
XSS payload. This is enforced in CI by
[`scripts/check-no-browser-secret-storage.sh`](../scripts/check-no-browser-secret-storage.sh)
(workflow `web-guards`), which fails the build if such an API appears in `web/`
app code. A non-secret value that genuinely needs persistence can opt out with a
`storage-guard:allow` comment on the line — never for secret-derived data.
