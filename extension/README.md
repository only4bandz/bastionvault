# Bastion — Chrome extension (Manifest V3)

A browser extension front-end for the **Bastion** zero-knowledge password
manager. It reuses the exact same audited Rust crypto core as the web app
(`crates/crypto-core` → WebAssembly), so encryption/decryption behaves
identically everywhere. The sync server only ever sees opaque encrypted blobs.

## How it's built

No bundler. The pieces are native ES modules and load unpacked as-is:

| File | Role |
|---|---|
| `manifest.json` | MV3 manifest (popup, module service worker, options) |
| `background.js` | **Service worker** — the only place the vault is decrypted. Holds the unlocked session (WASM `Account` + token + decrypted items) **in memory only**, runs all server calls, enforces auto-lock via `chrome.alarms`. |
| `popup.js` / `popup.html` / `popup.css` | The vault UI: unlock, search, "on this site" suggestions, copy username/password, one-click fill. |
| `options.js` / `options.html` | Configure the sync-server URL. |
| `lib/api.js` | Client for the zero-knowledge sync server. |
| `pkg/` | Generated — `crypto-wasm` compiled to WASM (gitignored). |
| `icons/` | Generated PNGs from `icons/icon.svg` (gitignored). |

## Security model

- The vault is **decrypted only inside the service worker**, in WASM memory.
  Nothing secret is ever written to `chrome.storage`, `localStorage`,
  IndexedDB or cookies (the same anti-stealer rule the web app enforces in CI).
- When Chrome evicts the service worker, the unlocked session can be rehydrated
  from extension-private, RAM-backed `chrome.storage.session` until its bounded
  expiry. It is never written to disk and is removed on lock.
- **Auto-lock** after 10 minutes of inactivity, and immediately when the OS
  session locks (`chrome.idle`).
- Two autofill paths: (1) **inline** — a content script shows a dropdown of
  matching accounts under a login field; on pick it fetches just that
  credential (`CREDS`) and fills the page DOM directly. The background only
  hands out non-secret metadata (`SUGGEST`) until the user explicitly picks an
  account. (2) **from the popup** — the *Fill* button injects a one-shot fill
  function into the active tab via `chrome.scripting` (`activeTab`).
- Credential release is bound to the same registrable domain (Public Suffix
  List aware). Distinct domains are never treated as equivalent implicitly.
- Cross-origin calls to the server are made from the worker under
  `host_permissions`, so no CORS relaxation is needed on the server.
- Remote server origins must use HTTPS. Plain HTTP is accepted only for the
  built-in `localhost` and `127.0.0.1` development origins.

## Build & load

```bash
cd extension
./build.sh                      # builds pkg/ (WASM) + icons/*.png
```

Then in Chrome:

1. Make sure your Bastion server is running: `cargo run -p server` (listens on
   `http://127.0.0.1:7777`, the default).
2. Open `chrome://extensions`, enable **Developer mode**, click **Load
   unpacked**, and select this `extension/` folder.
3. Click the Bastion icon → unlock with your email, master password and Secret
   Key (create the vault first in the Bastion app if you don't have one).

To point at a different server, open the extension's **options** page and set
the URL (you'll be asked to grant access to that host).

## Status

v0.1 — unlock, browse/search, copy, autofill. Creating a vault and editing
items are still done in the Bastion web app; the extension is read-and-fill for
now. Roadmap: in-popup item editing, generator, and a Firefox build.
