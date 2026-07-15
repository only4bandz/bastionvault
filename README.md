# 🔐 Bastion — zero-knowledge password manager

A **zero-knowledge** password manager written in Rust: the server never sees
your master password or a single secret in plaintext. All encryption happens
client-side. One audited crypto core (Rust → WASM) powers **two surfaces**: a
**web app** (React + TypeScript) and a **Chrome extension** (MV3) — plus
**Bastion Send**, end-to-end encrypted notes between users.

## Security model

```
master password ──Argon2id(salt, 64MiB)──► master key
                                              │
            Secret Key (128-bit, user) ──────►│ HKDF-Extract (salt)
                                              │
                          ┌──────HKDF─────────┼──────HKDF──────┐
                          ▼                                    ▼
                     wrap key                            auth secret ──► server
                          │                              (proves identity,
                          │ wraps                         decrypts nothing)
                          ▼
        vault key (random 256-bit) ──encrypts──► all items
```

- **Argon2id** (64 MiB, 3 passes) protects against offline brute-force.
- **Secret Key** (128 bits, 1Password model): a second factor held by the user,
  mixed in as an HKDF salt. Offline brute-force becomes infeasible **even with a
  weak password** — the server never sees it. Shown once via an **Emergency
  Kit**, re-entered on each device.
- **XChaCha20-Poly1305** encrypts each item (AEAD, random 192-bit nonce).
- The **vault key** is random and *wrapped*: changing the master password does
  not re-encrypt every item.
- **Integrity manifest**: an index encrypted under the vault key lists the
  digest of each item. On sync, it detects whether a malicious server has
  deleted, injected, or rolled back an item (which per-item AEAD alone cannot
  catch). A monotonic `seq` counter blocks manifest rollback relative to the
  latest trusted state. The web client and extension persist only a non-secret
  rollback checkpoint (server revision, manifest sequence, and manifest
  SHA-256), scoped to the account and API origin, so the guarantee survives a
  browser restart.
  Checkpoints are compared and advanced under a cross-tab lock and are never
  cleared automatically. Trusting a verified recovery snapshot requires the
  explicit reset of the relevant client storage. Legacy vaults without a
  manifest use one explicit trust-on-first-use bootstrap after every encrypted
  item validates.
- Browser vault mutations publish local plaintext state only after a successful
  CAS response or a fresh authenticated snapshot that exactly matches the
  prepared next revision. Every other ambiguous result locks the vault.
- The server only stores **opaque blobs** + a slow hash of the auth secret. A
  server breach reveals no passwords.

## ✉️ Bastion Send — end-to-end encrypted notes

Send a note that **only the chosen recipient can open** — the server stores
ciphertext only and never sees who can read it. Each user gets a stable,
non-enumerable **Bastion address** (128-bit, base32). Available in both the
**extension** and the **web app**.

- **Sealed box** to the recipient's **X25519** key + **Ed25519** sign-then-encrypt,
  so the recipient can cryptographically verify the sender (or send anonymously).
- Optional **extra passphrase** folded into the key derivation (a true second
  factor — the server can't run a dictionary attack on it).
- **Safety number** (60 digits, Signal-style): compare it out-of-band to pin a
  contact and defeat a malicious directory. Trust is shown explicitly —
  **Verified ✓ / Unverified / Anonymous**, and a **key-change** is flagged.
- The identity and verified contacts live as **encrypted reserved vault items**,
  so they **sync across surfaces** (verify a contact in the extension, it's
  verified in the web app too).
- Server-side: strict public-key/envelope routing validation, per-recipient
  inbox quotas, fixed-window rate limits with strictly bounded state, size
  caps, message dedupe, bounded expiry, and **read-once delete** — all without
  learning any plaintext. Account creation and login are also globally and
  per-account rate-limited before any server-side Argon2 work begins.

Design + threat model: [`docs/bastion-send-design.md`](docs/bastion-send-design.md).

## Structure

```
crates/crypto-core/   Crypto core, pure Rust (forbids unsafe). Native + WASM. Includes Bastion Send (send.rs).
crates/crypto-wasm/   wasm-bindgen bindings (vault + Send) consumed by both surfaces.
crates/server/        Zero-knowledge Axum API + SQLite persistence (accounts, vault, BIN proxy, Send).
app/                  Web app — React + TypeScript (Vite). Unlock, vault, generator, health, Send.
extension/            Chrome extension (MV3) — background worker owns the vault key; CSP-safe popup.
web/                  Original standalone WASM demo (encrypt/decrypt in the browser).
docs/                 Design docs (Bastion Send spec + UI implementation plan).
```

### Server — endpoints

Zero-knowledge: stores only opaque blobs + an **Argon2id hash** of the auth
secret (never the raw secret), persisted to **SQLite**. Reuses the types from
`crypto-core`. Persisted Send identities, routing fields, envelopes, and
timestamps are revalidated on read; corruption fails the request instead of
returning partial or synthetic data. Persisted account identifiers, KDFs,
wrapped keys, and bounded Argon2id credential hashes are validated before the
server begins serving traffic. On Unix, the database and its WAL/SHM sidecars
are forced to owner-only `0600`; symbolic-link artifacts and database parents
or ancestors writable by group or others are rejected before SQLite opens the
file (sticky temporary directories remain supported). Database artifacts with
hard links are also rejected so an alternate pathname cannot bypass the
owner-only mode.

| Method | Route | Role |
|---|---|---|
| `POST` | `/accounts` | Creates an account (stores `salt`, `kdf`, wrapped key, secret hash) |
| `GET` | `/accounts/:email/prelogin` | Returns `salt`+`kdf`+wrapped key (to derive client-side) |
| `POST` / `DELETE` | `/sessions` | Login (Argon2id) → bearer token (TTL 30 min) / logout |
| `GET` | `/vault` | Encrypted items + manifest + CAS revision (auth) |
| `PUT` | `/vault/transaction` | Atomically apply item operations + sealed manifest at an expected revision |
| `PUT`/`DELETE` | `/vault/items/:id` | Deprecated compatibility endpoint; use `/vault/transaction` |
| `PUT` | `/vault/manifest` | Deprecated compatibility endpoint; use `/vault/transaction` |
| `PUT` | `/send/identity` | Publish/rotate a Send identity → stable Bastion address |
| `GET` | `/send/whoami` · `/send/directory/:id` | Your address · resolve a contact (exact-match, rate-limited) |
| `POST` `/send` · `GET` `/send/inbox` · `DELETE` `/send/inbox/:id` | Validate and deliver / pull / read-once delete an opaque blob (explicit expiry ≤ 7 days) |

```bash
cargo run -p server          # listens on http://127.0.0.1:7777
```

## Roadmap

| # | Step | Status |
|---|-------|------|
| 1 | Crypto core (Argon2id, KDF policy, AEAD, key wrapping) | ✅ Done |
| 2 | Secret Key (two-secret) + Emergency Kit | ✅ Done |
| 3 | Vault integrity manifest | ✅ Done |
| 4 | WASM bindings + browser demo | ✅ Done |
| 5 | Axum server API (accounts, encrypted storage) | ✅ Done |
| 6 | Server persistence (SQLite) | ✅ Done |
| 7 | Web app (vault, generator, health, import, card/BIN detection) | ✅ Done |
| 8 | Chrome extension (autofill, save-on-signup, keep-unlock) | ✅ Done |
| 9 | **Bastion Send** — E2E notes (crypto, server, both UIs) | ✅ Done |
| 10 | Bastion Send polish (QR address, unread counts) | 🚧 In progress |
| 11 | TOTP 2FA · FIDO2 / WebAuthn keys | ⬜ |
| 12 | iOS / Android apps | ⬜ |

## Development

```bash
# crypto core + server
cargo test --workspace                       # native tests
wasm-pack test --node crates/crypto-wasm     # WASM tests (browser entropy)
cargo run -p server                          # zero-knowledge API on :7777

# web app (React + TS)
cd app && bash build-wasm.sh && npm install && npm run dev

# Chrome extension (MV3)
cd extension && ./build.sh                   # build the WASM module
# then load `extension/` unpacked at chrome://extensions
```

> ⚠️ The server is **not production-ready** (no TLS/CORS, and its bounded rate
> limits are process-local rather than coordinated across instances). It's a
> zero-knowledge reference backend for development.
