# 🔐 Password manager (zero-knowledge)

A **zero-knowledge** password manager written in Rust: the server never sees
your master password or a single secret in plaintext. All encryption happens
client-side. Designed for a web app today, and a **Chrome extension** later —
both share the same crypto core (Rust → WASM).

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
  catch). A monotonic `seq` counter blocks rollback of the manifest itself.
- The server only stores **opaque blobs** + a slow hash of the auth secret. A
  server breach reveals no passwords.

## Structure

```
crates/crypto-core/   ✅ Crypto core, pure Rust, 32 tests. Compiles native + WASM.
crates/crypto-wasm/   ✅ wasm-bindgen bindings + wasm32 test (entropy validated).
web/                  ✅ Browser demo (encrypt/decrypt in WASM). See web/README.md
crates/server/        ✅ Zero-knowledge Axum API: accounts + encrypted blobs (in-memory, MVP)
```

### Server — endpoints

Zero-knowledge: stores only opaque blobs + an **Argon2id hash** of the auth
secret (never the raw secret). Reuses the types from `crypto-core`.

| Method | Route | Role |
|---|---|---|
| `POST` | `/accounts` | Creates an account (stores `salt`, `kdf`, wrapped key, secret hash) |
| `GET` | `/accounts/:email/prelogin` | Returns `salt`+`kdf`+wrapped key (to derive client-side) |
| `POST` | `/sessions` | Verifies the auth secret (Argon2id, `spawn_blocking`) → bearer token (TTL 30 min) |
| `DELETE` | `/sessions` | Revokes the current token (logout) |
| `GET` | `/vault` | Encrypted items + manifest (auth) |
| `PUT`/`DELETE` | `/vault/items/:id` | Upsert / deletion of an encrypted item (auth) |
| `PUT` | `/vault/manifest` | Stores the integrity manifest (auth) |

```bash
cargo run -p server          # listens on http://127.0.0.1:7777
```

## Roadmap

| # | Step | Status |
|---|-------|------|
| 1 | Crypto core (Argon2id, KDF policy, AEAD, key wrapping) | ✅ Done |
| 2 | Secret Key (two-secret) + Emergency Kit | ✅ Done |
| 3 | Vault integrity manifest | ✅ Done |
| 4 | WASM bindings + browser demo (entropy validated) | ✅ Done |
| 5 | Axum server API (accounts, encrypted storage) — in-memory MVP | ✅ Done |
| 6 | Server persistence (SQLite) + full web interface | ⬜ |
| 7 | TOTP 2FA (authenticator) | ⬜ |
| 8 | FIDO2 / WebAuthn keys (YubiKey, Trustkey) | ⬜ |
| 9 | SMS verification | ⬜ |
| 10 | Chrome extension (reuses crypto-core via WASM) | ⬜ |

## Development

```bash
cargo test --workspace                       # native tests (crypto core)
wasm-pack test --node crates/crypto-wasm     # WASM tests (browser entropy)
./web/build.sh                               # build the demo's WASM module
cd web && python3 -m http.server 8080        # serve the demo → http://localhost:8080
```
