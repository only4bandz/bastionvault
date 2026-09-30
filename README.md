# 🔐 Bastion — zero-knowledge password manager

A **zero-knowledge** password manager written in Rust: the server never sees
your master password or a single secret in plaintext. All encryption happens
client-side. One shared, test-covered crypto core (Rust → WASM) powers **two surfaces**: a
**web app** (React + TypeScript) and a **Chrome extension** (MV3) — plus
**Bastion Send**, end-to-end encrypted notes between users.

[![ci](https://github.com/only4bandz/bastionvault/actions/workflows/ci.yml/badge.svg)](https://github.com/only4bandz/bastionvault/actions/workflows/ci.yml)
[![security-audit](https://github.com/only4bandz/bastionvault/actions/workflows/security-audit.yml/badge.svg)](https://github.com/only4bandz/bastionvault/actions/workflows/security-audit.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## About this project

I built Bastion mainly for my own use: I wanted a password manager whose
security model I could read, test, and fully understand, from the key
derivation up to the browser extension. Rather than keep it to myself, I am
giving it away for free to anyone who might find it interesting or useful:
read it, learn from it, run it, fork it, or build on it.

> **Project status:** Bastion is no longer under active development. What is
> here works and is tested, but the remaining roadmap items are not planned,
> and issues or pull requests may not get a timely answer. It is shared as-is
> under the MIT license, with no warranty, and it has not been independently
> audited (see below). Review it yourself before trusting it with real secrets.
> You are very welcome to fork it and take it further.

> **Audit status:** the repository has extensive deterministic, integration,
> and WebAssembly tests plus internal security review artifacts. It has not yet
> undergone an independent third-party security audit. The frozen
> [audit scope](docs/security-audit-scope.md) and
> [signed release gate](docs/independent-audit-release-gate.md) are ready for an
> external auditor; they do not constitute an audit result.

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
- Browser WASM rejects attacker-supplied Argon2 parameters above 128 MiB,
  6 passes, or parallelism 4 before attempting derivation; native tooling keeps
  a larger compatibility ceiling.
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
  For verified contacts, sender discovery and pinned signature verification
  stay inside WASM; a failed pin releases no note plaintext to JavaScript.
- The identity and verified contacts live as **encrypted reserved vault items**,
  so they **sync across surfaces** (verify a contact in the extension, it's
  verified in the web app too).
- Server-side: strict public-key/envelope routing validation, per-recipient
  inbox quotas, per-sender-recipient and aggregate-recipient token-bucket rate
  limits with strictly bounded state, size caps, message dedupe, bounded expiry,
  and **read-once delete** — all without learning any plaintext. Account
  creation and login are also globally, per trusted source, and per-account
  rate-limited before any server-side Argon2 work begins.

Design + threat model: [`docs/bastion-send-design.md`](docs/bastion-send-design.md).

## Structure

```
crates/crypto-core/   Crypto core, pure Rust (forbids unsafe). Native + WASM. Includes Bastion Send (send.rs).
crates/crypto-wasm/   wasm-bindgen bindings (vault + Send) consumed by both surfaces.
crates/server/        Zero-knowledge Axum API + SQLite persistence (accounts, vault, BIN proxy, Send).
app/                  Web app — React + TypeScript (Vite). Unlock, vault, generator, health, Send.
extension/            Chrome extension (MV3) — background worker owns the vault key; CSP-safe popup.
web/                  Original standalone WASM demo (encrypt/decrypt in the browser).
docs/                 Design docs, ADRs, and the production, mail, and audit runbooks.
scripts/              Validation gates, CI guards, and release/audit tooling.
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

The canonical HTTP API is namespaced under `/v1`. Unversioned routes remain as
a temporary compatibility surface and return `Deprecation: true` plus a
successor-version link. Production registration requires a short-lived mailbox
proof before any account row is created. That proof is registration-only: email
is never vault recovery, decryption, deletion, or human-identity authority.

SQLite runs in WAL mode with `synchronous=FULL`. A successful mutation is not
acknowledged until SQLite has requested a WAL sync for that commit, protecting
acknowledged writes across process/OS crashes and power loss to the extent that
the host filesystem and storage honor SQLite's sync requests. This is a local
durability guarantee, not a substitute for tested backups or replication.

The schema is migrated transactionally through SQLite `user_version`; this
binary supports schema version 5 and refuses newer databases. Foreign keys are
enabled and checked at startup. Create a coherent snapshot of a live database
without replacing any existing file with:

```bash
cargo run -p server --bin bastion-backup -- /secure/bastion.db /secure/backups/bastion.db
```

The backup command uses SQLite's online backup API, validates integrity,
foreign keys and schema version, fsyncs the owner-only snapshot, and publishes
it with no-clobber semantics. A snapshot still contains sensitive account
metadata and verifier material: encrypt it before off-host transfer. The
repository validates the complete live-backup/restore path with
`bash scripts/test-backup-restore.sh`; an environment-specific scheduler,
retention policy and recurring RPO/RTO drill are still required for production.

The current server is intentionally **single-instance per database**. It holds
an advisory `<database>-server.lock` for its full lifetime and refuses to start
a second Bastion server against the same SQLite file. This is required because
the account read cache, sessions, and rate-limit counters are process-local.
The server serializes synchronous `rusqlite` operations through one dedicated
storage thread behind a bounded command queue. Storage latency therefore does
not block Tokio executor threads; queue saturation fails fast and a delayed
accepted mutation is completed under its logical cache lock before the
instance re-opens storage admission. Only loss of the storage worker causes
permanent quarantine. Rate counters use separate bounded locks and never share
the account/session cache lock. `/livez` remains independent of storage, while
`/readyz` and the legacy `/health` route fail closed on storage faults. Do not
deploy multiple replicas or treat this backend as production-scale. The
database must live on a local filesystem with reliable advisory locks and sync
semantics; network and distributed filesystems are unsupported. Stop the server
for filesystem-level copies, or use a SQLite-aware backup tool that respects
the live database and WAL.

The accepted initial production direction remains single-instance and keeps
SQLite on local persistent storage behind a same-origin TLS ingress. It targets
a 15-minute RPO and a 60-minute RTO, subject to measured capacity and verified
restore drills. Horizontal replicas require a new shared-storage design; a
shared SQLite volume or removal of the exclusive lock is explicitly rejected.
See [ADR 0001](docs/adr/0001-production-topology-and-slos.md) for the topology,
service objectives, decision gates, and remaining production blockers.

The production operations gate is defined in
[`docs/production-operations.md`](docs/production-operations.md). The
`bastion-ops-status` binary emits a read-only, aggregate JSON snapshot without
account identifiers, tokens, bodies, routing ids, or ciphertext fields. Release
fault tests run with `bash scripts/test-operational-failures.sh`; deployed edge,
capacity, live backup, and readiness evidence is collected with
`scripts/verify-production-operations.sh`. Destructive host/disk/provider drills
remain restricted to isolated staging or restored copies.

Schema version 3 also contains a durable transactional-mail outbox. Its worker
leases mail outside the request path, releases SQLite before network I/O, uses
authenticated mandatory-STARTTLS SMTP, retries transient failures with bounded
backoff, and scrubs message data after delivery or terminal failure. Delivery
is at least once: a crash after relay acceptance can cause a duplicate with the
same `Message-ID`. SMTP settings and the provider acceptance gate are documented
in [`docs/transactional-mail-outbox.md`](docs/transactional-mail-outbox.md).
Schema version 4 adds pre-registration mailbox challenges without reserving an
account identifier; the complete protocol and threat boundary are documented
in [`docs/mailbox-verification.md`](docs/mailbox-verification.md).
Schema version 5 canonicalizes every ASCII account identifier to lowercase
across accounts, mailbox proofs, vault rows, Send ownership, mail ownership,
sessions, rate-limit buckets, ETags, and browser rollback-checkpoint scopes.
The migration is atomic and refuses to merge case-colliding historical vaults.
Run the read-only aggregate preflight before deployment:

```bash
python3 scripts/check-account-id-migration.py /var/lib/bastion/bastion.db
```

The command never prints account identifiers. Any non-zero collision count
blocks rollout and requires explicit private-data remediation; do not delete,
rename, or merge a vault automatically.

Production mode fails closed unless Axum is loopback-only, SQLite uses an
absolute path, and one canonical HTTPS public origin is declared. Proxied API
requests must preserve that public Host and carry the ingress-owned
`X-Forwarded-Proto: https` plus one canonical client IP in `X-Forwarded-For`;
CORS remains disabled. The complete ingress and certificate-renewal contract is
in
[`docs/production-edge-contract.md`](docs/production-edge-contract.md).

```bash
BASTION_ENV=production \
BIND_ADDR=127.0.0.1:7777 \
BASTION_DB=/var/lib/bastion/bastion.db \
BASTION_PUBLIC_ORIGIN=https://vault.example.com \
BASTION_SMTP_HOST=smtp.example.com \
BASTION_SMTP_PORT=587 \
BASTION_SMTP_USERNAME=bastion \
BASTION_SMTP_PASSWORD=replace-with-secret-injection \
BASTION_MAIL_FROM='Bastion <no-reply@example.com>' \
cargo run -p server

# Run against the deployed ingress, not the loopback listener.
bash scripts/verify-production-edge.sh https://vault.example.com
```

| Method | Route | Role |
|---|---|---|
| `GET` | `/v1/config` | Returns public client policy, including whether mailbox proof is required |
| `GET` | `/v1/livez` · `/v1/readyz` | Process liveness without storage · SQLite-backed routing readiness |
| `POST` | `/v1/registration-challenges` · `/v1/registration-challenges/verify` | Queue/rotate a bounded proof link · confirm an unexpired mailbox proof |
| `POST` | `/v1/accounts` | Consumes production mailbox proof and creates an account (stores `salt`, `kdf`, wrapped key, secret hash) |
| `DELETE` | `/v1/accounts` | Permanently deletes owned state; requires a session plus fresh `auth_secret` proof |
| `GET` | `/v1/accounts/:email/prelogin` | Returns `salt`+`kdf`+wrapped key (to derive client-side) |
| `POST` / `PUT` / `DELETE` | `/v1/sessions` | Login / idempotent bearer rotation / revoke current session family |
| `DELETE` | `/v1/sessions/all` | Revoke every active session for the authenticated account |
| `GET` | `/v1/vault` | Encrypted items + manifest + CAS revision (auth); supports opaque account-scoped `ETag` / `If-None-Match` revalidation |
| `GET` | `/v1/vault/revision` | Cheap authenticated freshness probe; changed revisions still require a full verified fetch |
| `PUT` | `/v1/vault/transaction` | Atomically apply item operations + sealed manifest at an expected revision |
| `PUT`/`DELETE` | `/v1/vault/items/:id` | Development-only deprecated compatibility endpoint; not registered in production |
| `PUT` | `/v1/vault/manifest` | Development-only deprecated compatibility endpoint; not registered in production |
| `PUT` | `/v1/send/identity` | Publish a Send identity once (identical retries allowed) → stable Bastion address |
| `GET` | `/v1/send/whoami` · `/v1/send/directory/:id` | Your address · resolve a contact (exact-match, rate-limited) |
| `POST` `/v1/send` · `GET` `/v1/send/inbox` · `DELETE` `/v1/send/inbox/:id` | Validate and deliver / pull / read-once delete an opaque blob (explicit expiry ≤ 7 days) |

```bash
cargo run -p server          # listens on http://127.0.0.1:7777
```

## Roadmap

This table records where the project stopped. Unchecked items are ideas, not
commitments.

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
| 10 | Bastion Send polish (QR address, unread counts) | 🚧 Partial, not planned |
| 11 | Encrypted folders · restorable trash · k-anonymous password breach scan | ✅ Done |
| 12 | Email masking relay/provider integration | ⬜ Architecture decision required |
| 13 | TOTP 2FA · FIDO2 / WebAuthn keys | ⬜ |
| 14 | iOS / Android apps | ⬜ |

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

# every gate CI runs, in one command
bash scripts/verify-all.sh
```

Toolchain: Rust 1.91 with the `wasm32-unknown-unknown` target, `wasm-pack`
0.13.1, and Node.js 22.

> ⚠️ The server is **not production-ready** until the documented TLS ingress,
> real-provider mailbox, off-host backup, alert-delivery, capacity, and
> deployment-specific RPO/RTO/failure drills have recorded evidence. The
> stateful controls remain process-local; the exclusive
> instance lock and isolated SQLite owner reject horizontal replicas rather
> than making them safe.

## Contributing

The project is not actively maintained, so the best way to build on it is to
fork it. Issues and pull requests are still open, but a response is not
guaranteed. If you do send a pull request, run `bash scripts/verify-all.sh`
first and make sure every gate passes.

Please do not report vulnerabilities in public issues. Follow
[`SECURITY.md`](SECURITY.md) instead.

## License

Bastion is released under the [MIT License](LICENSE). Bundled third-party
fonts and data keep their own licenses, listed in
[`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md).
