# Security policy

## Supported versions

Bastion is pre-1.0 software and is no longer under active development. Any
security fix lands on the latest commit of `main` only, on a best-effort basis
with no guaranteed response time; older commits and self-built historical
releases are not supported.

The server is currently a development/reference backend and is not approved
for Internet-facing production use. See the production-readiness warning in
the project README.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Submit a private
report through [GitHub Security Advisories](https://github.com/only4bandz/bastionvault/security/advisories/new)
with:

- the affected commit and component;
- reproduction steps or a minimal proof of concept;
- the expected and observed security boundary;
- known impact and any suggested remediation.

If private vulnerability reporting is unavailable, contact the repository
owner through an established private channel before disclosing details.
Maintainers will coordinate validation, remediation, and disclosure with the
reporter. Please avoid accessing other users' data, degrading availability, or
testing against infrastructure you do not own.

## Hardening posture

Beyond the zero-knowledge core (client-side Argon2id + Secret-Key key
derivation, XChaCha20-Poly1305 blobs, vault manifests with rollback anchors),
the clients and server enforce the following defensive layers. Each item links
the pull request that introduced or last changed it.

**Key derivation and account identity**

- The client refuses server-supplied Argon2id parameters below the policy
  floor before deriving anything, defeating KDF-downgrade credential
  harvesting by a compromised server (#193).
- Account emails are canonicalized (trimmed, lowercased) before every server
  call — one vault per mailbox regardless of typing (#203).
- Unknown accounts receive a deterministic, secret-keyed decoy from
  `/prelogin`; the endpoint no longer functions as an account-enumeration
  oracle, complementing the constant-cost dummy hash on login (#204).
- Vault creation offers an opt-in k-anonymous breach check of the master
  password (5-character SHA-1 prefix, padded responses) (#206).

**Session and secret lifecycle in the browser**

- Auto-lock: 10 minutes idle, 30 seconds hidden, immediate on server-side
  session expiry. Locking zeroizes the WASM vault key and clears plaintext
  state.
- Back/forward-cache snapshots are locked on entry and on restore, so the
  Back button can never resurrect an unlocked vault (#199).
- A pending copied secret is wiped from the OS clipboard the moment the vault
  locks, not 30 seconds later (#198); routine secret copies self-clear after
  30 seconds.
- Revealed secrets conceal on tab hide; the Secret Key Emergency Kit collapses
  the same way (#201). Print output suppresses all vault content (#179).
- Secret inputs force `spellcheck`/`autocorrect`/`autocapitalize` off so
  revealed values never reach cloud spell-checkers or keyboard dictionaries
  (#197); vault search applies the same posture plus `autocomplete="off"`
  (#207).
- Closing the tab while a vault mutation awaits server confirmation prompts
  for confirmation (#202). Parsed CSV plaintext is dropped from memory as soon
  as an import completes (#200).

**Transport and content policies**

- API fetches never follow redirects, never send ambient credentials, are
  never cached, and send no referrer (#195).
- The web app ships a strict CSP with no `unsafe-inline` styles in production
  (#205); the API stamps `default-src 'none'` CSP, `Permissions-Policy`,
  COOP/CORP, and legacy lockdown headers on every response (#196), plus
  `Retry-After` on rate-limited responses (#209).
- Extension pages run under `object-src 'none'; base-uri 'none';
  form-action 'none'; frame-ancestors 'none'` (#211). Autofill is gated by
  sender-frame origin checks and refused on insecure pages; suggestion UI
  lives in a closed shadow root.
- CSV exports neutralize spreadsheet formula injection; imports strip exactly
  the guard prefix so Bastion exports round-trip losslessly (#194).

**Supply chain and enforcement**

- CI runs the full Rust/app/extension test matrix, rustfmt, clippy
  (`-D warnings`), CSP guards, and browser-secret-storage guards on every PR.
- A scheduled workflow audits `Cargo.lock` against the RustSec database and
  the app's npm tree for known-vulnerability advisories weekly and on every
  change (#208).

## Scope and audit status

Security-sensitive components include `crypto-core`, the WASM boundary, vault
integrity and rollback handling, the Axum/SQLite server, the web application,
the browser extension, and Bastion Send.

The repository contains deterministic vectors, integration tests, WebAssembly
tests, and internal security-review artifacts. It has not yet undergone an
independent third-party security audit. The frozen scope, deterministic source
bundle, signed attestation format, and fail-closed release procedure are defined
in [`docs/security-audit-scope.md`](docs/security-audit-scope.md) and
[`docs/independent-audit-release-gate.md`](docs/independent-audit-release-gate.md).
These controls prepare and verify third-party evidence; their presence is not
an audit claim.
