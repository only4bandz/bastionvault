# Independent security audit scope

## Objective and frozen target

The audit determines whether one exact Bastion commit is suitable to proceed
to a controlled production release under
[ADR 0001](adr/0001-production-topology-and-slos.md). The auditor receives a
deterministic source bundle whose manifest binds every tracked file to SHA-256,
the Git commit, and the Git tree.

The audit is invalid for any other commit or tree. A remediation that changes
source, dependency locks, configuration, documentation, tests, or build scripts
requires a new bundle and independent retest of the resulting commit.

The release gate requires an organization and lead reviewer who did not design
or implement the audited release and who disclose financial, employment, and
delivery conflicts. Maintainer self-review, model review, ordinary PR review,
and prior design feedback are useful inputs but are not independent audit
evidence.

## System and trust boundaries

Bastion consists of:

- `crypto-core`, the Rust cryptographic and serialization authority;
- `crypto-wasm`, the WASM boundary used by browser surfaces;
- the React web application;
- the Chrome MV3 extension, including background ownership and autofill;
- the Axum server, isolated SQLite owner, and process-local security state;
- vault integrity/rollback checkpoints and compare-and-swap mutations;
- Bastion Send identities, directory, encrypted envelopes, and trust UX;
- the transactional mail outbox and registration-only mailbox proof;
- production TLS/origin, backup/restore, operations, and release tooling.

The server is zero-knowledge for vault and Send plaintext, not metadata-free.
It sees account identifiers, password-verifier material, opaque payload sizes,
routing identifiers, timing, sessions, and mail delivery state. Backups and
operational access remain sensitive.

The initial production topology is exactly one server and one SQLite writer on
a local filesystem behind same-host TLS ingress. Shared SQLite, simultaneous
replicas, cross-origin browser credentials, plaintext public transport, and
email-based vault recovery are unsupported and must not be accepted as audit
remediations.

## Required coverage

The signed attestation must contain every identifier below.

### `cryptography-and-secret-lifecycle`

- Argon2id/HKDF domain separation, parameter floors/ceilings, entropy, nonce and
  key generation, AEAD associated data, serialization, and test vectors.
- Master password, Secret Key, vault key, auth secret, Send private keys, and
  passphrase lifetime/zeroization across native and browser execution.
- Offline attack consequences after server, database, backup, browser storage,
  or encrypted export compromise.
- Error paths that could return unauthenticated or partially verified plaintext.

### `wasm-javascript-boundary`

- All exported/imported values, secret copies, exception paths, memory lifetime,
  lock behavior, and plaintext release ordering.
- Pin-lock and verified-Send paths that must withhold all plaintext until WASM
  completes authentication and trust checks.
- Attacker-controlled KDF and payload sizes before expensive allocation/work.

### `web-application-and-browser-storage`

- Unlock, create, import/export, clipboard, auto-lock, rollback anchors,
  ambiguous writes, mailbox proof, and account deletion flows.
- XSS/CSP, URL handling, external requests, cache behavior, browser persistence,
  cross-tab coordination, and secret cleanup.
- Proof that vault secrets never enter localStorage, sessionStorage, IndexedDB,
  cookies, telemetry, or uncontrolled logs.

### `browser-extension-and-autofill`

- MV3 permissions/CSP, service-worker secret ownership, popup/offscreen message
  validation, lock behavior, and update/restart behavior.
- Exact top-level document, tab, frame, scheme, origin/site, and navigation
  binding before credential release.
- Public-suffix handling, staged usernames, clipboard cleanup, rollback anchors,
  and failures that must lock or withhold plaintext.

### `server-authentication-and-sessions`

- Registration/prelogin/login/delete authorization, Argon2 resource controls,
  enumeration/timing behavior, bearer-token entropy/lifetime/revocation, and
  session limits.
- Request/body validation, quotas, rate-limit bounds, cache/database ordering,
  corrupt-state startup/read behavior, and error/log redaction.
- Process-local security controls and the consequences of restart or attempted
  horizontal scaling.

### `sqlite-migrations-durability-and-backup`

- Single-owner lock, dedicated worker/backpressure, timeouts/quarantine,
  `synchronous=FULL`, WAL behavior, filesystem/link/permission checks, and
  transaction boundaries.
- Every migration from an empty/legacy schema through the audited schema,
  foreign keys, partial-failure behavior, and downgrade/rollback constraints.
- Online backup consistency, no-clobber publication, restore validation,
  sensitive artifact handling, RPO/RTO assumptions, and host-loss recovery.

### `vault-integrity-rollback-and-cas`

- Per-item AEAD, manifests, item-set completeness, sequence/revision monotonicity,
  trusted checkpoint scope and persistence, legacy trust-on-first-use, and
  explicit recovery-anchor reset.
- Concurrent and ambiguous mutations, stale snapshots, rollback/substitution,
  malicious server responses, and plaintext publication ordering.

### `bastion-send-and-trust-model`

- X25519/Ed25519 construction, identity binding, sign/encrypt ordering,
  passphrase mode, wire validation, recipient routing, deduplication, quotas,
  expiry, and deletion semantics.
- Directory substitution/key change, safety-number verification, verified,
  unverified, and anonymous UI states, and cross-surface trust synchronization.
- Malicious server/provider, compromised sender/recipient, replay, redirection,
  metadata leakage, and downgrade scenarios.

### `tls-origin-and-deployment-boundary`

- Production startup validation, loopback-only Axum, trusted forwarded metadata,
  exact Host/proto checks, HTTP redirect, HSTS, certificate renewal, same-origin
  API, disabled CORS, caching, and SPA verification-link routing.
- Ingress misconfiguration and the prohibition on exposing Axum or operational
  state directly.

### `transactional-mail-and-mailbox-proof`

- SMTP authentication/mandatory STARTTLS, timeouts, leasing, retry/backoff,
  crash ambiguity, stable message ids, terminal scrubbing, queue bounds, and
  operational observability without recipient leakage.
- Challenge entropy/hash, expiry, rotation, resend behavior, abuse controls,
  account-squatting prevention, verification/account-create atomicity, URL
  fragment handling, and grandfathered accounts.
- Proof that email cannot recover/decrypt/delete a vault or replace credentials.

### `supply-chain-build-and-release`

- Rust/npm dependency locks, build scripts, GitHub workflow pinning, generated
  WASM, extension allowlist packaging, version/license coherence, deterministic
  artifacts, and dependency/advisory review.
- Audit bundle completeness and reproducibility, release artifact provenance,
  signing-key trust, and the independent-audit release gate itself.

### `operations-recovery-and-privacy-logging`

- Liveness/readiness, structured fields, aggregate operational snapshot,
  capacity bounds, alerts, incident ownership, mail baseline handling, and
  absence of tenant values in telemetry.
- Rollout, schema-aware rollback, process/disk/SMTP/ingress faults, alert drills,
  credential rotation, encrypted off-host backup, and replacement-host restore.
- Whether deployment-conditioned evidence accurately supports every production
  claim and whether unsupported HA/scale assumptions remain rejected.

## Required adversary analysis

At minimum, assess:

- stolen database/backup/export/extension package and offline computation;
- malicious or compromised sync server, ingress, mail provider, or directory;
- network attacker before/after TLS termination and spoofed proxy metadata;
- malicious website, iframe, navigation race, extension message sender, XSS,
  dependency/build compromise, and hostile imported data;
- account enumeration, credential stuffing, resource exhaustion, storage
  saturation, disk loss, process crash, replay, rollback, and concurrent clients;
- compromised unlocked endpoint, browser profile, OS, or clipboard, clearly
  separating mitigated behavior from residual risk.

## Review methods and evidence

The auditor must perform manual code review and threat-model analysis, not only
automated scanning. Dynamic and static techniques should include:

- independent cryptographic construction review and vector verification;
- native, WASM, browser, API, migration, race, backup/restore, and fault tests;
- dependency/advisory and build/release provenance review;
- browser/extension CSP, storage, origin/frame/navigation, and message tests;
- malformed/fuzz/property-style testing of security-sensitive parsers and wire
  boundaries where practical;
- staging validation of ingress, SMTP, mailbox, logging, backup, rollback, and
  recovery claims when deployment evidence is available.

The repository baseline command is:

```bash
bash scripts/verify-all.sh
```

Passing repository tests is necessary but not sufficient for approval.

## Finding severity and release rule

- **Critical:** practical compromise of vault/Send plaintext or keys at scale,
  authentication/authorization bypass with severe impact, release/supply-chain
  compromise, or similarly catastrophic boundary failure.
- **High:** practical compromise of sensitive data or account authority,
  exploitable cryptographic/integrity failure, durable remote denial of service,
  or a production-boundary failure with major impact.
- **Medium:** meaningful security weakness requiring conditions or limited
  impact, without a direct Critical/High path.
- **Low:** defense-in-depth, hardening, or limited-impact weakness.
- **Informational:** observation with no current exploitable security impact.

No Critical or High finding may remain `open` or `risk_accepted`. A resolved
finding must name its remediation commit and be independently retested. Open or
risk-accepted Medium/Low/Informational findings require an owner and non-overdue
due date. The auditor must explicitly recommend the exact release.

## Deliverables

The independent auditor supplies:

1. a final report describing methods, scope, limitations, findings, severity,
   exploitability, remediation guidance, and retest results;
2. the exact JSON attestation defined by
   [`audit/attestation.example.json`](../audit/attestation.example.json), with no
   placeholders and complete coverage;
3. an SSH signature over the exact attestation bytes using namespace
   `bastion-audit` and a public key trusted out of band before report delivery;
4. conflict/independence disclosure and explicit release recommendation;
5. separate confidential reproduction material for non-public vulnerabilities.

The report may remain private before coordinated disclosure. Its SHA-256, the
scope SHA-256, the full validation-log SHA-256, commit, and tree are bound by
the signed attestation.

## Explicitly out of scope

The audit cannot certify the security of browser/OS hardware already controlled
by an attacker, user-chosen master-password quality, third-party provider
internals, or infrastructure not represented by retained evidence. It does not
create an uptime SLA, formal cryptographic proof, regulatory certification, or
permission to deploy multiple active servers/shared SQLite.

Those limitations must be stated in the final report; they do not permit the
auditor to omit review of Bastion's behavior when those dependencies fail.
