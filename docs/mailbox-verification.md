# Mailbox proof for registration

## Security boundary

Production registration requires proof that the registrant can receive mail at
the chosen account identifier. This proof prevents pre-registration squatting
without converting email into account recovery or vault authority.

Mailbox proof establishes only one fact: the holder received one short-lived
link. It does not identify a person, reset a master password, replace a Secret
Key, decrypt data, authorize account deletion, or recover a vault. Bastion has
no email recovery path.

## Protocol

1. The web client reads `GET /v1/config`. Production reports
   `email_verification_required: true`.
2. `POST /v1/registration-challenges` accepts one syntactically valid mailbox.
   The response is always `202` for both a new challenge and a no-op, so it
   does not add an account-existence oracle beyond the legacy prelogin route.
3. SQLite atomically stores a 256-bit token hash, a 30-minute expiry, a
   two-minute resend boundary, and the outbox message containing the raw link.
   No account row is created, so an attacker cannot squat the identifier merely
   by requesting mail.
4. The link opens `/verify-email#token=...`. The proof is an URL fragment, so
   the browser never sends it to the static ingress. The web client immediately
   removes it from the address bar, submits it to
   `POST /v1/registration-challenges/verify`, and keeps it only in memory. The
   server marks the matching unexpired challenge verified and returns its
   mailbox.
5. Only then does the client collect the master password, generate the vault
   and Secret Key locally, and submit `POST /v1/accounts` with the same raw
   token as `mailbox_proof`.
6. SQLite rechecks the verified token, mailbox binding, and expiry in the same
   transaction that creates the account, then consumes the challenge. Its
   outbox history cascades away.

Account identifiers are canonical lowercase ASCII before challenge storage,
mail delivery, proof lookup, account creation, authentication, and rate-limit
account bucketing. Case variants therefore refer to one mailbox proof and one
vault; they cannot reserve parallel accounts or obtain independent quotas.

The server stores only SHA-256 of the 256-bit proof token in the challenge
table. A fast hash is correct here because the token has full cryptographic
entropy; this is not a password. The raw token exists temporarily in the
pending outbox body, in the recipient's mailbox, and in browser memory during
registration. It is not placed in an HTTP request target.

## Abuse and lifecycle controls

- Challenge requests: 30 globally, 10 per trusted source, and 2 per mailbox per
  process/minute.
- Verification attempts: 120 globally, 30 per trusted source, and 5 per token
  prefix per process/minute.
- Durable resend cooldown: two minutes, enforced in SQLite across restarts.
- Challenge expiry: 30 minutes.
- Active outbox capacity: 10,000 globally and 3 per challenge owner.
- A resend after the cooldown rotates the token and cascades the stale queued
  message; old links stop working.
- The mail worker deletes expired challenges before claiming work, so it does
  not intentionally send already-expired links.
- Existing accounts produce the same accepted challenge response but no mail.

Process-local account, token, and trusted-source rate limits are a
first-instance abuse boundary, not a distributed anti-abuse system. The
selected ingress/provider must still add its own source-aware controls and
provider quotas during the production operations phase.

## Deployment requirements

`BASTION_ENV=production` now refuses to start without the complete authenticated
STARTTLS configuration documented in
[`transactional-mail-outbox.md`](transactional-mail-outbox.md). The public
ingress must serve the SPA entry point for `/verify-email` while continuing to
proxy only `/api/*` to Axum.

Before external registration is enabled, the selected mail provider/domain must
pass the provider acceptance gate, and a real mailbox drill must demonstrate:

- delivery of the current template;
- successful link verification and account creation;
- expired and rotated links failing closed;
- no account row before proof consumption;
- no verification token in application, ingress, or provider telemetry;
- no recovery behavior after verification.

Schema version 4 marks pre-existing accounts verified during migration. There
is no safe way to retroactively prove historical mailbox ownership; the
grandfathering is explicit and must be recorded for the first production data
migration.
