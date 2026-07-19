# Transactional mail outbox

## Scope

Bastion uses a SQLite outbox for transactional email. Application state and
the mail request that follows from it must commit in the same database
transaction. SMTP network I/O never runs while a SQLite transaction or the
application state lock is held.

This component provides durable at-least-once delivery. It does not turn email
into vault recovery, prove a human identity, or make SMTP end-to-end encrypted.
The mail operator can observe recipients, timing, subjects, and message bodies.

## State machine

Schema version 3 adds `mail_outbox`. Every row is tied to an account with a
cascading foreign key and follows one state machine:

```text
pending --lease--> in_flight --relay accepted--> delivered
   ^                    |
   |                    +--transient failure--> pending
   |                    |
   +--expired lease-----+
                        +--permanent / exhausted--> dead
```

- One worker leases one due message for 60 seconds in an immediate SQLite
  transaction, then releases SQLite before contacting the relay.
- A crashed worker's expired lease is reclaimed with the same stable message
  identifier.
- Transient failures retry after 30 seconds with exponential backoff capped at
  six hours.
- A permanent SMTP response or eight failed/ambiguous attempts moves the row to
  `dead`.
- `recipient`, `subject`, and `text_body` are scrubbed on `delivered` and
  `dead`. Until then they are sensitive backup data.
- Database constraints bound identifiers, recipients, subjects, bodies,
  attempts, states, leases, and error codes. Provider error text is never
  persisted or logged.

There is an unavoidable ambiguity if the SMTP relay accepts a message and the
process crashes before SQLite records success. Bastion retries with the same
RFC 5322 `Message-ID`, but SMTP does not guarantee deduplication. A recipient
can therefore receive a rare duplicate. Designs claiming exactly-once email
delivery are rejected.

## SMTP contract

Mail delivery is disabled unless all settings are present:

```bash
BASTION_SMTP_HOST=smtp.example.com
BASTION_SMTP_PORT=587
BASTION_SMTP_USERNAME=bastion
BASTION_SMTP_PASSWORD=replace-with-secret-injection
BASTION_MAIL_FROM='Bastion <no-reply@example.com>'
```

Partial or malformed configuration fails startup. The worker always uses
authenticated SMTP with mandatory STARTTLS and Web PKI certificate validation;
plaintext SMTP and opportunistic TLS are not supported. SMTP operations time
out after 30 seconds and never block Tokio executor threads or the SQLite owner.

The password must enter through the selected deployment's secret-injection
mechanism, not a repository file, image layer, process argument, or log. The
deployment record must name the mail provider, processing region, credential
owner, and rotation procedure.

## Provider acceptance gate

Before external users are enabled, the selected relay must demonstrate:

- authenticated STARTTLS with a valid certificate;
- SPF, DKIM, and DMARC alignment for the configured From domain;
- documented rate limits above Bastion's bounded registration/resend envelope;
- bounce, complaint, and suppression handling with a named operator;
- data processing and retention terms for recipient addresses and bodies;
- delivery and failure telemetry that does not copy verification tokens into
  logs or metrics;
- a credential-revocation and rotation drill.

The repository tests the durable state machine with a deterministic fake
sender. A provider-specific delivery test is deployment evidence and cannot be
claimed before a provider and domain are selected.

## Producer rules

Every producer added after this foundation must:

1. generate a random 128-bit lowercase hexadecimal outbox id;
2. insert the bounded plain-text message in the same SQLite transaction as the
   authoritative application state;
3. apply global and per-account abuse limits before producing mail;
4. make stale links harmless and independently expiring;
5. never store a reusable vault or authentication secret in mail;
6. treat delivery as notification only, never as account recovery authority.

Mailbox verification is the first planned producer. Until that producer and
its abuse controls are merged, SMTP configuration alone sends no mail.
