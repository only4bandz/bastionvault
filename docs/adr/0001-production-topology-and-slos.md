# ADR 0001: Initial production topology and service objectives

- Status: Accepted
- Date: 2026-07-19
- Owners: Bastion maintainers
- Applies to: the first controlled Internet-facing Bastion deployment

## Context

The current sync server keeps the account read cache, bearer sessions, and
rate-limit counters in one process. It serializes durable mutations through a
single SQLite connection and protects the database with an exclusive
per-database server lock. These are deliberate correctness boundaries, not a
high-availability design.

The browser application already uses a same-origin `/api/v1` path. The browser
extension connects directly to one configured API origin and rejects plaintext
HTTP except on loopback. No hosting platform, region, or managed storage
service is selected by this repository.

An initial production contract is required before changing concurrency,
storage, transport, mail, or deployment behavior. Without it, those changes
could silently create unsupported multi-writer or cross-origin designs.

## Decision

### Topology

The first production candidate will use exactly one active Bastion server and
one SQLite database on a local persistent filesystem:

```text
web browser ---------+
                     |
browser extension ---+--> HTTPS ingress
                              |-- /       -> immutable web assets
                              `-- /api/*  -> one private Axum server
                                                   |
                                          bounded storage queue
                                                   |
                                          one SQLite owner
                                                   |
                                          local persistent disk
                                                   |
                                          encrypted off-host backups
```

The implemented initial contract requires the ingress and Axum server to share
a host: production startup restricts Axum to a numeric loopback listener. A
future private authenticated network hop requires a new reviewed contract.
Axum must not be directly reachable from the public Internet. The application
remains same-origin: the public web origin serves both the static application
and `/api/*`. CORS is disabled by default.

The browser extension may call the same HTTPS origin through an explicitly
granted extension host permission. A narrowly scoped CORS exception may be
added only if a packaged-browser integration test proves it is required. A
wildcard, reflected origin, or credentialed wildcard is never acceptable.

### Storage boundary

SQLite must reside on a local filesystem that honors advisory locks and sync
requests. Network filesystems, distributed filesystems, shared SQLite volumes,
and simultaneous server replicas are unsupported. Backups must use a
SQLite-aware snapshot mechanism and be copied, encrypted, to a failure domain
outside the application host.

Synchronous SQLite work runs off Tokio executor threads without weakening the
single-owner boundary. A bounded command queue feeds one dedicated storage
owner. Queue saturation fails fast. If an accepted command exceeds its response
deadline, the process withdraws readiness; an accepted mutation still finishes
under its logical cache lock before the process remains quarantined for restart.
Unbounded `spawn_blocking` tasks and pools of competing SQLite connections are
explicitly rejected.

The schema is transactionally versioned and guarded by foreign keys. The
repository also provides a no-clobber online snapshot command and an
application-level restore test covering encrypted vault, manifest, and Send
state. Production still requires an encrypted off-host scheduler, retention
policy, monitoring of backup age, and a restore drill on the selected
deployment environment that demonstrates the RPO and RTO below.

Transactional email uses a SQLite outbox owned by the same isolated storage
thread. A leased worker performs authenticated mandatory-STARTTLS SMTP outside
SQLite transactions, retries transient failures with bounded backoff, and
scrubs terminal rows. Delivery is explicitly at least once; the deployment
must not claim exactly-once SMTP semantics. Mailbox verification and provider
acceptance remain separate production gates.

### Availability and durability objectives

The initial objectives are:

| Objective | Initial target | Measurement boundary |
|---|---:|---|
| Recovery point objective (RPO) | 15 minutes | Maximum committed database state lost after total host loss |
| Recovery time objective (RTO) | 60 minutes | Time to restore a verified backup on a replacement host and pass readiness |
| Backup restore verification | Every release and at least monthly | Automated restore plus application-level invariant checks |
| Planned deployment topology | One active instance | The exclusive server lock must remain enabled |
| Transport availability | HTTPS only | Public requests must never reach Axum over plaintext HTTP |

These are engineering acceptance targets, not a public uptime SLA. A public
availability promise requires measured production data and an approved support
and incident-response commitment.

### Capacity envelope

The server's protocol limits remain hard safety ceilings, not capacity claims:

- at most 64 MiB of encrypted vault state and 10,000 items per account;
- at most 500 stored Send messages per recipient;
- at most 100,000 active in-process sessions;
- at most four simultaneous server-side Argon2 operations.

Before accepting external production users, a reproducible load test must
establish a lower supported operating envelope for account count, database
size, request concurrency, p95/p99 latency, queue depth, and restore time on the
selected hardware. The deployment must reject or alert before those measured
limits are exceeded. Protocol maxima must not be advertised as tested scale.

### Data classification, residency, and retention

The database is zero-knowledge for vault and Send plaintext, but it still
contains sensitive metadata: login identifiers, password-verifier material,
encrypted payload sizes, routing identifiers, and timestamps. Database files,
WAL files, snapshots, and operational access therefore require the same
confidential handling.

The deployment owner must record, outside this platform-neutral ADR:

- the selected hosting region and applicable residency commitment;
- the backup region and encryption-key owner;
- backup retention and deletion periods;
- log retention and access policy;
- the transactional-email provider and processing region;
- named incident, restore, and security-response owners.

Production is blocked while any of these fields is unspecified. Logs must
continue to exclude account identifiers, tokens, ciphertexts, message ids, and
request or response bodies.

### Horizontal scaling decision gate

The SQLite topology is acceptable only while a single active server and a
restore-based recovery path meet the approved service objectives. If the
product requires zero-downtime host failover, more than one active replica, or
regional redundancy, implementation must stop and a new ADR must select a
shared transactional store.

The expected multi-replica direction is PostgreSQL, but it is not approved by
this ADR. Such a migration must first:

1. make durable storage the authority instead of the process-local account
   cache;
2. move or redesign sessions and rate limits so every replica observes the
   same security state;
3. preserve vault revision compare-and-swap in one database transaction;
4. run the same storage conformance, race, backup, and restore tests against
   the new backend;
5. prove failover behavior before enabling a second replica.

Putting SQLite on shared storage or removing the exclusive lock is explicitly
rejected as a scaling strategy.

## Production gates

An Internet-facing production deployment is prohibited until all of the
following are complete:

1. SQLite operations are isolated from Tokio executor threads with bounded
   backpressure and separate liveness/readiness checks.
2. Schema migrations are versioned and backup/restore drills meet the RPO and
   RTO above.
3. HTTPS, origin enforcement, certificate renewal, and the private Axum
   boundary pass the repository's automated production-edge drill on the
   selected deployment.
4. Mailbox verification uses durable delivery, bounded abuse controls, and
   never acts as vault recovery.
5. Operational metrics, alerts, rollback procedures, and failure drills are
   exercised on the selected deployment environment.
6. An independent security audit of the frozen release has no unresolved
   Critical or High findings.

## Consequences

This decision minimizes new distributed-systems failure modes and preserves
the server's existing single-writer assumptions. It also means that the first
production candidate cannot provide seamless failover and will have a recovery
window after total host loss.

The repository remains platform-neutral. Concrete ingress, compute, disk,
backup, monitoring, mail, and region selections belong in a deployment record
once an environment is chosen; they must satisfy this ADR rather than weaken
it.

## Revisit conditions

Revisit this ADR before any of the following:

- enabling a second active server;
- moving the database away from a local filesystem;
- publishing an uptime SLA;
- changing the RPO or RTO;
- serving the web application and API from different origins;
- adding a second production region.
