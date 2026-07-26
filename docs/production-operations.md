# Production operations and failure drills

This runbook implements gate 5 of
[ADR 0001](adr/0001-production-topology-and-slos.md) for the initial
single-instance deployment. It is platform-neutral. The deployment record must
name the actual host, ingress, monitoring, backup, and mail systems without
weakening these controls.

Production is not approved merely because the repository tests pass. The live
deployment must produce the evidence listed here, and the evidence must be
retained with the release record.

## Hard operating boundary

- Exactly one Bastion server may own the local SQLite database.
- SQLite, its WAL/SHM files, and the server lock stay on one local filesystem
  that honors file locks and fsync. Shared or network SQLite is rejected.
- Axum listens on numeric loopback only. The public ingress serves immutable
  assets and proxies `/api/*` plus the exact `security.txt` and closed honeypot
  exceptions documented by the edge contract; it must not add a catch-all
  proxy or proxy the operational status CLI.
- Backups are SQLite-aware, encrypted before off-host transfer, and treated as
  sensitive metadata and verifier material.
- Destructive disk, network, and process drills run only on an isolated staging
  host or disposable restored copy. Filling the production disk, changing live
  database permissions, or faulting the only active host is prohibited.
- A second replica is not a recovery mechanism. Recovery means starting one
  owner against a verified local restore.

## Safe operational signals

Every request log contains only method, redacted route shape, status, and
`latency_ms`. Transactional-mail events contain only attempt number, a fixed
outcome, and a fixed error code. Logs must never add headers, query strings,
account identifiers, routing ids, tokens, bodies, or ciphertext fields.

Security-relevant outcomes are logged at `warn` with the message `security`, an
`event` label, and that label's running process-lifetime `total`. The labels are
`auth_rejected` (401), `forbidden` (403), `rate_limited` (429),
`wrong_public_host` (421), `unmatched_path` (a 404 on no known route), and
`honeypot`. They carry no more data than an ordinary request line — the counters
are one per class, never per account, token, or address, so a caller cannot grow
this state by sending more requests.

An explicit account-wide revocation emits `event="sessions_revoked_all"` at
`warn` without an account identifier or token. It is an action event rather
than an outcome counter and therefore has no process-lifetime `total`.

`honeypot` fires only on a closed set of paths no Bastion client ever requests
(`/.env`, `/admin`, `/wp-login.php`, …). A hit is therefore an unambiguous
scanner rather than a mistyped URL, which is what makes it worth alerting on;
the lure answers a constant 404 that reflects no request data and changes no
authentication, authorization, quota, or rate-limit decision. Decoys of this
kind — including the prelogin decoy for unknown accounts — are additions on top
of the real controls and must never be introduced as a substitute for one.

Authentication and authenticated-operation counters use separate bounded
mutexes; neither shares the account/session cache lock or remains held across
storage work. Send admission applies both a 30/minute sender-recipient limit and
a 120/minute aggregate recipient limit, so one account cannot consume a
recipient's entire shared budget. These counters use deterministic integer
token buckets and are process-local. Authentication-facing routes also apply a
source bucket to the canonical client address asserted by the same-host trusted
ingress. Source buckets are keyed by end-site prefix — the full address for
IPv4, the /64 for IPv6 — because a single IPv6 address is not a unit of
accountability: one ordinary allocation would otherwise supply 2^64 distinct
keys and clear every per-source limit at no cost. They are held in a table of
their own, separate from account and token buckets, so caller-chosen keys can
never crowd out a key the server issued. At its bound a rate table evicts its
least recently used bucket and counts a `rate_limiter_pressure` event rather
than refusing an unseen subject; a sustained rate of those events means
enforcement is being diluted and the bound needs review. The application rejects missing, duplicate, malformed, or chained
forwarding values and never uses forwarding metadata in development mode.
Client addresses exist only as bounded in-process counter keys and are not
added to application logs. Source-bucket capacities per 60-second refill window
are 5 account creations, 30 logins, 60 prelogins, 10 mailbox challenges, and 30
proof verifications.

Readiness is answered from a 500 ms cache with one single-flight refresh.
Concurrent callers at cache expiry fail fast with 503 instead of entering the
SQLite queue. Detection of a storage fault is therefore delayed by up to that
window, never suppressed: the fault is observed on the next admitted uncached
probe, and the instance then stays failed closed.

An accepted mutation that exceeds the storage response deadline temporarily
withdraws readiness and rejects new storage work until that exact command
finishes. A successful commit or explicit SQLite rollback re-opens admission;
only loss of the storage worker causes permanent quarantine. Vault transactions
also have one pre-lock admission slot, preventing an authenticated client from
pre-loading a queue behind the global cache write lock.

Full vault reads return a weak opaque `ETag` derived from the authenticated
account and committed vault revision. A matching `If-None-Match` returns an
empty `304 Not Modified` without cloning or serializing up to 64 MiB of
ciphertext. `Cache-Control: no-store` remains mandatory on both 200 and 304
responses: the validator enables explicit revalidation, not shared or
persistent HTTP caching. The validator is deliberately weak because equivalent
item maps may serialize in a different key order after a process restart. A
client may use 304 only to retain a snapshot it already authenticated,
decrypted, and checked against its rollback anchor. The ETag is a freshness
validator and must never replace manifest authentication, revision/sequence
comparison, or the local rollback checkpoint. The existing `/vault/revision`
probe remains supported.

`bastion-ops-status` opens the live WAL database read-only and emits one JSON
object containing only:

- schema version and observation timestamp;
- total database/WAL/SHM bytes and account count;
- aggregate active, verified, and expired registration challenge counts;
- aggregate pending, in-flight, and dead outbox counts;
- age of the oldest active outbox message.

Build the release binaries before deployment:

```bash
cargo build --release --locked -p server \
  --bin server --bin bastion-backup --bin bastion-ops-status
```

Poll the snapshot from the database host under the same OS identity or a
strictly read-only operational identity with access to the owner-only database:

```bash
bastion-ops-status /var/lib/bastion/bastion.db
```

Do not publish this output as a public HTTP endpoint. Aggregate counts remain
internal operational metadata.

## Required alerts

The measured capacity envelope in the deployment record supplies values where
this table says “measured”; protocol maxima are not capacity claims.

| Signal | Warning | Critical / action |
|---|---|---|
| Public HTTPS blackbox | one failed probe | two consecutive failures; page the service owner |
| `/api/v1/livez` | one failed probe | two consecutive failures; restart only after capturing process evidence |
| `/api/v1/readyz` | one failed probe | unavailable for 60 seconds; withdraw traffic and investigate storage before restart |
| Request 5xx logs | any sustained increase | more than 1% for 5 minutes, or any `storage unavailable`; incident |
| Request latency | p95 above measured envelope for 5 minutes | p99 above measured envelope for 5 minutes; stop onboarding and investigate |
| Database bytes | 80% of measured limit | 90% of measured limit; stop onboarding and expand/restore capacity |
| Host disk or inodes | 20% free | 10% free; withdraw writes before exhaustion |
| Latest verified off-host backup | 10 minutes old | 15 minutes old; RPO breach and incident |
| Backup/restore duration | 45 minutes | 60 minutes; RTO breach and incident |
| Oldest active mail | 5 minutes | 30 minutes or challenge TTL; provider incident |
| Dead outbox rows | any increase over the reviewed baseline | sustained increase or provider-correlated failures; incident |
| Expired challenges | persistent for two polls | persistent for 5 minutes; mail worker/storage incident |
| Certificate lifetime | 45 days | 30 days; renewal owner must act |
| Unexpected process restart | any | repeated restart or migration failure; keep traffic withdrawn |
| `security` events `auth_rejected` / `rate_limited` | sustained rate above the reviewed baseline | sharp sustained increase; suspected credential-stuffing or enumeration campaign |
| `security` event `honeypot` / `unmatched_path` | any hit | sustained scanning, or any honeypot hit correlated with a rise in `auth_rejected`; investigate the source |
| `security` event `sessions_revoked_all` | informational user action | unexplained burst; investigate possible token theft or client loop |
| Provider bounce/complaint rate | provider warning threshold | provider suspension threshold; disable external registration |

Alert routes must have a named primary owner, secondary owner, and tested
delivery channel. “Dashboard only” is not an alert.

## Deployment acceptance command

On the selected database host, provide limits established by the load/capacity
test and paths to the installed release binaries:

```bash
export BASTION_BACKUP_BIN=/opt/bastion/bin/bastion-backup
export BASTION_OPS_STATUS_BIN=/opt/bastion/bin/bastion-ops-status
export BASTION_MAX_DATABASE_BYTES=10737418240  # example only; replace
export BASTION_MAX_ACCOUNTS=1000               # example only; replace
export BASTION_MAX_ACTIVE_MAIL_AGE_SECONDS=300
export BASTION_MAX_BACKUP_VERIFY_SECONDS=3600
export BASTION_ACKNOWLEDGED_DEAD_MAIL=0

bash scripts/verify-production-operations.sh \
  https://vault.example.com \
  /var/lib/bastion/bastion.db \
  /var/lib/bastion/drills/production-$(date -u +%Y%m%dT%H%M%SZ).db
```

The destination must not exist. The command validates the public edge,
liveness, readiness, measured aggregate limits, mail backlog, a no-clobber
online backup, and the restored snapshot schema. It intentionally leaves the
plaintext local snapshot in place so an operator can encrypt and transfer the
exact tested artifact. The approved retention procedure must then remove the
plaintext copy.

`BASTION_ACKNOWLEDGED_DEAD_MAIL` is the last reviewed aggregate baseline, not a
suppression threshold. A higher live value blocks the command and requires an
incident review of fixed-code mail events and provider telemetry. After review,
record the evidence and advance the baseline; do not edit outbox rows directly.

This baseline does not prove replacement-host RTO by itself. The quarterly
host-loss drill below must restore the encrypted off-host artifact on a clean
replacement host, start the pinned release, pass readiness, and record total
elapsed time.

## Rollout

1. Freeze one reviewed commit and record binary, web-asset, and configuration
   checksums. Run `bash scripts/verify-all.sh` from a clean checkout.
2. Before the schema-v5 rollout, run
   `python3 scripts/check-account-id-migration.py /var/lib/bastion/bastion.db`
   against the live v4 database. The read-only aggregate check must report zero
   account and challenge case collisions. A collision blocks deployment:
   automatic selection, deletion, renaming, or merging of either vault is
   prohibited.
3. Confirm alert delivery, free disk/inodes, current off-host backup age, mail
   provider health, and certificate lifetime.
4. Create and verify a pre-deployment SQLite-aware backup. Encrypt and copy it
   off-host before changing the running process.
5. Put the ingress into maintenance/read-only withdrawal. Stop the existing
   server cleanly and confirm no process owns the server lock.
6. Install the pinned binary and immutable assets. Never start old and new
   binaries concurrently against the same database.
7. Start the new binary. Startup migrations are forward-only and must complete
   before `/readyz` returns success.
8. Run the edge and production-operations acceptance commands. Inspect logs for
   migration, storage, 5xx, and SMTP errors.
9. Perform one real mailbox registration with a designated test address. Verify
   there was no account before proof, the current link succeeds, a rotated link
   fails, and email provides no recovery behavior.
10. Remove maintenance only after all checks pass. Record timestamps, command
   output, artifact hashes, and operator/reviewer names.

## Rollback

Rollback is schema-aware; replacing the binary is not always safe.

1. Withdraw traffic and stop the current server. Preserve logs and the failed
   database for incident analysis.
2. Read the current schema with `bastion-ops-status` and compare it with the
   previous binary's supported schema.
3. If the schema did not advance and the previous binary supports it, start
   exactly one previous binary and repeat all acceptance probes.
4. If the schema advanced, the previous binary must not open the migrated
   database. Restore the pre-deployment backup to a new local path, verify it,
   and start the previous binary against that restore.
5. A restore can discard writes accepted after the backup. Keep traffic
   withdrawn until the incident owner explicitly accepts that loss against the
   RPO or chooses a forward fix.

Never edit `PRAGMA user_version`, copy a live `.db`/WAL pair with filesystem
tools, overwrite a backup destination, remove the exclusive lock, or run two
servers to “see which one works.” Those actions break the supported recovery
model.

## Failure-drill matrix

Repository-level deterministic fault tests run on every release:

```bash
bash scripts/test-operational-failures.sh
```

They prove bounded SQLite saturation, executor isolation, transient admission
withdrawal and recovery after an accepted-operation timeout, permanent
quarantine on storage-worker loss, single-owner exclusion, live backup/restore,
outbox lease recovery, bounded retries, and terminal payload scrubbing.

The selected deployment must additionally execute and retain evidence for:

| Drill | Minimum frequency | Pass condition |
|---|---:|---|
| Graceful process restart | every release | SIGTERM drains, WAL checkpoints, one owner restarts, readiness passes |
| Abrupt process loss | quarterly, isolated restore | WAL recovery succeeds, integrity/readiness pass, no second owner |
| SQLite queue saturation or slow accepted mutation | every release, isolated staging | liveness stays responsive, readiness fails closed during saturation, admission recovers without restart after the worker drains |
| SQLite worker loss | every release, isolated staging | readiness remains failed closed; one clean restart restores service after evidence is captured |
| Disk/inode exhaustion | quarterly, disposable volume only | alerts fire before exhaustion; writes are withdrawn; no corruption after recovery |
| SMTP outage and recovery | every release, staging provider | durable row retries without blocking requests; queue drains after recovery; duplicate possibility recorded |
| SMTP permanent rejection | every release, staging provider | payload is scrubbed, dead-row alert fires, no secret appears in telemetry |
| Token rotation/expiry | every release | old/expired links fail, current link works, no account exists before consumption |
| Total host loss | quarterly | encrypted off-host backup restores on clean host within 60 minutes and loses at most 15 minutes |
| Ingress/certificate | every release/change | `verify-production-edge.sh` passes against the real public origin |
| Alert delivery | quarterly | primary and secondary receive a synthetic alert and acknowledge it |
| Credential rotation | quarterly | SMTP and backup credentials rotate without repository/image/log exposure |

For each drill record the frozen commit, environment, start/end time, exact
commands, redacted output, alert timestamps, observed RPO/RTO, artifact hashes,
operator, reviewer, and follow-up issues. Failed drills block release.

## Deployment record

The release record must contain, at minimum:

- frozen commit and checksums for server binary, web assets, and configuration;
- host/region, ingress, local filesystem type, and proof it is not shared;
- measured account, database-size, concurrency, and latency envelope;
- monitoring system, retention, dashboard, alert routes, and named owners;
- backup schedule, encryption mechanism/key owner, off-host region, retention,
  last successful copy, and latest restore evidence;
- mail provider/region, sender domain, credential owner, provider acceptance,
  and real-mailbox drill evidence;
- certificate/renewal owner and latest edge evidence;
- incident, restore, security-response, and release decision owners;
- explicit schema migration and pre-existing-account grandfathering decisions;
- every open risk, exception, expiry date, and approving owner.

Do not put credentials, tokens, account identifiers, database paths containing
tenant data, message bodies, or raw logs into a public deployment record.
