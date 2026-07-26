# Session lifecycle

Bastion bearer sessions are process-local and never written to SQLite. A
server restart therefore revokes every session by construction.

## Lifetimes

- A bearer token is valid for 30 minutes.
- The web app and extension rotate an active token every 10 minutes.
- Rotation renews the 30-minute access window but preserves the original
  session-family creation time.
- No family can survive longer than 12 hours, regardless of rotations.
- The immediately preceding token remains accepted for 60 seconds so requests
  already in flight do not fail when a concurrent request rotates the family.

The 12-hour server ceiling is independent of the shorter client auto-lock
policies. Client inactivity, tab lifecycle, browser session lock, or explicit
lock can end access earlier. The extension also persists the original absolute
deadline in RAM-backed trusted session storage. Rehydrating an evicted service
worker may create a fresh server family, but cannot move that local deadline;
legacy records inherit their existing expiry as the non-extending ceiling.

## Rotation protocol

`PUT /v1/sessions` requires the current bearer and an empty JSON object as its
body:

```json
{}
```

The server mints the replacement itself, exactly as it does at login, and
returns it:

```json
{"token":"<64 lowercase hex characters>"}
```

It stores only the domain-separated hash of either token. The replacement was
previously supplied by the client, which delegated the entropy of the server's
own bearer credential to whatever generator the caller happened to use — the
server could validate its shape but never its randomness, and that guarantee has
to hold for every client that ever talks to the deployment, not only the two in
this repository.

Retrying is still safe, and no raw token is retained to make it so. Each active
token records whether it has ever authenticated a request, which distinguishes
the two cases a retry can be in:

- the successor has never been used, so the client did not receive it: it is
  revoked and a fresh replacement is issued;
- the successor is already in use, so the legitimate client holds it and this
  predecessor is being replayed: the entire family is revoked and the server
  emits a `session_reuse_detected` security event.

The family's creation time carries across both paths, so a retry cannot restart
a session's lifetime. Both clients retry one ambiguous transport failure. If
both responses are lost, they perform a fresh authenticated login from the
already-unlocked account and revoke the ambiguous family best-effort.

Do not shorten the predecessor grace below the complete client request deadline
and retry budget. Do not make predecessors indefinite: that would turn rotation
into token duplication.

## Revocation

- `DELETE /v1/sessions` revokes the complete current family. Calling it with the
  grace-period predecessor also revokes its active successor.
- `DELETE /v1/sessions/all` revokes every family for the authenticated account,
  including the caller, and returns `204`.
- Account deletion removes active and grace-period session state.
- A ninth login evicts the oldest of the account's maximum eight active
  families.

Global revocation is intentionally account-scoped. It must never be implemented
as a process-wide session clear, which would let one account log out every
tenant.

## Operational notes

Rotation and global revocation share a per-account `session-control` token
bucket capped at 30 operations per minute. Active sessions remain capped at
100,000 process-wide; grace state is bounded to at most one predecessor per
active family.

This lifecycle adds no SQLite schema or persisted state. In a multi-replica
deployment, sessions remain replica-local until the architecture explicitly
moves them to shared state; ingress affinity alone is not global revocation.
