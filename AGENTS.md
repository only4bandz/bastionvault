# Project agent instructions

## Trust zones

- Vercel must never call an upstream service.
- Vercel must never store or use credentials or write tokens.
- Upstream APIs and credentials live only on the worker (VPS or external runner).
- Vercel serves pre-published snapshots only.
- The worker and Vercel never communicate directly.
- Browser and extension clients never communicate with the worker.
- Any deviation from these rules is a release blocker.

## Snapshot contract

- The worker generates and validates snapshots with Zod before publication.
- Every snapshot has a content checksum and an immutable checksum-stable path.
- Publication is atomic: stage, validate, publish the immutable object, then promote
  the latest pointer.
- Vercel Blob is public-read and private-write. Write credentials exist only on
  the worker.
- Vercel reads through `SNAPSHOT_BASE_URL`, emits the snapshot checksum as `ETag`,
  honors `If-None-Match`, and returns `503` when a snapshot is unavailable.
- There are no runtime retries, upstream fallbacks, or hidden network calls.

## Repository safety

- Treat schema, publishing, cache-header, and API-semantic changes as
  production-impacting.
- Keep changes small and reversible, and document behavior changes explicitly.
- Before proposing or merging a change, inspect the available scripts and run the
  relevant format, lint, typecheck, build, and test commands.
