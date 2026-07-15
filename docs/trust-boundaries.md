# Production trust boundaries

## Release status

The React vault and Chrome extension currently contain interactive sync clients.
They are development surfaces until their network paths are replaced by the
snapshot handoff described here. They must not be deployed on Vercel or pointed
at the worker in production.

## Allowed production flow

```text
upstream APIs -> worker -> public immutable Vercel Blob snapshots
                                      |
                                      v
                         Vercel snapshot reader -> client
```

Storage is the only handoff boundary. The worker owns upstream credentials and
the Blob write token. Vercel owns no secret and can read only public Blob/CDN
objects. Clients communicate with Vercel, never with the worker.

## Explicitly forbidden designs

- A Vercel rewrite, proxy, function, server action, or middleware call to Axum or
  any other upstream.
- A Blob write token, upstream API key, bearer token, or authentication secret in
  a Vercel environment.
- A browser or extension setting that points directly at the worker.
- A runtime fallback that bypasses a missing or invalid snapshot.

## Delivery contract

Snapshots use versioned schemas and checksum-stable immutable paths. A reader
must validate the snapshot, verify its checksum, set `ETag` from that checksum,
return `304` for a matching `If-None-Match`, and fail with `503` when the object is
missing or invalid. Serving stale hidden fallback data is not allowed.
