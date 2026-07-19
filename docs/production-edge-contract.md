# Production TLS and origin contract

This contract applies to the single-instance deployment accepted by
[ADR 0001](adr/0001-production-topology-and-slos.md). It is platform-neutral:
the selected ingress may vary, but weakening these invariants is not allowed.

## Process configuration

The production server must start with all four values set explicitly:

```bash
BASTION_ENV=production
BIND_ADDR=127.0.0.1:7777
BASTION_DB=/var/lib/bastion/bastion.db
BASTION_PUBLIC_ORIGIN=https://vault.example.com
```

Startup fails before serving when:

- `BIND_ADDR` is not a numeric loopback socket address;
- `BASTION_DB` is relative or in-memory;
- `BASTION_PUBLIC_ORIGIN` is not one canonical HTTPS origin;
- a setting is missing or `BASTION_ENV` is unknown.

Listening on `0.0.0.0`, a public address, or an unauthenticated private network
is explicitly unsupported. A future remote ingress requires a separately
authenticated private-hop design and a new reviewed configuration contract.

## Ingress requirements

The ingress and Axum process run on the same host. The ingress must:

1. serve the immutable web application and proxy `/api/*` to the loopback
   listener;
2. redirect plaintext HTTP to the exact HTTPS URL before any application
   request reaches Axum;
3. preserve the original public `Host` header;
4. remove every client-supplied forwarding header, then set exactly one
   `X-Forwarded-Proto: https` value on proxied HTTPS requests;
5. use a publicly trusted certificate, renew it automatically, and alert while
   at least 30 days of validity remain;
6. pass through Bastion's `Strict-Transport-Security: max-age=31536000` header.

Axum rejects non-health application requests unless `Host` exactly matches the
configured public authority and the trusted proto value is exactly `https`.
Only `/health`, `/livez`, and `/readyz` (versioned or legacy) bypass that check
so private loopback probes do not need forged forwarding metadata.

`X-Forwarded-Proto` is trusted only because production startup makes the Axum
listener loopback-only. Do not expose that listener through port publishing,
a sidecar, or a host-network rule.

## Origin and CORS policy

The web application uses relative `/api/v1` URLs. Static assets and the API
therefore share `BASTION_PUBLIC_ORIGIN`. The API emits no
`Access-Control-Allow-*` headers and does not implement credentialed CORS.

The browser extension uses an explicit HTTPS host permission and Bearer tokens;
it does not require a CORS exception. `Origin` is not treated as client
authentication. Do not add wildcard or reflected CORS, and do not add a cookie
authentication path. Any future cross-origin browser client requires a new
threat-model review and packaged-browser integration tests before an exact
allowlist is introduced.

## Deployment acceptance

After deploying or changing the ingress, run:

```bash
bash scripts/verify-production-edge.sh https://vault.example.com
```

The drill validates certificate lifetime, HTTP-to-HTTPS redirect, HSTS, the
health endpoint, stripping of spoofed forwarding metadata, rejection of a
wrong Host, and absence of CORS opt-in. It is intentionally not part of the
local test suite because it must exercise the real certificate and ingress.

Record the command output with the release evidence. Production remains
blocked until a selected deployment passes this drill and its certificate
renewal alert has an owner.
