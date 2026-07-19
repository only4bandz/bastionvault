# Security policy

## Supported versions

Bastion is pre-1.0 software. Security fixes are applied to the latest commit on
`main`; older commits, development branches, and self-built historical releases
are not supported.

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

## Scope and audit status

Security-sensitive components include `crypto-core`, the WASM boundary, vault
integrity and rollback handling, the Axum/SQLite server, the web application,
the browser extension, and Bastion Send.

The repository contains deterministic vectors, integration tests, WebAssembly
tests, and internal security-review artifacts. It has not yet undergone an
independent third-party security audit.
