#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if grep -nP '<script(?![^>]*\bsrc=)' app/index.html; then
  echo "The main app must not contain inline scripts." >&2
  exit 1
fi

if ! grep -qE "default-src 'none'" app/index.html \
  || ! grep -qE "script-src 'self' 'wasm-unsafe-eval'" app/index.html \
  || ! grep -qE "connect-src 'self' https://api\.pwnedpasswords\.com" app/index.html \
  || ! grep -qE "object-src 'none'" app/index.html \
  || ! grep -qE "base-uri 'none'" app/index.html \
  || ! grep -qE "form-action 'none'" app/index.html; then
  echo "The main app must enforce its reviewed Content Security Policy." >&2
  exit 1
fi

if grep -nP "script-src[^;]*'unsafe-(?:inline|eval)'" app/index.html; then
  echo "The main app CSP must not permit inline scripts or JavaScript eval." >&2
  exit 1
fi

echo "Main app CSP guard passed."
