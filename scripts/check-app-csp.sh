#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if rg --pcre2 -n '<script(?![^>]*\bsrc=)' app/index.html; then
  echo "The main app must not contain inline scripts." >&2
  exit 1
fi

if ! rg -q "default-src 'none'" app/index.html \
  || ! rg -q "script-src 'self' 'wasm-unsafe-eval'" app/index.html \
  || ! rg -q "connect-src 'self'" app/index.html \
  || ! rg -q "object-src 'none'" app/index.html \
  || ! rg -q "base-uri 'none'" app/index.html; then
  echo "The main app must enforce its reviewed Content Security Policy." >&2
  exit 1
fi

if rg --pcre2 -n "script-src[^;]*'unsafe-(?:inline|eval)'" app/index.html; then
  echo "The main app CSP must not permit inline scripts or JavaScript eval." >&2
  exit 1
fi

echo "Main app CSP guard passed."
