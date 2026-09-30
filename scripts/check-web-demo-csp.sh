#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if grep -nE '<style|\sstyle=|\.innerHTML|\.outerHTML|insertAdjacentHTML|document\.write' web/index.html web/app.js; then
  echo "The WASM demo must not use inline styles or HTML injection sinks." >&2
  exit 1
fi

if grep -nP '<script(?![^>]*\bsrc=)' web/index.html; then
  echo "The WASM demo must not contain inline scripts." >&2
  exit 1
fi

if ! grep -qE "script-src 'self' 'wasm-unsafe-eval'" web/index.html; then
  echo "The WASM demo must enforce its reviewed Content Security Policy." >&2
  exit 1
fi

if grep -nE "'unsafe-inline'|'unsafe-eval'" web/index.html; then
  echo "The WASM demo CSP must not permit unsafe inline scripts or JavaScript eval." >&2
  exit 1
fi

echo "WASM demo CSP guard passed."
