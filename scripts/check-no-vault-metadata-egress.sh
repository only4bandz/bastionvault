#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

pattern='icons\.duckduckgo\.com|lookup\.binlist\.net|/api/bin/'
if rg -n "$pattern" app/src crates/server; then
  echo "Vault domains and card prefixes must not be sent to third-party metadata services." >&2
  exit 1
fi

echo "Vault metadata egress guard passed."
