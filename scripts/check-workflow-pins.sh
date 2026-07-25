#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

status=0
while IFS= read -r entry; do
  ref="$(sed -E 's/.*uses:[[:space:]]+([^[:space:]#]+).*/\1/' <<<"$entry")"
  if [[ ! "$ref" =~ ^[^@[:space:]]+@[0-9a-f]{40}$ ]]; then
    echo "Unpinned GitHub Action: $entry" >&2
    status=1
  fi
done < <(grep -nH -E '^[[:space:]]*(-[[:space:]]+)?uses:' .github/workflows/*.yml)

if (( status != 0 )); then
  exit "$status"
fi

echo "GitHub Actions pin guard passed."
