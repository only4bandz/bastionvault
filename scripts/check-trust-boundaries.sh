#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

runtime_roots=()
for root in api vercel snapshot-web/api app/api app/src/app/api; do
  if [ -d "$root" ]; then
    runtime_roots+=("$root")
  fi
done

if [ "${#runtime_roots[@]}" -gt 0 ]; then
  secret_pattern='BLOB_READ_WRITE_TOKEN|API[_-]?KEY|AUTH[_-]?SECRET|CLIENT[_-]?SECRET|BEARER[_-]?TOKEN|PRIVATE[_-]?KEY'
  if rg -n -i "$secret_pattern" "${runtime_roots[@]}"; then
    echo "Vercel runtime code must not reference credentials or write tokens." >&2
    exit 1
  fi

  write_pattern='@vercel/blob.*(put|del|copy)|\b(put|del|copy)\s*\(|blob\.vercel-storage\.com.*(POST|PUT|DELETE)'
  if rg -n -i "$write_pattern" "${runtime_roots[@]}"; then
    echo "Vercel runtime code must never write or mutate Blob objects." >&2
    exit 1
  fi

  network_hits="$(rg -n 'fetch\(|axios|reqwest|XMLHttpRequest|WebSocket|EventSource' "${runtime_roots[@]}" || true)"
  unapproved="$(printf '%s\n' "$network_hits" | rg -v 'trust-boundary:blob-read' || true)"
  if [ -n "$unapproved" ]; then
    echo "Every Vercel runtime network call must be an explicitly marked Blob/CDN read." >&2
    printf '%s\n' "$unapproved" >&2
    exit 1
  fi
fi

config_files=()
while IFS= read -r file; do
  config_files+=("$file")
done < <(rg --files -g 'vercel.json')

if [ "${#config_files[@]}" -gt 0 ]; then
  if rg -n -i '"destination"\s*:\s*"https?://|destination[^,]*(worker|upstream|127\.0\.0\.1|localhost)' "${config_files[@]}"; then
    echo "Vercel configuration must not rewrite or proxy to an upstream service." >&2
    exit 1
  fi
fi

echo "Trust-boundary guard passed."
