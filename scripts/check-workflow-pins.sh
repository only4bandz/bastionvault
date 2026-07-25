#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

workflow_dir="${BASTION_WORKFLOW_DIR:-.github/workflows}"
mapfile -d '' -t workflow_files < <(
  find "$workflow_dir" -maxdepth 1 -type f \
    \( -name '*.yml' -o -name '*.yaml' \) -print0 | sort -z
)
if (( ${#workflow_files[@]} == 0 )); then
  echo "No GitHub workflow files found in $workflow_dir." >&2
  exit 1
fi

status=0
while IFS= read -r entry; do
  ref="$(sed -E 's/.*uses:[[:space:]]+([^[:space:]#]+).*/\1/' <<<"$entry")"
  if [[ ! "$ref" =~ ^[^@[:space:]]+@[0-9a-f]{40}$ ]]; then
    echo "Unpinned GitHub Action: $entry" >&2
    status=1
  fi
done < <(
  grep -nH -E '^[[:space:]]*(-[[:space:]]+)?uses:' "${workflow_files[@]}" || true
)

if (( status != 0 )); then
  exit "$status"
fi

echo "GitHub Actions pin guard passed."
