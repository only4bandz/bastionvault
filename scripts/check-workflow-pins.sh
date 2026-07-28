#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

# Scans all of .github, not just .github/workflows: `uses:` also appears in
# composite action definitions (.github/actions/*/action.yml), which a
# depth-1 scan of the workflows directory silently skipped. An unpinned
# third-party action introduced there would ship unchecked — exactly the
# supply-chain hole this guard exists to close.
workflow_dir="${BASTION_WORKFLOW_DIR:-.github}"
mapfile -d '' -t workflow_files < <(
  find "$workflow_dir" -type f \
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
