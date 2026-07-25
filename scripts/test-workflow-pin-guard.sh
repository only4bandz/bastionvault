#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

test_root="$(mktemp -d)"
trap 'rm -rf "$test_root"' EXIT
workflow_dir="$test_root/workflows"
mkdir "$workflow_dir"

cat >"$workflow_dir/pinned.yml" <<'YAML'
name: pinned
jobs:
  test:
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5
YAML

BASTION_WORKFLOW_DIR="$workflow_dir" bash scripts/check-workflow-pins.sh >/dev/null

cat >"$workflow_dir/floating.yaml" <<'YAML'
name: floating
jobs:
  test:
    steps:
      - uses: actions/checkout@v4
YAML

if BASTION_WORKFLOW_DIR="$workflow_dir" bash scripts/check-workflow-pins.sh >/dev/null 2>&1; then
  echo "Workflow pin guard accepted a floating action in a .yaml file." >&2
  exit 1
fi

echo "GitHub Actions pin guard self-test passed."
