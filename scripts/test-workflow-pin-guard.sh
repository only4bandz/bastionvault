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

# A composite action definition is not in the workflows directory, and its
# `uses:` entries are just as capable. The guard must reach them.
nested_root="$(mktemp -d)"
trap 'rm -rf "$test_root" "$nested_root"' EXIT
mkdir -p "$nested_root/workflows" "$nested_root/actions/setup"
cat >"$nested_root/workflows/pinned.yml" <<'YAML'
name: pinned
jobs:
  test:
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5
YAML
cat >"$nested_root/actions/setup/action.yml" <<'YAML'
name: setup
runs:
  using: composite
  steps:
    - uses: actions/setup-node@v4
YAML

if BASTION_WORKFLOW_DIR="$nested_root" bash scripts/check-workflow-pins.sh >/dev/null 2>&1; then
  echo "Workflow pin guard missed a floating action in a composite action." >&2
  exit 1
fi

echo "GitHub Actions pin guard self-test passed."
