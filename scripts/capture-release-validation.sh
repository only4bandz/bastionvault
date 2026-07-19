#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <new-validation-log>" >&2
  exit 2
fi

cd "$(dirname "$0")/.."
output=$1
if [[ $output != /* ]]; then
  echo "validation log path must be absolute" >&2
  exit 2
fi
if [[ -n $(git status --porcelain) ]]; then
  echo "release validation requires a clean worktree" >&2
  exit 1
fi
set -o noclobber
: >"$output"
set +o noclobber

commit=$(git rev-parse HEAD^{commit})
tree=$(git rev-parse HEAD^{tree})
started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)

set +e
{
  echo "BASTION_RELEASE_VALIDATION_V1"
  echo "commit=$commit"
  echo "tree=$tree"
  echo "started_at=$started_at"
  bash scripts/verify-all.sh
  status=$?
  if [[ $status -eq 0 ]]; then
    echo "result=passed"
  else
    echo "result=failed:$status"
  fi
  exit "$status"
} 2>&1 | tee -a "$output"
statuses=("${PIPESTATUS[@]}")
set -e
if [[ ${statuses[0]} -ne 0 ]]; then
  exit "${statuses[0]}"
fi
exit "${statuses[1]}"
