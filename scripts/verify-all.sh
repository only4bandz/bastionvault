#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

run() {
  echo
  echo "==> $*"
  "$@"
}

run cargo fmt --all -- --check
run cargo test --workspace --all-features --locked
run cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
run bash scripts/test-backup-restore.sh
run bash -n scripts/verify-production-edge.sh
run wasm-pack test --node crates/crypto-wasm

run bash app/build-wasm.sh
run npm ci --prefix app
run npm run lint --prefix app
run npm test --prefix app
run npm run build --prefix app

run npm test --prefix extension
echo
echo "==> Check extension JavaScript syntax"
find extension \
  -path extension/node_modules -prune -o \
  -path extension/pkg -prune -o \
  -name '*.js' -print0 | xargs -0 -n1 node --check
run bash extension/build.sh
run python3 scripts/check-release.py
run bash web/build.sh

run bash scripts/check-no-browser-secret-storage.sh
run bash scripts/check-no-vault-metadata-egress.sh
run bash scripts/check-web-demo-csp.sh
run bash scripts/check-app-csp.sh
run git diff --check

echo
echo "All Bastion validation gates passed."
