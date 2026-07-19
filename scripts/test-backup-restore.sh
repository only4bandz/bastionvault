#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

cargo test -p server --test api live_backup_restores_vault_and_send_state --locked -- --exact
