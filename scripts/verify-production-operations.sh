#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <https-origin> <live-database> <new-local-backup-path>" >&2
  exit 2
fi

origin=${1%/}
database=$2
backup=$3
backup_bin=${BASTION_BACKUP_BIN:-bastion-backup}
status_bin=${BASTION_OPS_STATUS_BIN:-bastion-ops-status}
max_database_bytes=${BASTION_MAX_DATABASE_BYTES:-}
max_accounts=${BASTION_MAX_ACCOUNTS:-}
max_mail_age=${BASTION_MAX_ACTIVE_MAIL_AGE_SECONDS:-300}
max_backup_verify_seconds=${BASTION_MAX_BACKUP_VERIFY_SECONDS:-3600}
acknowledged_dead_mail=${BASTION_ACKNOWLEDGED_DEAD_MAIL:-0}

for value_name in BASTION_MAX_DATABASE_BYTES BASTION_MAX_ACCOUNTS; do
  if [[ -z ${!value_name:-} || ! ${!value_name} =~ ^[1-9][0-9]*$ ]]; then
    echo "$value_name must be a positive measured deployment limit" >&2
    exit 2
  fi
done
for pair in \
  "BASTION_MAX_ACTIVE_MAIL_AGE_SECONDS:$max_mail_age" \
  "BASTION_MAX_BACKUP_VERIFY_SECONDS:$max_backup_verify_seconds" \
  "BASTION_ACKNOWLEDGED_DEAD_MAIL:$acknowledged_dead_mail"; do
  name=${pair%%:*}
  value=${pair#*:}
  if [[ ! $value =~ ^[0-9]+$ || ($name != BASTION_ACKNOWLEDGED_DEAD_MAIL && $value == 0) ]]; then
    echo "$name must be a non-negative integer (and non-zero for time budgets)" >&2
    exit 2
  fi
done
if [[ $database != /* || $backup != /* ]]; then
  echo "database and backup paths must be absolute" >&2
  exit 2
fi
if [[ ! -f $database ]]; then
  echo "live database does not exist: $database" >&2
  exit 2
fi
if [[ -e $backup ]]; then
  echo "backup destination already exists (no-clobber): $backup" >&2
  exit 2
fi
for command in "$backup_bin" "$status_bin" curl python3; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "required command not found: $command" >&2
    exit 2
  fi
done

script_dir=$(cd "$(dirname "$0")" && pwd)
"$script_dir/verify-production-edge.sh" "$origin"

echo "Checking public liveness and storage readiness"
curl --silent --show-error --fail --max-time 15 --output /dev/null \
  "$origin/api/v1/livez"
curl --silent --show-error --fail --max-time 15 --output /dev/null \
  "$origin/api/v1/readyz"

validate_snapshot() {
  local label=$1
  local json=$2
  python3 - "$label" "$max_database_bytes" "$max_accounts" "$max_mail_age" \
    "$acknowledged_dead_mail" \
    3<<<"$json" <<'PY'
import json
import os
import sys

label, max_database_bytes, max_accounts, max_mail_age, acknowledged_dead_mail = sys.argv[1:]
with os.fdopen(3) as snapshot_input:
    snapshot = json.load(snapshot_input)
required = {
    "observed_at",
    "schema_version",
    "database_bytes",
    "accounts",
    "registration_challenges_active",
    "registration_challenges_verified",
    "registration_challenges_expired",
    "mail_pending",
    "mail_in_flight",
    "mail_dead",
    "oldest_active_mail_age_seconds",
}
if set(snapshot) != required:
    raise SystemExit(f"{label}: unexpected operational snapshot fields")
for key in required - {"oldest_active_mail_age_seconds"}:
    if type(snapshot[key]) is not int or snapshot[key] < 0:
        raise SystemExit(f"{label}: invalid {key}")
age = snapshot["oldest_active_mail_age_seconds"]
if age is not None and (type(age) is not int or age < 0):
    raise SystemExit(f"{label}: invalid oldest_active_mail_age_seconds")
if snapshot["database_bytes"] > int(max_database_bytes):
    raise SystemExit(f"{label}: measured database capacity exceeded")
if snapshot["accounts"] > int(max_accounts):
    raise SystemExit(f"{label}: measured account capacity exceeded")
if snapshot["mail_dead"] > int(acknowledged_dead_mail):
    raise SystemExit(f"{label}: new dead transactional mail requires incident review")
if snapshot["registration_challenges_expired"]:
    raise SystemExit(f"{label}: expired registration challenges are not being reaped")
if age is not None and age > int(max_mail_age):
    raise SystemExit(f"{label}: active transactional mail is too old")
print(json.dumps(snapshot, sort_keys=True, separators=(",", ":")))
PY
}

echo "Inspecting aggregate live storage state"
live_snapshot=$("$status_bin" "$database")
validate_snapshot live "$live_snapshot"

echo "Creating and verifying a no-clobber online backup"
started_at=$(date +%s)
"$backup_bin" "$database" "$backup"
backup_snapshot=$("$status_bin" "$backup")
validate_snapshot backup "$backup_snapshot"
finished_at=$(date +%s)
backup_verify_seconds=$((finished_at - started_at))
if (( backup_verify_seconds > max_backup_verify_seconds )); then
  echo "backup verification exceeded its budget: ${backup_verify_seconds}s" >&2
  exit 1
fi

echo "Production operations baseline passed in ${backup_verify_seconds}s"
echo "The local backup remains sensitive plaintext: encrypt and transfer it off-host, then remove it under the approved retention procedure: $backup"
