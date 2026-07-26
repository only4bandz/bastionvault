#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

run_exact() {
  echo
  echo "==> cargo test $* -- --exact"
  local output
  output=$(mktemp)
  if ! cargo test "$@" -- --exact 2>&1 | tee "$output"; then
    rm -f "$output"
    return 1
  fi
  if ! grep -Eq 'test result: ok\. 1 passed; 0 failed;' "$output"; then
    echo "exact operational test did not execute exactly one passing test" >&2
    rm -f "$output"
    return 1
  fi
  rm -f "$output"
}

# These are deterministic release-level fault tests. Destructive host, disk,
# ingress, and provider drills belong on an isolated deployment environment.
run_exact -p server --lib --locked \
  tests::blocked_sqlite_does_not_block_tokio_and_queue_saturation_fails_fast
run_exact -p server --lib --locked \
  tests::delayed_mutation_sheds_new_storage_work_then_recovers
run_exact -p server --lib --locked \
  tests::a_failed_slow_mutation_recovers_without_false_quarantine
run_exact -p server --lib --locked \
  tests::concurrent_uncached_readiness_has_one_storage_probe_in_flight
run_exact -p server --test api --locked \
  refuses_a_second_server_for_the_same_database
run_exact -p server --test api --locked \
  live_backup_restores_vault_and_send_state
run_exact -p server --lib --locked \
  mail_outbox::tests::transient_failure_retries_with_the_same_stable_id
run_exact -p server --lib --locked \
  mail_outbox::tests::expired_lease_is_recovered_and_permanent_failure_is_scrubbed
run_exact -p server --lib --locked \
  mail_outbox::tests::expired_final_attempt_is_not_delivered_a_ninth_time

echo
echo "Deterministic operational failure gates passed."
