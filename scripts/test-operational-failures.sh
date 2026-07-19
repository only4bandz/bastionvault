#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

run() {
  echo
  echo "==> $*"
  "$@"
}

# These are deterministic release-level fault tests. Destructive host, disk,
# ingress, and provider drills belong on an isolated deployment environment.
run cargo test -p server --lib --locked \
  tests::blocked_sqlite_does_not_block_tokio_and_queue_saturation_fails_fast -- --exact
run cargo test -p server --lib --locked \
  tests::delayed_accepted_mutation_finishes_then_quarantines_the_instance -- --exact
run cargo test -p server --test api --locked \
  refuses_a_second_server_for_the_same_database -- --exact
run cargo test -p server --test api --locked \
  live_backup_restores_vault_and_send_state -- --exact
run cargo test -p server --lib --locked \
  mail_outbox::tests::transient_failure_retries_with_the_same_stable_id -- --exact
run cargo test -p server --lib --locked \
  mail_outbox::tests::expired_lease_is_recovered_and_permanent_failure_is_scrubbed -- --exact
run cargo test -p server --lib --locked \
  mail_outbox::tests::expired_final_attempt_is_not_delivered_a_ninth_time -- --exact

echo
echo "Deterministic operational failure gates passed."
