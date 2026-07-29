#!/bin/sh
set -eu

repository="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$repository"

run_drill() {
    drill_id="$1"
    test_filter="$2"
    expected_state="$3"
    operator_action="$4"
    recovery_point="$5"
    evidence_preservation="$6"
    echo "incident-drill: $drill_id" >&2
    cargo test --locked --offline "$test_filter" -- --exact >&2
    printf '    {"id":"%s","command":"cargo test --locked --offline %s -- --exact","expected_state":"%s","operator_action":"%s","recovery_point":"%s","evidence_preservation":"%s","status":"passed"}' \
        "$drill_id" "$test_filter" "$expected_state" "$operator_action" "$recovery_point" "$evidence_preservation"
}

printf '{\n  "schema_version":"telosieve.incident-drills/v1",\n'
printf '  "execution_mode":"local-offline-no-production-credentials",\n'
printf '  "drills":[\n'
run_drill "state-corruption" "actuator_store::tests::stale_corrupt_oversized_and_locked_state_fail_closed" "corrupt state refuses without mutation" "quarantine files and stop actuation" "last independently verified backup" "preserve state witness lock and error"
printf ',\n'
run_drill "witness-loss" "actuator_store::tests::committed_witness_loss_fails_closed" "missing committed witness is a stop condition" "stop and investigate witness loss" "no automatic recovery point" "preserve state and missing-witness error"
printf ',\n'
run_drill "full-ledger" "actuator_store::tests::full_consumption_ledger_does_not_apply_or_advance" "capacity refusal preserves state and history" "stop deletions and retain the ledger" "unchanged pre-request state" "preserve ledger state and refusal"
printf ',\n'
run_drill "stale-lock" "anchor_store::tests::missing_corrupt_and_locked_stores_fail_closed" "lock contention refuses without guessing ownership" "prove owner death before lock removal" "unchanged anchored state" "preserve lock metadata state and error"
printf ',\n'
run_drill "bad-upgrade" "actuator_store::tests::legacy_upgrade_preserves_consumption_and_is_recoverable" "interrupted upgrade retains exact legacy state" "invoke recovery without retrying actuation" "committed legacy state" "preserve legacy state witness and recovery result"
printf ',\n'
run_drill "key-compromise" "protocol::key_lifecycle_tests::recovery_root_can_activate_a_fresh_key_after_revocation" "offline recovery root revokes and replaces compromised key" "revoke key and activate replacement from offline root" "last trusted lifecycle tip" "preserve compromise evidence lifecycle chain and signatures"
printf ',\n'
run_drill "lifecycle-rollback" "protocol::key_lifecycle_tests::lifecycle_rollback_equivocation_kind_mismatch_and_bounds_fail_closed" "trusted-tip rollback and equivocation fail closed" "stop issuance and investigate trust-store integrity" "last trusted lifecycle tip" "preserve candidate chain trusted tip and verification error"
printf '\n  ],\n  "passed":7,\n  "failed":0\n}\n'
echo "incident-drill: passed 7/7" >&2
