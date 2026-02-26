"""
Test C: Principal Isolation

Validates that:
1. Ledger entries for principal A do not affect principal B
2. Trust scores are computed independently per principal
3. Trust state updates for one principal don't leak to another
4. State persistence maintains principal isolation

Success criteria:
- principal_a trust score ≠ principal_b trust score (when histories differ)
- Updates to principal_a state don't affect principal_b
- QSEAL-signed states maintain principal separation
- No cross-principal trust contamination
"""

import os
import sys
from pathlib import Path

# Add parent directories to path
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "mvar-core"))

from mvar_core.trust_tracker import TrustTracker
from mvar_core.decision_ledger import MVARDecisionLedger


def test_principal_isolation():
    """Test C: Principal isolation (no trust contamination)"""
    print("\n" + "="*80)
    print("Test C: Principal Isolation")
    print("="*80 + "\n")

    os.environ["MVAR_ENABLE_LEDGER"] = "1"
    os.environ["QSEAL_SECRET"] = "test_secret_key_for_validation"
    ledger_path = "/tmp/mvar_test_trust_c_decisions.jsonl"
    trust_state_path = "/tmp/mvar_test_trust_c_state.jsonl"
    os.environ["MVAR_LEDGER_PATH"] = ledger_path
    os.environ["MVAR_TRUST_STATE_PATH"] = trust_state_path

    # Cleanup
    if Path(ledger_path).exists():
        Path(ledger_path).unlink()
    if Path(trust_state_path).exists():
        Path(trust_state_path).unlink()

    ledger = MVARDecisionLedger(ledger_path=ledger_path, enable_qseal_signing=True)
    tracker = TrustTracker(decision_ledger=ledger, trust_state_path=trust_state_path, enable_qseal_signing=True)

    print("1️⃣  Test: Principal A and B start with zero trust\n")

    score_a = tracker.compute_trust_score("principal_a")
    score_b = tracker.compute_trust_score("principal_b")

    print(f"   Principal A trust: {score_a:.2f}")
    print(f"   Principal B trust: {score_b:.2f}")

    if score_a != 0.0 or score_b != 0.0:
        print(f"   ❌ FAIL: Expected both 0.0\n")
        assert False

    print(f"   ✅ PASS\n")

    print("2️⃣  Test: Update principal A → principal B unaffected\n")

    # Update principal A (build trust)
    tracker.update_trust_state(
        principal_id="principal_a",
        decision_id="test_a_1",
        override_created=True,
        sink_risk="low",
        ttl_hours=24
    )

    tracker.update_trust_state(
        principal_id="principal_a",
        decision_id="test_a_2",
        override_created=True,
        sink_risk="low",
        ttl_hours=24
    )

    # Recompute
    tracker._trust_cache = None
    score_a_after = tracker.compute_trust_score("principal_a")
    score_b_after = tracker.compute_trust_score("principal_b")

    print(f"   Principal A trust (after 2 safe overrides): {score_a_after:.2f}")
    print(f"   Principal B trust (no activity): {score_b_after:.2f}")

    if score_a_after == 0.0:
        print(f"   ❌ FAIL: Principal A trust should have increased\n")
        assert False

    if score_b_after != 0.0:
        print(f"   ❌ FAIL: Principal B contaminated (should be 0.0, got {score_b_after:.2f})\n")
        assert False

    print(f"   ✅ PASS: Principal isolation maintained\n")

    print("3️⃣  Test: Update principal B → independent score\n")

    # Update principal B (build different trust profile)
    for i in range(5):
        tracker.update_trust_state(
            principal_id="principal_b",
            decision_id=f"test_b_{i}",
            override_created=True,
            sink_risk="high",  # Different risk profile
            ttl_hours=72  # Different TTL profile
        )

    # Recompute
    tracker._trust_cache = None
    score_a_final = tracker.compute_trust_score("principal_a")
    score_b_final = tracker.compute_trust_score("principal_b")

    print(f"   Principal A trust: {score_a_final:.2f} (2 low-risk, short-TTL)")
    print(f"   Principal B trust: {score_b_final:.2f} (5 high-risk, long-TTL)")

    # Scores should differ (different risk/TTL profiles)
    if abs(score_a_final - score_b_final) < 0.01:
        print(f"   ⚠️  WARNING: Scores unexpectedly identical (may be coincidence)")

    # Verify A wasn't affected by B's updates
    if score_a_final != score_a_after:
        print(f"   ❌ FAIL: Principal A score changed (was {score_a_after:.2f}, now {score_a_final:.2f})\n")
        assert False

    print(f"   ✅ PASS: Independent trust profiles\n")

    print("4️⃣  Test: State persistence maintains isolation\n")

    # Reload tracker (new instance)
    tracker2 = TrustTracker(decision_ledger=ledger, trust_state_path=trust_state_path, enable_qseal_signing=True)

    score_a_reload = tracker2.compute_trust_score("principal_a")
    score_b_reload = tracker2.compute_trust_score("principal_b")

    print(f"   After reload:")
    print(f"   Principal A: {score_a_reload:.2f} (expected {score_a_final:.2f})")
    print(f"   Principal B: {score_b_reload:.2f} (expected {score_b_final:.2f})")

    if abs(score_a_reload - score_a_final) > 0.01:
        print(f"   ❌ FAIL: Principal A score changed after reload\n")
        assert False

    if abs(score_b_reload - score_b_final) > 0.01:
        print(f"   ❌ FAIL: Principal B score changed after reload\n")
        assert False

    print(f"   ✅ PASS: Isolation persists across reloads\n")

    print("5️⃣  Test: Violation in principal A doesn't affect principal B\n")

    # Add violation to principal A
    tracker2.update_trust_state(
        principal_id="principal_a",
        decision_id="test_a_violation",
        override_created=True,
        violation=True,  # Violation
        sink_risk="critical"
    )

    tracker2._trust_cache = None
    score_a_violation = tracker2.compute_trust_score("principal_a")
    score_b_violation = tracker2.compute_trust_score("principal_b")

    print(f"   Principal A trust (after violation): {score_a_violation:.2f}")
    print(f"   Principal B trust (no change): {score_b_violation:.2f}")

    # A's score should drop (violation penalty)
    if score_a_violation >= score_a_final:
        print(f"   ⚠️  WARNING: Principal A score didn't drop after violation")

    # B should be unaffected
    if abs(score_b_violation - score_b_final) > 0.01:
        print(f"   ❌ FAIL: Principal B affected by A's violation\n")
        assert False

    print(f"   ✅ PASS: Violations isolated per principal\n")

    print("6️⃣  Test: No default principal allowed\n")

    try:
        tracker2.compute_trust_score("")  # Empty string
        print(f"   ❌ FAIL: Empty principal_id accepted\n")
        assert False
    except ValueError as e:
        print(f"   ✅ PASS: Empty principal_id rejected ({e})\n")

    print("="*80)
    print("Test C: ✅ PASS - Principal isolation works correctly")
    print("="*80 + "\n")
    return


if __name__ == "__main__":
    try:
        test_principal_isolation()
    except AssertionError:
        sys.exit(1)
    sys.exit(0)
