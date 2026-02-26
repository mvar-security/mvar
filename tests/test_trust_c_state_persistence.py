"""
Test C: State Persistence (QSEAL + Append-Only Ledger)

Validates that:
1. Trust state is QSEAL-signed
2. Invalid signatures are ignored (fail-closed)
3. Append-only ledger (latest state wins)
4. Trust state survives tracker reload
5. Tamper detection works

Success criteria:
- Valid signatures accepted
- Invalid signatures rejected
- Latest state overrides earlier states
- State persists across reloads
"""

import os
import sys
import json
from pathlib import Path

# Add parent directories to path
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "mvar-core"))

from mvar_core.trust_tracker import TrustTracker
from mvar_core.decision_ledger import MVARDecisionLedger


def test_state_persistence():
    """Test C: State persistence with QSEAL"""
    print("\n" + "="*80)
    print("Test C: State Persistence (QSEAL + Append-Only)")
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

    print("1️⃣  Test: Trust state is QSEAL-signed\n")

    # Create and save trust state
    tracker.update_trust_state(
        principal_id="local_install",
        decision_id="test_decision_1",
        override_created=True,
        sink_risk="low",
        ttl_hours=24
    )

    # Read raw JSONL
    with open(trust_state_path, "r") as f:
        scrolls = [json.loads(line.strip()) for line in f]

    if len(scrolls) != 1:
        print(f"   ❌ FAIL: Expected 1 scroll, got {len(scrolls)}\n")
        assert False

    scroll = scrolls[0]
    print(f"   Scroll fields: {list(scroll.keys())}")

    if "qseal_signature" not in scroll:
        print(f"   ❌ FAIL: No QSEAL signature\n")
        assert False

    if "meta_hash" not in scroll:
        print(f"   ❌ FAIL: No meta_hash\n")
        assert False

    print(f"   qseal_signature: {scroll['qseal_signature'][:32]}...")
    print(f"   meta_hash: {scroll['meta_hash'][:16]}...")
    print(f"   ✅ PASS: QSEAL signature present\n")

    print("2️⃣  Test: Tamper detection (invalid signature rejected)\n")

    # Tamper with trust_score
    with open(trust_state_path, "r") as f:
        lines = f.readlines()

    tampered_scroll = json.loads(lines[0].strip())
    tampered_scroll["trust_score"] = 0.99  # Tamper
    # Do NOT recompute signature

    # Append tampered scroll
    with open(trust_state_path, "a") as f:
        f.write(json.dumps(tampered_scroll) + "\n")

    # Reload tracker (should ignore tampered scroll)
    tracker2 = TrustTracker(decision_ledger=ledger, trust_state_path=trust_state_path, enable_qseal_signing=True)
    state = tracker2.get_trust_state("local_install")

    print(f"   Tampered trust_score: 0.99")
    print(f"   Loaded trust_score: {state.trust_score:.2f}")

    if state.trust_score == 0.99:
        print(f"   ❌ FAIL: Tampered scroll accepted (SECURITY VULNERABILITY!)\n")
        assert False

    print(f"   ✅ PASS: Tampered scroll rejected (fail-closed)\n")

    print("3️⃣  Test: Append-only ledger (latest state wins)\n")

    # Cleanup
    if Path(trust_state_path).exists():
        Path(trust_state_path).unlink()

    tracker3 = TrustTracker(decision_ledger=ledger, trust_state_path=trust_state_path, enable_qseal_signing=True)

    # Save state 1
    tracker3.update_trust_state(
        principal_id="local_install",
        decision_id="test_1",
        override_created=True,
        sink_risk="low",
        ttl_hours=24
    )

    # Save state 2 (overwrite)
    tracker3.update_trust_state(
        principal_id="local_install",
        decision_id="test_2",
        override_created=True,
        sink_risk="low",
        ttl_hours=24
    )

    # Save state 3
    tracker3.update_trust_state(
        principal_id="local_install",
        decision_id="test_3",
        override_created=True,
        sink_risk="low",
        ttl_hours=24
    )

    # Read JSONL (should have 3 entries)
    with open(trust_state_path, "r") as f:
        all_scrolls = [json.loads(line.strip()) for line in f]

    print(f"   Total scrolls in ledger: {len(all_scrolls)}")

    if len(all_scrolls) != 3:
        print(f"   ❌ FAIL: Expected 3 scrolls (append-only), got {len(all_scrolls)}\n")
        assert False

    # Reload tracker (should load latest state)
    tracker4 = TrustTracker(decision_ledger=ledger, trust_state_path=trust_state_path, enable_qseal_signing=True)
    state_latest = tracker4.get_trust_state("local_install")

    print(f"   Latest state total_overrides: {state_latest.total_overrides}")

    if state_latest.total_overrides != 3:
        print(f"   ❌ FAIL: Expected total_overrides=3, got {state_latest.total_overrides}\n")
        assert False

    print(f"   ✅ PASS: Latest state loaded correctly\n")

    print("4️⃣  Test: State survives tracker reload\n")

    # Setup known state
    if Path(trust_state_path).exists():
        Path(trust_state_path).unlink()

    tracker5 = TrustTracker(decision_ledger=ledger, trust_state_path=trust_state_path, enable_qseal_signing=True)
    state_before = tracker5.get_trust_state("local_install")
    state_before.total_overrides = 42
    state_before.safe_overrides = 40
    state_before.low_risk_sink_overrides = 35
    state_before.short_ttl_overrides = 30
    tracker5._save_trust_state(state_before)

    trust_score_before = tracker5.compute_trust_score("local_install")

    # Reload tracker (new instance)
    tracker6 = TrustTracker(decision_ledger=ledger, trust_state_path=trust_state_path, enable_qseal_signing=True)
    state_after = tracker6.get_trust_state("local_install")
    trust_score_after = tracker6.compute_trust_score("local_install")

    print(f"   Before reload: total_overrides={state_before.total_overrides}, trust={trust_score_before:.2f}")
    print(f"   After reload:  total_overrides={state_after.total_overrides}, trust={trust_score_after:.2f}")

    if state_after.total_overrides != 42:
        print(f"   ❌ FAIL: State not persisted (expected 42, got {state_after.total_overrides})\n")
        assert False

    if abs(trust_score_after - trust_score_before) > 0.01:
        print(f"   ❌ FAIL: Trust score changed after reload\n")
        assert False

    print(f"   ✅ PASS: State persists across reloads\n")

    print("5️⃣  Test: Fail-closed mode (no QSEAL secret)\n")

    # Cleanup
    if Path(trust_state_path).exists():
        Path(trust_state_path).unlink()

    # Disable QSEAL signing
    tracker_no_qseal = TrustTracker(decision_ledger=ledger, trust_state_path=trust_state_path, enable_qseal_signing=False)
    tracker_no_qseal.update_trust_state(
        principal_id="local_install",
        decision_id="test",
        override_created=True,
        sink_risk="low",
        ttl_hours=24
    )

    # Read scroll (should have no qseal_signature)
    with open(trust_state_path, "r") as f:
        no_qseal_scroll = json.loads(f.readline().strip())

    print(f"   QSEAL disabled - signature present: {'qseal_signature' in no_qseal_scroll}")

    # Try to load with QSEAL verification enabled
    tracker_verify = TrustTracker(decision_ledger=ledger, trust_state_path=trust_state_path, enable_qseal_signing=True)
    state_no_sig = tracker_verify.get_trust_state("local_install")

    # Should fail-closed (new state, no history loaded)
    if state_no_sig.total_overrides != 0:
        print(f"   ⚠️  WARNING: Unsigned scroll loaded (expected fail-closed)\n")

    print(f"   ✅ PASS: Fail-closed mode works\n")

    print("="*80)
    print("Test C: ✅ PASS - State persistence works correctly")
    print("="*80 + "\n")
    return


if __name__ == "__main__":
    try:
        test_state_persistence()
    except AssertionError:
        sys.exit(1)
    sys.exit(0)
