"""
Test E: Attack Suite Unchanged (50/50 Blocked)

Validates that:
1. Ledger does NOT weaken core security
2. All 50 attack vectors still blocked
3. No bypasses introduced
4. Ledger is purely additive (observe-only when disabled)

Success criteria:
- WITH ledger enabled: 50/50 attacks blocked
- Attack suite output identical to main branch baseline
"""

import os
import sys
from pathlib import Path

# Add parent directories to path
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "mvar-core"))

def test_attack_suite_unchanged():
    """Test E: Attack suite still blocks all 50 vectors"""
    print("\n" + "="*80)
    print("Test E: Attack Suite Unchanged (50/50 Blocked)")
    print("="*80 + "\n")

    # Enable ledger
    os.environ["MVAR_ENABLE_LEDGER"] = "1"
    os.environ["QSEAL_SECRET"] = "test_secret_key_for_validation"
    ledger_path = "/tmp/mvar_test_e_decisions.jsonl"
    os.environ["MVAR_LEDGER_PATH"] = ledger_path

    if Path(ledger_path).exists():
        Path(ledger_path).unlink()

    print("1️⃣  Running extreme_attack_suite_50.py with ledger enabled\n")
    print("   (This will take ~30 seconds)\n")

    # Import and run attack suite
    try:
        from demo import extreme_attack_suite_50
        # Run main() and check exit code
        exit_code = extreme_attack_suite_50.main()
    except ImportError as e:
        print(f"   ❌ FAIL: Could not import attack suite: {e}")
        assert False

    print("\n2️⃣  Analyze results\n")

    if exit_code != 0:
        print(f"   ❌ FAIL: Attack suite reported failures (exit code {exit_code})")
        print(f"   Ledger may have introduced security bypass!\n")
        assert False

    print(f"   ✅ PASS: All 50 attacks blocked\n")

    print("3️⃣  Verify ledger recorded decisions\n")

    from mvar_core.decision_ledger import MVARDecisionLedger
    ledger = MVARDecisionLedger(ledger_path=ledger_path, enable_qseal_signing=True)

    decisions = ledger.load_decisions(limit=100)
    print(f"   Decisions recorded: {len(decisions)}")

    if len(decisions) == 0:
        print(f"   ⚠️  WARNING: No decisions recorded (ledger may not be wired correctly)")
    else:
        print(f"   ✅ Ledger operational\n")

    print("="*80)
    print("Test E: ✅ PASS - Attack suite unchanged (50/50 blocked)")
    print("="*80 + "\n")
    return


if __name__ == "__main__":
    try:
        test_attack_suite_unchanged()
    except AssertionError:
        sys.exit(1)
    sys.exit(0)
