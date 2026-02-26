"""
Test D: Revocation Works Correctly

Validates that:
1. Override works before revocation
2. Expiry scroll created
3. Override does NOT work after revocation
4. Append-only pattern (no deletes)

Success criteria:
- Override matches before expiry scroll
- Expiry scroll created successfully
- Override does NOT match after expiry scroll
- Ledger still contains all scrolls (append-only)
"""

import os
import sys
from pathlib import Path

# Add mvar-core to path
sys.path.insert(0, str(Path(__file__).parent.parent / "mvar-core"))

from mvar_core.decision_ledger import MVARDecisionLedger
from mvar_core.provenance import ProvenanceGraph, provenance_external_doc
from mvar_core.capability import CapabilityRuntime, CapabilityType, build_shell_tool
from mvar_core.sink_policy import SinkPolicy, register_common_sinks, PolicyOutcome


def test_revocation():
    """Test D: Revocation works correctly"""
    print("\n" + "="*80)
    print("Test D: Revocation Works Correctly")
    print("="*80 + "\n")

    os.environ["MVAR_ENABLE_LEDGER"] = "1"
    os.environ["QSEAL_SECRET"] = "test_secret_key_for_validation"
    ledger_path = "/tmp/mvar_test_d_decisions.jsonl"
    os.environ["MVAR_LEDGER_PATH"] = ledger_path

    if Path(ledger_path).exists():
        Path(ledger_path).unlink()

    graph = ProvenanceGraph(enable_qseal=True)
    cap_runtime = CapabilityRuntime()
    policy = SinkPolicy(cap_runtime, graph, enable_qseal=True)
    register_common_sinks(policy)
    bash_manifest = build_shell_tool("bash", ["*"], [])
    cap_runtime.manifests["bash"] = bash_manifest

    print("1️⃣  Create decision + override\n")

    external_node = provenance_external_doc(graph, "command", "https://example.com", {"taint_tags": ["external"]})
    target = "echo 'test'"
    decision = policy.evaluate("bash", "exec", target, external_node.node_id)
    decision_id = decision.decision_id

    ledger = MVARDecisionLedger(ledger_path=ledger_path, enable_qseal_signing=True)
    principal_id = ledger._default_principal_id()
    override_id = ledger.create_override(decision_id, principal_id=principal_id, ttl_hours=24)

    print(f"   Decision: {decision_id}")
    print(f"   Override: {override_id}")
    print(f"   ✅ Created\n")

    print("2️⃣  Verify override works BEFORE revocation\n")

    sink = policy.get_sink("bash", "exec")
    matched = ledger.check_override(sink, target, principal_id)

    if not matched:
        print(f"   ❌ FAIL: Override should match before revocation")
        assert False

    print(f"   ✅ PASS: Override matches\n")

    print("3️⃣  Revoke override (create expiry scroll)\n")

    expiry_id = ledger.expire_override(override_id)
    print(f"   Expiry ID: {expiry_id}")
    print(f"   ✅ Expiry scroll created\n")

    print("4️⃣  Verify ledger contains all scrolls (append-only)\n")

    all_scrolls = ledger._load_scrolls_raw()  # Load all scrolls (including expired)
    decisions = [s for s in all_scrolls if s["scroll_type"] == "decision"]
    overrides = [s for s in all_scrolls if s["scroll_type"] == "override"]
    expiries = [s for s in all_scrolls if s["scroll_type"] == "expiry"]

    print(f"   Total scrolls: {len(all_scrolls)}")
    print(f"   Decisions: {len(decisions)}")
    print(f"   Overrides: {len(overrides)}")
    print(f"   Expiries: {len(expiries)}")

    if len(overrides) != 1:
        print(f"   ❌ FAIL: Override should still exist in ledger")
        assert False

    if len(expiries) != 1:
        print(f"   ❌ FAIL: Expected 1 expiry scroll")
        assert False

    print(f"   ✅ PASS: All scrolls preserved (append-only)\n")

    print("5️⃣  Verify override does NOT work AFTER revocation\n")

    # Invalidate cache
    ledger._scroll_cache = None
    matched = ledger.check_override(sink, target, principal_id)

    if matched:
        print(f"   ❌ FAIL: Override should NOT match after revocation")
        assert False

    print(f"   ✅ PASS: Revoked override filtered out\n")

    print("6️⃣  Verify operation BLOCKED again\n")

    decision2 = policy.evaluate("bash", "exec", target, external_node.node_id)

    if decision2.outcome != PolicyOutcome.BLOCK:
        print(f"   ❌ FAIL: Should BLOCK after revocation")
        assert False

    print(f"   ✅ PASS: Operation blocked (override revoked)\n")

    print("="*80)
    print("Test D: ✅ PASS - Revocation works correctly")
    print("="*80 + "\n")
    return


if __name__ == "__main__":
    try:
        test_revocation()
    except AssertionError:
        sys.exit(1)
    sys.exit(0)
