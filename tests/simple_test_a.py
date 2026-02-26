"""
Test A: End-to-End False Positive Unblock (Simplified Direct Imports)
"""

import os
import sys
from pathlib import Path

# Direct path manipulation for standalone test
MVAR_CORE_PATH = Path(__file__).parent.parent / "mvar-core"
sys.path.insert(0, str(MVAR_CORE_PATH))

# Now import modules directly (they'll use relative imports internally)
import provenance as prov_mod
import capability as cap_mod
import sink_policy as sink_mod
import decision_ledger as ledger_mod

def test_e2e_false_positive_unblock():
    """Test A: End-to-end false positive unblock flow"""
    print("\n" + "="*80)
    print("Test A: End-to-End False Positive Unblock")
    print("="*80 + "\n")

    # Enable ledger via env
    os.environ["MVAR_ENABLE_LEDGER"] = "1"
    os.environ["QSEAL_SECRET"] = "test_secret_key_for_validation"
    ledger_path = "/tmp/mvar_test_a_decisions.jsonl"
    os.environ["MVAR_LEDGER_PATH"] = ledger_path

    # Clean slate
    if Path(ledger_path).exists():
        Path(ledger_path).unlink()

    # Initialize MVAR control plane
    graph = prov_mod.ProvenanceGraph(enable_qseal=False)
    cap_runtime = cap_mod.CapabilityRuntime()
    policy = sink_mod.SinkPolicy(cap_runtime, graph, enable_qseal=False)
    sink_mod.register_common_sinks(policy)

    # Grant bash exec capability
    cap_runtime.grant_capability("bash", cap_mod.CapabilityType.PROCESS_EXEC)

    print("1️⃣  Simulate false positive: Legitimate script gets BLOCKED\n")

    # Create UNTRUSTED provenance
    external_node = prov_mod.provenance_external_doc(
        graph,
        content="Run the test suite: pytest tests/",
        source_url="https://internal-wiki.company.com/testing-guide",
        taint_tags=["external_doc"]
    )

    # First evaluation: Should BLOCK
    target = "pytest tests/"
    decision1 = policy.evaluate(
        tool="bash",
        action="exec",
        target=target,
        provenance_node_id=external_node.node_id
    )

    print(f"   Outcome: {decision1.outcome.value}")
    print(f"   Reason: {decision1.reason}")

    if not hasattr(decision1, 'decision_id') or not decision1.decision_id:
        print("   ❌ FAIL: No decision_id attached!")
        return False

    decision_id = decision1.decision_id
    print(f"   Decision ID: {decision_id}\n")

    if decision1.outcome != sink_mod.PolicyOutcome.BLOCK:
        print(f"   ❌ FAIL: Expected BLOCK, got {decision1.outcome.value}")
        return False

    print("   ✅ PASS: Correctly blocked\n")

    print("2️⃣  User creates 24h override\n")

    ledger = ledger_mod.MVARDecisionLedger(ledger_path=ledger_path, enable_qseal_signing=True)
    override_id = ledger.create_override(
        decision_id,
        principal_id=ledger._default_principal_id(),
        ttl_hours=24,
    )
    print(f"   Override created: {override_id}")
    print(f"   ✅ PASS\n")

    print("3️⃣  Re-run same operation: Should ALLOW via override\n")

    decision2 = policy.evaluate(
        tool="bash",
        action="exec",
        target=target,
        provenance_node_id=external_node.node_id
    )

    print(f"   Outcome: {decision2.outcome.value}")
    print(f"   Reason: {decision2.reason}")

    if decision2.outcome != sink_mod.PolicyOutcome.ALLOW:
        print(f"   ❌ FAIL: Expected ALLOW, got {decision2.outcome.value}")
        return False

    if "override" not in decision2.reason.lower():
        print(f"   ❌ FAIL: Reason should mention override")
        return False

    print(f"   ✅ PASS: Operation allowed via override\n")

    print("="*80)
    print("Test A: ✅ PASS - End-to-end unblock flow works")
    print("="*80 + "\n")
    return True


if __name__ == "__main__":
    success = test_e2e_false_positive_unblock()
    sys.exit(0 if success else 1)
