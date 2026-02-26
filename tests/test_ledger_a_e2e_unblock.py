"""
Test A: End-to-End False Positive Unblock

Validates that:
1. A legitimate operation gets BLOCKED (false positive)
2. User creates override
3. Same operation now ALLOWED via override
4. Override decision is recorded with correct provenance

Success criteria:
- First call: BLOCK
- Override created successfully
- Second call (same target): ALLOW with override reason
- Ledger contains both decision + override scrolls
"""

import os
import sys
from pathlib import Path

# Import from mvar_core package (requires setup.py install -e . or package in PYTHONPATH)
from mvar_core.provenance import ProvenanceGraph, provenance_user_input, provenance_external_doc
from mvar_core.capability import CapabilityRuntime, CapabilityType, build_shell_tool
from mvar_core.sink_policy import SinkPolicy, SinkClassification, SinkRisk, PolicyOutcome, register_common_sinks
from mvar_core.decision_ledger import MVARDecisionLedger


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
    graph = ProvenanceGraph(enable_qseal=True)
    cap_runtime = CapabilityRuntime()
    policy = SinkPolicy(cap_runtime, graph, enable_qseal=True)
    register_common_sinks(policy)

    # Grant bash exec capability
    bash_manifest = build_shell_tool("bash", ["*"], [])
    cap_runtime.manifests["bash"] = bash_manifest

    print("1️⃣  Simulate false positive: Legitimate script gets BLOCKED")
    print("   (User wants to run: 'pytest tests/' but it's flagged as untrusted)\n")

    # Create UNTRUSTED provenance (simulating external doc with command)
    external_node = provenance_external_doc(
        graph,
        content="Run the test suite: pytest tests/",
        doc_url="https://internal-wiki.company.com/testing-guide",
        metadata={"taint_tags": ["external_doc"]}
    )

    # First evaluation: Should BLOCK (UNTRUSTED + CRITICAL)
    target = "pytest tests/"
    decision1 = policy.evaluate(
        tool="bash",
        action="exec",
        target=target,
        provenance_node_id=external_node.node_id
    )

    print(f"   Outcome: {decision1.outcome.value}")
    print(f"   Reason: {decision1.reason}")
    if hasattr(decision1, 'decision_id') and decision1.decision_id:
        print(f"   Decision ID: {decision1.decision_id}\n")
        decision_id = decision1.decision_id
    else:
        print("   ❌ ERROR: No decision_id attached!")
        assert False

    if decision1.outcome != PolicyOutcome.BLOCK:
        print(f"   ❌ FAIL: Expected BLOCK, got {decision1.outcome.value}")
        assert False

    print("   ✅ PASS: Correctly blocked untrusted command\n")

    print("2️⃣  User reviews decision and creates 24h override")
    print(f"   (User runs: mvar allow add {decision_id})\n")

    # Create override
    ledger = MVARDecisionLedger(ledger_path=ledger_path, enable_qseal_signing=True)
    principal_id = ledger._default_principal_id()
    try:
        override_id = ledger.create_override(
            original_decision_id=decision_id,
            principal_id=principal_id,
            ttl_hours=24
        )
        print(f"   Override created: {override_id}")
        print(f"   ✅ PASS: Override scroll created\n")
    except Exception as e:
        print(f"   ❌ FAIL: Override creation failed: {e}")
        assert False

    print("3️⃣  Re-run same operation: Should ALLOW via override\n")

    # Second evaluation: Should ALLOW (override active)
    decision2 = policy.evaluate(
        tool="bash",
        action="exec",
        target=target,
        provenance_node_id=external_node.node_id
    )

    print(f"   Outcome: {decision2.outcome.value}")
    print(f"   Reason: {decision2.reason}")

    if decision2.outcome != PolicyOutcome.ALLOW:
        print(f"   ❌ FAIL: Expected ALLOW, got {decision2.outcome.value}")
        assert False

    if "override" not in decision2.reason.lower():
        print(f"   ❌ FAIL: Reason should mention override")
        assert False

    print(f"   ✅ PASS: Operation allowed via override\n")

    print("4️⃣  Verify ledger integrity")
    print(f"   (Ledger: {ledger_path})\n")

    # Verify ledger contains both decision + override
    decisions = ledger.load_decisions()
    overrides = ledger.load_overrides()

    print(f"   Decisions recorded: {len(decisions)}")
    print(f"   Overrides recorded: {len(overrides)}")

    if len(decisions) < 1:
        print(f"   ❌ FAIL: No decisions in ledger")
        assert False

    if len(overrides) != 1:
        print(f"   ❌ FAIL: Expected 1 override, got {len(overrides)}")
        assert False

    # Verify signature chain
    all_scrolls = ledger._load_scrolls()
    print(f"   Total scrolls: {len(all_scrolls)}")
    verified_count = sum(1 for s in all_scrolls if ledger._verify_scroll(s))
    print(f"   Verified signatures: {verified_count}/{len(all_scrolls)}")

    if verified_count != len(all_scrolls):
        print(f"   ❌ FAIL: Some signatures invalid")
        assert False

    print(f"   ✅ PASS: All signatures valid\n")

    print("="*80)
    print("Test A: ✅ PASS - End-to-end unblock flow works correctly")
    print("="*80 + "\n")
    return


if __name__ == "__main__":
    try:
        test_e2e_false_positive_unblock()
    except AssertionError:
        sys.exit(1)
    sys.exit(0)
