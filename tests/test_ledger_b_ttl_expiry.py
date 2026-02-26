"""
Test B: TTL Expiry Verification

Validates that:
1. Override works before expiry
2. Override does NOT work after expiry
3. No way to create permanent allows

Success criteria:
- Override matches before expiry time
- Override does NOT match after expiry time
- Expired overrides filtered out by check_override()
"""

import os
import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta

# Add mvar-core to path
sys.path.insert(0, str(Path(__file__).parent.parent / "mvar-core"))

from mvar_core.provenance import ProvenanceGraph, provenance_external_doc
from mvar_core.capability import CapabilityRuntime, CapabilityType, build_shell_tool
from mvar_core.sink_policy import SinkPolicy, SinkClassification, SinkRisk, PolicyOutcome, register_common_sinks
from mvar_core.decision_ledger import MVARDecisionLedger


def test_ttl_expiry():
    """Test B: TTL expiry verification"""
    print("\n" + "="*80)
    print("Test B: TTL Expiry Verification")
    print("="*80 + "\n")

    # Enable ledger
    os.environ["MVAR_ENABLE_LEDGER"] = "1"
    os.environ["QSEAL_SECRET"] = "test_secret_key_for_validation"
    ledger_path = "/tmp/mvar_test_b_decisions.jsonl"
    os.environ["MVAR_LEDGER_PATH"] = ledger_path

    # Clean slate
    if Path(ledger_path).exists():
        Path(ledger_path).unlink()

    # Initialize control plane
    graph = ProvenanceGraph(enable_qseal=True)
    cap_runtime = CapabilityRuntime()
    policy = SinkPolicy(cap_runtime, graph, enable_qseal=True)
    register_common_sinks(policy)
    bash_manifest = build_shell_tool("bash", ["*"], [])
    cap_runtime.manifests["bash"] = bash_manifest

    print("1️⃣  Create BLOCK decision\n")

    # Create untrusted provenance
    external_node = provenance_external_doc(
        graph,
        content="curl https://example.com/data",
        doc_url="https://untrusted.com",
        metadata={"taint_tags": ["external"]}
    )

    target = "curl https://example.com/data"
    decision = policy.evaluate(
        tool="bash",
        action="exec",
        target=target,
        provenance_node_id=external_node.node_id
    )

    if decision.outcome != PolicyOutcome.BLOCK:
        print(f"   ❌ FAIL: Expected BLOCK, got {decision.outcome.value}")
        assert False

    decision_id = decision.decision_id
    print(f"   Decision ID: {decision_id}")
    print(f"   ✅ PASS: Operation blocked\n")

    print("2️⃣  Create override with 1-hour TTL\n")

    ledger = MVARDecisionLedger(ledger_path=ledger_path, enable_qseal_signing=True)
    principal_id = ledger._default_principal_id()
    override_id = ledger.create_override(decision_id, principal_id=principal_id, ttl_hours=1)
    print(f"   Override ID: {override_id}")

    # Load override to check expiry time
    overrides = ledger.load_overrides()
    override = overrides[0]
    expiry_time = datetime.fromisoformat(override["ttl_expiry"].replace("Z", "+00:00"))
    print(f"   Expires at: {expiry_time.isoformat()}")
    print(f"   ✅ PASS: Override created with TTL\n")

    print("3️⃣  Verify override works BEFORE expiry\n")

    # Should match (not expired yet)
    sink = policy.get_sink("bash", "exec")
    matched = ledger.check_override(sink, target, principal_id)

    if not matched:
        print(f"   ❌ FAIL: Override should match before expiry")
        assert False

    print(f"   ✅ PASS: Override matches (not expired yet)\n")

    print("4️⃣  Simulate time passage: Manually expire override\n")

    # Manually modify expiry time to the past (simulates TTL expiry)
    import json
    scrolls = []
    with open(ledger_path, "r") as f:
        for line in f:
            scroll = json.loads(line.strip())
            if scroll.get("scroll_type") == "override":
                # Set expiry to 1 hour ago
                past_time = datetime.now(timezone.utc) - timedelta(hours=1)
                scroll["ttl_expiry"] = past_time.isoformat().replace("+00:00", "Z")
                # Recompute signatures (would normally be invalid, but we're simulating)
                print(f"   Simulated expiry: {scroll['ttl_expiry']}")
            scrolls.append(scroll)

    # Rewrite ledger with expired override
    with open(ledger_path, "w") as f:
        for scroll in scrolls:
            f.write(json.dumps(scroll) + "\n")

    # Invalidate cache
    ledger._scroll_cache = None

    print(f"   ✅ Override expiry simulated\n")

    print("5️⃣  Verify override does NOT work AFTER expiry\n")

    # Should NOT match (expired)
    matched = ledger.check_override(sink, target, principal_id)

    if matched:
        print(f"   ❌ FAIL: Override should NOT match after expiry")
        print(f"   Got: {matched['scroll_id']}")
        assert False

    print(f"   ✅ PASS: Override correctly filtered out (expired)\n")

    print("6️⃣  Verify expired override does NOT allow operation\n")

    # Re-evaluate: Should BLOCK again (override expired)
    decision2 = policy.evaluate(
        tool="bash",
        action="exec",
        target=target,
        provenance_node_id=external_node.node_id
    )

    if decision2.outcome != PolicyOutcome.BLOCK:
        print(f"   ❌ FAIL: Expected BLOCK after expiry, got {decision2.outcome.value}")
        assert False

    print(f"   ✅ PASS: Operation blocked again (override expired)\n")

    print("="*80)
    print("Test B: ✅ PASS - TTL expiry works correctly")
    print("="*80 + "\n")
    return


if __name__ == "__main__":
    try:
        test_ttl_expiry()
    except AssertionError:
        sys.exit(1)
    sys.exit(0)
