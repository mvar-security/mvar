"""
Test C: Tamper Detection (Fail-Closed)

Validates that:
1. Valid signature → scroll accepted
2. Invalid signature → scroll IGNORED (fail-closed)
3. Modified scroll → signature verification fails
4. System continues to operate (non-fatal)

Success criteria:
- Valid scrolls pass verification
- Tampered scrolls fail verification
- check_override() filters out invalid scrolls
- No security bypass via tampering
"""

import os
import sys
import json
from pathlib import Path

# Add mvar-core to path
sys.path.insert(0, str(Path(__file__).parent.parent / "mvar-core"))

from mvar_core.decision_ledger import MVARDecisionLedger
from mvar_core.provenance import ProvenanceGraph, provenance_external_doc
from mvar_core.capability import CapabilityRuntime, CapabilityType, build_shell_tool
from mvar_core.sink_policy import SinkPolicy, register_common_sinks, PolicyOutcome


def test_tamper_detection():
    """Test C: Tamper detection (fail-closed)"""
    print("\n" + "="*80)
    print("Test C: Tamper Detection (Fail-Closed)")
    print("="*80 + "\n")

    os.environ["MVAR_ENABLE_LEDGER"] = "1"
    os.environ["QSEAL_SECRET"] = "test_secret_key_for_validation"
    ledger_path = "/tmp/mvar_test_c_decisions.jsonl"
    os.environ["MVAR_LEDGER_PATH"] = ledger_path

    if Path(ledger_path).exists():
        Path(ledger_path).unlink()

    # Create a decision + override
    graph = ProvenanceGraph(enable_qseal=True)
    cap_runtime = CapabilityRuntime()
    policy = SinkPolicy(cap_runtime, graph, enable_qseal=True)
    register_common_sinks(policy)
    bash_manifest = build_shell_tool("bash", ["*"], [])
    cap_runtime.manifests["bash"] = bash_manifest

    print("1️⃣  Create valid decision + override\n")

    external_node = provenance_external_doc(graph, "malicious command", "https://attacker.com", {"taint_tags": ["external"]})
    target = "rm -rf /"
    decision = policy.evaluate("bash", "exec", target, external_node.node_id)
    decision_id = decision.decision_id

    ledger = MVARDecisionLedger(ledger_path=ledger_path, enable_qseal_signing=True)
    principal_id = ledger._default_principal_id()
    override_id = ledger.create_override(decision_id, principal_id=principal_id, ttl_hours=24)

    print(f"   Decision: {decision_id}")
    print(f"   Override: {override_id}")
    print(f"   ✅ Valid scrolls created\n")

    print("2️⃣  Verify valid scrolls pass verification\n")

    scrolls = ledger._load_scrolls_raw()  # Load ALL scrolls
    valid_count = sum(1 for s in scrolls if ledger._verify_scroll(s))
    print(f"   Total scrolls: {len(scrolls)}")
    print(f"   Valid: {valid_count}")

    if valid_count != len(scrolls):
        print(f"   ❌ FAIL: Not all scrolls valid")
        assert False

    print(f"   ✅ PASS: All scrolls pass verification\n")

    print("3️⃣  Tamper with override scroll (modify target_hash)\n")

    # Manually tamper with ledger
    scrolls = []
    with open(ledger_path, "r") as f:
        for line in f:
            scroll = json.loads(line.strip())
            if scroll.get("scroll_type") == "override":
                # Tamper: Change target_hash to bypass check
                original_hash = scroll["match_criteria"]["target_hash"]
                scroll["match_criteria"]["target_hash"] = "0000000000000000"
                print(f"   Original hash: {original_hash}")
                print(f"   Tampered hash: {scroll['match_criteria']['target_hash']}")
            scrolls.append(scroll)

    # Rewrite with tampered scroll
    with open(ledger_path, "w") as f:
        for scroll in scrolls:
            f.write(json.dumps(scroll) + "\n")

    ledger._scroll_cache = None  # Invalidate cache
    print(f"   ✅ Tampered scroll written\n")

    print("4️⃣  Verify tampered scroll FAILS verification\n")

    scrolls = ledger._load_scrolls_raw()  # Load ALL scrolls (including invalid ones)
    valid_count = sum(1 for s in scrolls if ledger._verify_scroll(s))
    print(f"   Total scrolls: {len(scrolls)}")
    print(f"   Valid: {valid_count}")

    if valid_count == len(scrolls):
        print(f"   ❌ FAIL: Tampered scroll should fail verification")
        assert False

    print(f"   ✅ PASS: Tampered scroll failed verification\n")

    print("5️⃣  Verify tampered override does NOT match (fail-closed)\n")

    sink = policy.get_sink("bash", "exec")
    matched = ledger.check_override(sink, target, principal_id)

    if matched:
        print(f"   ❌ FAIL: Tampered override should NOT match")
        print(f"   Got: {matched['scroll_id']}")
        assert False

    print(f"   ✅ PASS: Tampered override correctly filtered out\n")

    print("6️⃣  Verify operation still BLOCKED (no bypass)\n")

    decision2 = policy.evaluate("bash", "exec", target, external_node.node_id)

    if decision2.outcome != PolicyOutcome.BLOCK:
        print(f"   ❌ FAIL: Should BLOCK (no valid override)")
        assert False

    print(f"   ✅ PASS: Operation blocked (tamper did not bypass security)\n")

    print("="*80)
    print("Test C: ✅ PASS - Tamper detection works (fail-closed)")
    print("="*80 + "\n")
    return


if __name__ == "__main__":
    try:
        test_tamper_detection()
    except AssertionError:
        sys.exit(1)
    sys.exit(0)
