"""Composition risk regression tests (cumulative risk hardening)."""

import os

import test_common  # noqa: F401
from capability import CapabilityGrant, CapabilityRuntime, CapabilityType
from provenance import ConfidentialityLevel, IntegrityLevel, ProvenanceGraph
from sink_policy import PolicyOutcome, SinkPolicy, register_common_sinks


def _build_policy(step_up_threshold: int, block_threshold: int):
    tracked_keys = [
        "MVAR_ENABLE_COMPOSITION_RISK",
        "MVAR_COMPOSITION_WINDOW_SECONDS",
        "MVAR_COMPOSITION_STEP_UP_THRESHOLD",
        "MVAR_COMPOSITION_BLOCK_THRESHOLD",
        "MVAR_COMPOSITION_RISK_WEIGHTS",
        "MVAR_ENABLE_LEDGER",
        "MVAR_ENABLE_TRUST_ORACLE",
        "MVAR_FAIL_CLOSED",
    ]
    previous = {key: os.environ.get(key) for key in tracked_keys}

    os.environ["MVAR_ENABLE_COMPOSITION_RISK"] = "1"
    os.environ["MVAR_COMPOSITION_WINDOW_SECONDS"] = "3600"
    os.environ["MVAR_COMPOSITION_STEP_UP_THRESHOLD"] = str(step_up_threshold)
    os.environ["MVAR_COMPOSITION_BLOCK_THRESHOLD"] = str(block_threshold)
    os.environ["MVAR_COMPOSITION_RISK_WEIGHTS"] = '{"low":1,"medium":3,"high":6,"critical":10}'
    os.environ["MVAR_ENABLE_LEDGER"] = "0"
    os.environ["MVAR_ENABLE_TRUST_ORACLE"] = "0"
    os.environ["MVAR_FAIL_CLOSED"] = "1"

    graph = ProvenanceGraph(enable_qseal=False)
    runtime = CapabilityRuntime()
    runtime.register_tool(
        tool_name="filesystem",
        capabilities=[
            CapabilityGrant(
                cap_type=CapabilityType.FILESYSTEM_READ,
                allowed_targets=["/tmp/**", "/private/tmp/**"],
            )
        ],
    )
    runtime.register_tool(
        tool_name="http",
        capabilities=[
            CapabilityGrant(
                cap_type=CapabilityType.NETWORK_EGRESS,
                allowed_targets=["*"],
            )
        ],
    )

    policy = SinkPolicy(runtime, graph, enable_qseal=False)
    register_common_sinks(policy)

    trusted_node = graph.create_node(
        source="user",
        integrity=IntegrityLevel.TRUSTED,
        confidentiality=ConfidentialityLevel.PUBLIC,
        content="status check",
    )

    def _restore():
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    return policy, trusted_node.node_id, _restore


def test_composition_risk_blocks_medium_after_low_chain():
    policy, node_id, restore = _build_policy(step_up_threshold=4, block_threshold=5)
    try:
        first = policy.evaluate("filesystem", "read", "/tmp/r1.txt", node_id)
        second = policy.evaluate("filesystem", "read", "/tmp/r2.txt", node_id)
        third = policy.evaluate("http", "post", "https://api.example.com/upload", node_id)

        assert first.outcome == PolicyOutcome.ALLOW
        assert second.outcome == PolicyOutcome.ALLOW
        assert third.outcome == PolicyOutcome.BLOCK
        assert "Cumulative composition risk budget exceeded" in third.reason
        assert any("composition_threshold_block" in line for line in third.evaluation_trace)
    finally:
        restore()


def test_composition_risk_escalates_allow_to_step_up():
    policy, node_id, restore = _build_policy(step_up_threshold=2, block_threshold=10)
    try:
        first = policy.evaluate("filesystem", "read", "/tmp/a.txt", node_id)
        second = policy.evaluate("filesystem", "read", "/tmp/b.txt", node_id)

        assert first.outcome == PolicyOutcome.ALLOW
        assert second.outcome == PolicyOutcome.STEP_UP
        assert "Cumulative composition risk requires STEP_UP" in second.reason
        assert any("composition_threshold_step_up" in line for line in second.evaluation_trace)
    finally:
        restore()


def test_composition_risk_does_not_count_blocked_decisions():
    policy, node_id, restore = _build_policy(step_up_threshold=2, block_threshold=10)
    try:
        blocked = policy.evaluate("unknown_tool", "exec", "any", node_id)
        first = policy.evaluate("filesystem", "read", "/tmp/c.txt", node_id)
        second = policy.evaluate("filesystem", "read", "/tmp/d.txt", node_id)

        assert blocked.outcome == PolicyOutcome.BLOCK
        assert first.outcome == PolicyOutcome.ALLOW
        assert second.outcome == PolicyOutcome.STEP_UP
    finally:
        restore()
