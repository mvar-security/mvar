"""Regression tests for deterministic declassification + scoped memory writes."""

import os

import test_common  # noqa: F401
from capability import CapabilityGrant, CapabilityRuntime, CapabilityType
from provenance import ConfidentialityLevel, IntegrityLevel, ProvenanceGraph
from sink_policy import PolicyOutcome, SinkPolicy, register_common_sinks


def _build_policy():
    tracked_keys = [
        "MVAR_REQUIRE_DECLASSIFY_TOKEN",
        "MVAR_DECLASSIFY_TOKEN_TTL_SECONDS",
        "MVAR_DECLASSIFY_TOKEN_ONE_TIME",
        "MVAR_DECLASSIFY_TOKEN_SECRET",
        "MVAR_ENABLE_LEDGER",
        "MVAR_ENABLE_TRUST_ORACLE",
        "MVAR_FAIL_CLOSED",
    ]
    previous = {key: os.environ.get(key) for key in tracked_keys}

    os.environ["MVAR_REQUIRE_DECLASSIFY_TOKEN"] = "1"
    os.environ["MVAR_DECLASSIFY_TOKEN_TTL_SECONDS"] = "300"
    os.environ["MVAR_DECLASSIFY_TOKEN_ONE_TIME"] = "1"
    os.environ["MVAR_DECLASSIFY_TOKEN_SECRET"] = "declass_secret"
    os.environ["MVAR_ENABLE_LEDGER"] = "0"
    os.environ["MVAR_ENABLE_TRUST_ORACLE"] = "0"
    os.environ["MVAR_FAIL_CLOSED"] = "1"

    graph = ProvenanceGraph(enable_qseal=False)
    runtime = CapabilityRuntime()
    runtime.register_tool(
        tool_name="memory",
        capabilities=[
            CapabilityGrant(
                cap_type=CapabilityType.IPC,
                allowed_targets=["session", "user", "org"],
            )
        ],
    )
    policy = SinkPolicy(runtime, graph, enable_qseal=False)
    register_common_sinks(policy)

    sensitive_node = graph.create_node(
        source="planner_context",
        integrity=IntegrityLevel.TRUSTED,
        confidentiality=ConfidentialityLevel.SENSITIVE,
        content="sensitive plan",
    )

    def _restore():
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    return policy, sensitive_node.node_id, _restore


def test_sensitive_cross_scope_memory_write_requires_declassify_token():
    policy, node_id, restore = _build_policy()
    try:
        decision = policy.evaluate(
            tool="memory",
            action="write",
            target="user",
            provenance_node_id=node_id,
            parameters={"scope": "user", "source_scope": "session"},
        )
        assert decision.outcome == PolicyOutcome.BLOCK
        assert "declassify token required" in decision.reason.lower()
        assert any("declassify_token_missing" in t for t in decision.evaluation_trace)
    finally:
        restore()


def test_valid_declassify_token_allows_sensitive_cross_scope_write():
    policy, node_id, restore = _build_policy()
    try:
        token = policy.issue_declassify_token(
            tool="memory",
            action="write",
            target="user",
            provenance_node_id=node_id,
            source_scope="session",
            target_scope="user",
            confidentiality="sensitive",
            policy_hash=policy._compute_policy_hash(),  # pylint: disable=protected-access
        )
        assert token is not None

        decision = policy.evaluate(
            tool="memory",
            action="write",
            target="user",
            provenance_node_id=node_id,
            parameters={"scope": "user", "source_scope": "session"},
            declassify_token=token,
        )
        assert decision.outcome == PolicyOutcome.ALLOW
        assert any("declassify_token_valid" in t for t in decision.evaluation_trace)
    finally:
        restore()


def test_declassify_token_replay_is_blocked():
    policy, node_id, restore = _build_policy()
    try:
        token = policy.issue_declassify_token(
            tool="memory",
            action="write",
            target="user",
            provenance_node_id=node_id,
            source_scope="session",
            target_scope="user",
            confidentiality="sensitive",
            policy_hash=policy._compute_policy_hash(),  # pylint: disable=protected-access
        )
        first = policy.evaluate(
            tool="memory",
            action="write",
            target="user",
            provenance_node_id=node_id,
            parameters={"scope": "user", "source_scope": "session"},
            declassify_token=token,
        )
        assert first.outcome == PolicyOutcome.ALLOW

        second = policy.evaluate(
            tool="memory",
            action="write",
            target="user",
            provenance_node_id=node_id,
            parameters={"scope": "user", "source_scope": "session"},
            declassify_token=token,
        )
        assert second.outcome == PolicyOutcome.BLOCK
        assert "declassify token invalid" in second.reason.lower()
    finally:
        restore()
