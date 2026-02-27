"""
Adapter conformance tests for policy-to-execution enforcement.
"""

import os

import test_common  # noqa: F401
from capability import CapabilityGrant, CapabilityRuntime, CapabilityType, build_shell_tool
from provenance import ProvenanceGraph, provenance_user_input
from sink_policy import SinkPolicy, register_common_sinks, PolicyOutcome


def test_authorize_execution_requires_token():
    old_require = os.environ.get("MVAR_REQUIRE_EXECUTION_TOKEN")
    old_one_time = os.environ.get("MVAR_EXECUTION_TOKEN_ONE_TIME")
    old_secret = os.environ.get("MVAR_EXEC_TOKEN_SECRET")
    old_fail_closed = os.environ.get("MVAR_FAIL_CLOSED")
    old_ledger = os.environ.get("MVAR_ENABLE_LEDGER")
    old_trust = os.environ.get("MVAR_ENABLE_TRUST_ORACLE")
    os.environ["MVAR_REQUIRE_EXECUTION_TOKEN"] = "1"
    os.environ["MVAR_EXECUTION_TOKEN_ONE_TIME"] = "1"
    os.environ["MVAR_EXEC_TOKEN_SECRET"] = "adapter_conformance_secret"
    os.environ["MVAR_FAIL_CLOSED"] = "1"
    os.environ["MVAR_ENABLE_LEDGER"] = "0"
    os.environ["MVAR_ENABLE_TRUST_ORACLE"] = "0"

    try:
        graph = ProvenanceGraph(enable_qseal=False)
        runtime = CapabilityRuntime()
        runtime.manifests["bash"] = build_shell_tool("bash", ["ls"], ["/tmp/**"])
        policy = SinkPolicy(runtime, graph, enable_qseal=False)
        register_common_sinks(policy)

        user = provenance_user_input(graph, "list tmp")
        result = policy.authorize_execution(
            tool="bash",
            action="exec",
            target="ls",
            provenance_node_id=user.node_id,
            parameters={"command": "ls /tmp"},
            execution_token=None,
        )
        assert result.outcome == PolicyOutcome.BLOCK
        assert "Execution token required" in result.reason
    finally:
        if old_require is None:
            os.environ.pop("MVAR_REQUIRE_EXECUTION_TOKEN", None)
        else:
            os.environ["MVAR_REQUIRE_EXECUTION_TOKEN"] = old_require
        if old_one_time is None:
            os.environ.pop("MVAR_EXECUTION_TOKEN_ONE_TIME", None)
        else:
            os.environ["MVAR_EXECUTION_TOKEN_ONE_TIME"] = old_one_time
        if old_secret is None:
            os.environ.pop("MVAR_EXEC_TOKEN_SECRET", None)
        else:
            os.environ["MVAR_EXEC_TOKEN_SECRET"] = old_secret
        if old_fail_closed is None:
            os.environ.pop("MVAR_FAIL_CLOSED", None)
        else:
            os.environ["MVAR_FAIL_CLOSED"] = old_fail_closed
        if old_ledger is None:
            os.environ.pop("MVAR_ENABLE_LEDGER", None)
        else:
            os.environ["MVAR_ENABLE_LEDGER"] = old_ledger
        if old_trust is None:
            os.environ.pop("MVAR_ENABLE_TRUST_ORACLE", None)
        else:
            os.environ["MVAR_ENABLE_TRUST_ORACLE"] = old_trust


def test_authorize_execution_validates_token_binding():
    old_require = os.environ.get("MVAR_REQUIRE_EXECUTION_TOKEN")
    old_one_time = os.environ.get("MVAR_EXECUTION_TOKEN_ONE_TIME")
    old_secret = os.environ.get("MVAR_EXEC_TOKEN_SECRET")
    old_fail_closed = os.environ.get("MVAR_FAIL_CLOSED")
    old_ledger = os.environ.get("MVAR_ENABLE_LEDGER")
    old_trust = os.environ.get("MVAR_ENABLE_TRUST_ORACLE")
    os.environ["MVAR_REQUIRE_EXECUTION_TOKEN"] = "1"
    os.environ["MVAR_EXECUTION_TOKEN_ONE_TIME"] = "1"
    os.environ["MVAR_EXEC_TOKEN_SECRET"] = "adapter_conformance_secret"
    os.environ["MVAR_FAIL_CLOSED"] = "1"
    os.environ["MVAR_ENABLE_LEDGER"] = "0"
    os.environ["MVAR_ENABLE_TRUST_ORACLE"] = "0"

    try:
        graph = ProvenanceGraph(enable_qseal=False)
        runtime = CapabilityRuntime()
        runtime.manifests["bash"] = build_shell_tool("bash", ["ls"], ["/tmp/**"])
        policy = SinkPolicy(runtime, graph, enable_qseal=False)
        register_common_sinks(policy)

        user = provenance_user_input(graph, "list tmp")
        decision = policy.evaluate(
            tool="bash",
            action="exec",
            target="ls",
            provenance_node_id=user.node_id,
            parameters={"command": "ls /tmp"},
        )
        assert decision.execution_token is not None

        ok = policy.authorize_execution(
            tool="bash",
            action="exec",
            target="ls",
            provenance_node_id=user.node_id,
            parameters={"command": "ls /tmp"},
            execution_token=decision.execution_token,
        )
        assert ok.outcome in (PolicyOutcome.ALLOW, PolicyOutcome.STEP_UP)

        other = provenance_user_input(graph, "other principal context")
        bad = policy.authorize_execution(
            tool="bash",
            action="exec",
            target="ls",
            provenance_node_id=other.node_id,
            parameters={"command": "ls /tmp"},
            execution_token=decision.execution_token,
        )
        assert bad.outcome == PolicyOutcome.BLOCK
        assert "Execution token invalid" in bad.reason
    finally:
        if old_require is None:
            os.environ.pop("MVAR_REQUIRE_EXECUTION_TOKEN", None)
        else:
            os.environ["MVAR_REQUIRE_EXECUTION_TOKEN"] = old_require
        if old_one_time is None:
            os.environ.pop("MVAR_EXECUTION_TOKEN_ONE_TIME", None)
        else:
            os.environ["MVAR_EXECUTION_TOKEN_ONE_TIME"] = old_one_time
        if old_secret is None:
            os.environ.pop("MVAR_EXEC_TOKEN_SECRET", None)
        else:
            os.environ["MVAR_EXEC_TOKEN_SECRET"] = old_secret
        if old_fail_closed is None:
            os.environ.pop("MVAR_FAIL_CLOSED", None)
        else:
            os.environ["MVAR_FAIL_CLOSED"] = old_fail_closed
        if old_ledger is None:
            os.environ.pop("MVAR_ENABLE_LEDGER", None)
        else:
            os.environ["MVAR_ENABLE_LEDGER"] = old_ledger
        if old_trust is None:
            os.environ.pop("MVAR_ENABLE_TRUST_ORACLE", None)
        else:
            os.environ["MVAR_ENABLE_TRUST_ORACLE"] = old_trust


def test_authorize_execution_rejects_replayed_token():
    old_require = os.environ.get("MVAR_REQUIRE_EXECUTION_TOKEN")
    old_one_time = os.environ.get("MVAR_EXECUTION_TOKEN_ONE_TIME")
    old_secret = os.environ.get("MVAR_EXEC_TOKEN_SECRET")
    old_fail_closed = os.environ.get("MVAR_FAIL_CLOSED")
    old_ledger = os.environ.get("MVAR_ENABLE_LEDGER")
    old_trust = os.environ.get("MVAR_ENABLE_TRUST_ORACLE")
    os.environ["MVAR_REQUIRE_EXECUTION_TOKEN"] = "1"
    os.environ["MVAR_EXECUTION_TOKEN_ONE_TIME"] = "1"
    os.environ["MVAR_EXEC_TOKEN_SECRET"] = "adapter_conformance_secret"
    os.environ["MVAR_FAIL_CLOSED"] = "1"
    os.environ["MVAR_ENABLE_LEDGER"] = "0"
    os.environ["MVAR_ENABLE_TRUST_ORACLE"] = "0"

    try:
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
        policy = SinkPolicy(runtime, graph, enable_qseal=False)
        register_common_sinks(policy)

        user = provenance_user_input(graph, "read file")
        decision = policy.evaluate(
            tool="filesystem",
            action="read",
            target="/tmp/report.txt",
            provenance_node_id=user.node_id,
        )
        assert decision.execution_token is not None

        first = policy.authorize_execution(
            tool="filesystem",
            action="read",
            target="/tmp/report.txt",
            provenance_node_id=user.node_id,
            execution_token=decision.execution_token,
        )
        assert first.outcome == PolicyOutcome.ALLOW

        replay = policy.authorize_execution(
            tool="filesystem",
            action="read",
            target="/tmp/report.txt",
            provenance_node_id=user.node_id,
            execution_token=decision.execution_token,
        )
        assert replay.outcome == PolicyOutcome.BLOCK
        assert "Execution token invalid" in replay.reason
        assert any("execution_token_invalid" in line for line in replay.evaluation_trace)
    finally:
        if old_require is None:
            os.environ.pop("MVAR_REQUIRE_EXECUTION_TOKEN", None)
        else:
            os.environ["MVAR_REQUIRE_EXECUTION_TOKEN"] = old_require
        if old_one_time is None:
            os.environ.pop("MVAR_EXECUTION_TOKEN_ONE_TIME", None)
        else:
            os.environ["MVAR_EXECUTION_TOKEN_ONE_TIME"] = old_one_time
        if old_secret is None:
            os.environ.pop("MVAR_EXEC_TOKEN_SECRET", None)
        else:
            os.environ["MVAR_EXEC_TOKEN_SECRET"] = old_secret
        if old_fail_closed is None:
            os.environ.pop("MVAR_FAIL_CLOSED", None)
        else:
            os.environ["MVAR_FAIL_CLOSED"] = old_fail_closed
        if old_ledger is None:
            os.environ.pop("MVAR_ENABLE_LEDGER", None)
        else:
            os.environ["MVAR_ENABLE_LEDGER"] = old_ledger
        if old_trust is None:
            os.environ.pop("MVAR_ENABLE_TRUST_ORACLE", None)
        else:
            os.environ["MVAR_ENABLE_TRUST_ORACLE"] = old_trust


def test_pre_evaluated_decision_mismatch_blocks():
    old_require = os.environ.get("MVAR_REQUIRE_EXECUTION_TOKEN")
    old_fail_closed = os.environ.get("MVAR_FAIL_CLOSED")
    old_ledger = os.environ.get("MVAR_ENABLE_LEDGER")
    old_trust = os.environ.get("MVAR_ENABLE_TRUST_ORACLE")
    os.environ["MVAR_REQUIRE_EXECUTION_TOKEN"] = "0"
    os.environ["MVAR_FAIL_CLOSED"] = "1"
    os.environ["MVAR_ENABLE_LEDGER"] = "0"
    os.environ["MVAR_ENABLE_TRUST_ORACLE"] = "0"

    try:
        graph = ProvenanceGraph(enable_qseal=False)
        runtime = CapabilityRuntime()
        runtime.manifests["bash"] = build_shell_tool("bash", ["ls", "pwd"], ["/tmp/**"])
        policy = SinkPolicy(runtime, graph, enable_qseal=False)
        register_common_sinks(policy)

        user = provenance_user_input(graph, "list tmp")
        decision = policy.evaluate(
            tool="bash",
            action="exec",
            target="ls",
            provenance_node_id=user.node_id,
            parameters={"command": "ls /tmp"},
        )

        mismatch = policy.authorize_execution(
            tool="bash",
            action="exec",
            target="pwd",
            provenance_node_id=user.node_id,
            parameters={"command": "pwd /tmp"},
            pre_evaluated_decision=decision,
        )
        assert mismatch.outcome == PolicyOutcome.BLOCK
        assert "Pre-evaluated decision mismatch" in mismatch.reason
        assert any("pre_evaluated_decision_mismatch" in line for line in mismatch.evaluation_trace)
    finally:
        if old_require is None:
            os.environ.pop("MVAR_REQUIRE_EXECUTION_TOKEN", None)
        else:
            os.environ["MVAR_REQUIRE_EXECUTION_TOKEN"] = old_require
        if old_fail_closed is None:
            os.environ.pop("MVAR_FAIL_CLOSED", None)
        else:
            os.environ["MVAR_FAIL_CLOSED"] = old_fail_closed
        if old_ledger is None:
            os.environ.pop("MVAR_ENABLE_LEDGER", None)
        else:
            os.environ["MVAR_ENABLE_LEDGER"] = old_ledger
        if old_trust is None:
            os.environ.pop("MVAR_ENABLE_TRUST_ORACLE", None)
        else:
            os.environ["MVAR_ENABLE_TRUST_ORACLE"] = old_trust


def test_pre_evaluated_decision_avoids_double_counting_composition_risk():
    old_require = os.environ.get("MVAR_REQUIRE_EXECUTION_TOKEN")
    old_one_time = os.environ.get("MVAR_EXECUTION_TOKEN_ONE_TIME")
    old_secret = os.environ.get("MVAR_EXEC_TOKEN_SECRET")
    old_fail_closed = os.environ.get("MVAR_FAIL_CLOSED")
    old_ledger = os.environ.get("MVAR_ENABLE_LEDGER")
    old_trust = os.environ.get("MVAR_ENABLE_TRUST_ORACLE")
    old_comp = os.environ.get("MVAR_ENABLE_COMPOSITION_RISK")
    old_comp_window = os.environ.get("MVAR_COMPOSITION_WINDOW_SECONDS")
    old_comp_step = os.environ.get("MVAR_COMPOSITION_STEP_UP_THRESHOLD")
    old_comp_block = os.environ.get("MVAR_COMPOSITION_BLOCK_THRESHOLD")
    old_comp_weights = os.environ.get("MVAR_COMPOSITION_RISK_WEIGHTS")

    os.environ["MVAR_REQUIRE_EXECUTION_TOKEN"] = "1"
    os.environ["MVAR_EXECUTION_TOKEN_ONE_TIME"] = "1"
    os.environ["MVAR_EXEC_TOKEN_SECRET"] = "adapter_conformance_secret"
    os.environ["MVAR_FAIL_CLOSED"] = "1"
    os.environ["MVAR_ENABLE_LEDGER"] = "0"
    os.environ["MVAR_ENABLE_TRUST_ORACLE"] = "0"
    os.environ["MVAR_ENABLE_COMPOSITION_RISK"] = "1"
    os.environ["MVAR_COMPOSITION_WINDOW_SECONDS"] = "3600"
    os.environ["MVAR_COMPOSITION_STEP_UP_THRESHOLD"] = "3"
    os.environ["MVAR_COMPOSITION_BLOCK_THRESHOLD"] = "10"
    os.environ["MVAR_COMPOSITION_RISK_WEIGHTS"] = '{"low":1,"medium":3,"high":6,"critical":10}'

    try:
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
        policy = SinkPolicy(runtime, graph, enable_qseal=False)
        register_common_sinks(policy)

        user = provenance_user_input(graph, "read file")
        decision = policy.evaluate(
            tool="filesystem",
            action="read",
            target="/tmp/report-a.txt",
            provenance_node_id=user.node_id,
        )
        assert decision.outcome == PolicyOutcome.ALLOW
        assert decision.execution_token is not None

        auth = policy.authorize_execution(
            tool="filesystem",
            action="read",
            target="/tmp/report-a.txt",
            provenance_node_id=user.node_id,
            execution_token=decision.execution_token,
            pre_evaluated_decision=decision,
        )
        assert auth.outcome == PolicyOutcome.ALLOW
        assert any("pre_evaluated_decision_used" in line for line in auth.evaluation_trace)

        second = policy.evaluate(
            tool="filesystem",
            action="read",
            target="/tmp/report-b.txt",
            provenance_node_id=user.node_id,
        )
        # If authorize_execution re-evaluated, cumulative score would already be 2
        # and this second read would step up at threshold=3. It should remain ALLOW.
        assert second.outcome == PolicyOutcome.ALLOW
    finally:
        if old_require is None:
            os.environ.pop("MVAR_REQUIRE_EXECUTION_TOKEN", None)
        else:
            os.environ["MVAR_REQUIRE_EXECUTION_TOKEN"] = old_require
        if old_one_time is None:
            os.environ.pop("MVAR_EXECUTION_TOKEN_ONE_TIME", None)
        else:
            os.environ["MVAR_EXECUTION_TOKEN_ONE_TIME"] = old_one_time
        if old_secret is None:
            os.environ.pop("MVAR_EXEC_TOKEN_SECRET", None)
        else:
            os.environ["MVAR_EXEC_TOKEN_SECRET"] = old_secret
        if old_fail_closed is None:
            os.environ.pop("MVAR_FAIL_CLOSED", None)
        else:
            os.environ["MVAR_FAIL_CLOSED"] = old_fail_closed
        if old_ledger is None:
            os.environ.pop("MVAR_ENABLE_LEDGER", None)
        else:
            os.environ["MVAR_ENABLE_LEDGER"] = old_ledger
        if old_trust is None:
            os.environ.pop("MVAR_ENABLE_TRUST_ORACLE", None)
        else:
            os.environ["MVAR_ENABLE_TRUST_ORACLE"] = old_trust
        if old_comp is None:
            os.environ.pop("MVAR_ENABLE_COMPOSITION_RISK", None)
        else:
            os.environ["MVAR_ENABLE_COMPOSITION_RISK"] = old_comp
        if old_comp_window is None:
            os.environ.pop("MVAR_COMPOSITION_WINDOW_SECONDS", None)
        else:
            os.environ["MVAR_COMPOSITION_WINDOW_SECONDS"] = old_comp_window
        if old_comp_step is None:
            os.environ.pop("MVAR_COMPOSITION_STEP_UP_THRESHOLD", None)
        else:
            os.environ["MVAR_COMPOSITION_STEP_UP_THRESHOLD"] = old_comp_step
        if old_comp_block is None:
            os.environ.pop("MVAR_COMPOSITION_BLOCK_THRESHOLD", None)
        else:
            os.environ["MVAR_COMPOSITION_BLOCK_THRESHOLD"] = old_comp_block
        if old_comp_weights is None:
            os.environ.pop("MVAR_COMPOSITION_RISK_WEIGHTS", None)
        else:
            os.environ["MVAR_COMPOSITION_RISK_WEIGHTS"] = old_comp_weights
