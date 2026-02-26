"""
Adapter conformance tests for policy-to-execution enforcement.
"""

import os

import test_common  # noqa: F401
from capability import CapabilityRuntime, build_shell_tool
from provenance import ProvenanceGraph, provenance_user_input
from sink_policy import SinkPolicy, register_common_sinks, PolicyOutcome


def test_authorize_execution_requires_token():
    old_require = os.environ.get("MVAR_REQUIRE_EXECUTION_TOKEN")
    old_secret = os.environ.get("MVAR_EXEC_TOKEN_SECRET")
    old_fail_closed = os.environ.get("MVAR_FAIL_CLOSED")
    old_ledger = os.environ.get("MVAR_ENABLE_LEDGER")
    old_trust = os.environ.get("MVAR_ENABLE_TRUST_ORACLE")
    os.environ["MVAR_REQUIRE_EXECUTION_TOKEN"] = "1"
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
    old_secret = os.environ.get("MVAR_EXEC_TOKEN_SECRET")
    old_fail_closed = os.environ.get("MVAR_FAIL_CLOSED")
    old_ledger = os.environ.get("MVAR_ENABLE_LEDGER")
    old_trust = os.environ.get("MVAR_ENABLE_TRUST_ORACLE")
    os.environ["MVAR_REQUIRE_EXECUTION_TOKEN"] = "1"
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
