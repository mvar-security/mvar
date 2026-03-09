"""Execution-contract regression tests for privileged sink invocations."""

import os

import test_common  # noqa: F401
from capability import CapabilityGrant, CapabilityRuntime, CapabilityType, build_shell_tool
from provenance import ProvenanceGraph, provenance_user_input
from sink_policy import PolicyOutcome, SinkPolicy, register_common_sinks


_ENV_KEYS = (
    "MVAR_REQUIRE_EXECUTION_CONTRACT",
    "MVAR_REQUIRE_EXECUTION_TOKEN",
    "MVAR_EXECUTION_TOKEN_ONE_TIME",
    "MVAR_EXEC_TOKEN_SECRET",
    "MVAR_FAIL_CLOSED",
    "MVAR_REQUIRE_SIGNED_POLICY_BUNDLE",
)


def _snapshot_env():
    return {key: os.environ.get(key) for key in _ENV_KEYS}


def _restore_env(snapshot):
    for key, value in snapshot.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value


def _configure_contract_env():
    os.environ["MVAR_REQUIRE_EXECUTION_CONTRACT"] = "1"
    os.environ["MVAR_REQUIRE_EXECUTION_TOKEN"] = "0"
    os.environ["MVAR_EXECUTION_TOKEN_ONE_TIME"] = "1"
    os.environ["MVAR_EXEC_TOKEN_SECRET"] = "execution_contract_secret"
    os.environ["MVAR_FAIL_CLOSED"] = "1"
    os.environ["MVAR_REQUIRE_SIGNED_POLICY_BUNDLE"] = "0"


def test_execution_contract_missing_blocks_bash_exec():
    snap = _snapshot_env()
    try:
        _configure_contract_env()
        graph = ProvenanceGraph(enable_qseal=False)
        runtime = CapabilityRuntime()
        runtime.manifests["bash"] = build_shell_tool("bash", ["ls", "echo"], ["/tmp/**"])
        policy = SinkPolicy(runtime, graph, enable_qseal=False)
        register_common_sinks(policy)
        node = provenance_user_input(graph, "list tmp")

        decision = policy.evaluate(
            tool="bash",
            action="exec",
            target="ls",
            provenance_node_id=node.node_id,
            parameters={"command": "ls /tmp"},
        )

        blocked = policy.authorize_execution(
            tool="bash",
            action="exec",
            target="ls",
            provenance_node_id=node.node_id,
            parameters={"command": "ls /tmp"},
            execution_token=None,
        )
        assert blocked.outcome == PolicyOutcome.BLOCK
        assert "execution contract required" in blocked.reason.lower()
    finally:
        _restore_env(snap)


def test_execution_contract_detects_bash_argument_mutation():
    snap = _snapshot_env()
    try:
        _configure_contract_env()
        graph = ProvenanceGraph(enable_qseal=False)
        runtime = CapabilityRuntime()
        runtime.manifests["bash"] = build_shell_tool("bash", ["ls", "echo"], ["/tmp/**"])
        policy = SinkPolicy(runtime, graph, enable_qseal=False)
        register_common_sinks(policy)
        node = provenance_user_input(graph, "list tmp")

        decision = policy.evaluate(
            tool="bash",
            action="exec",
            target="ls",
            provenance_node_id=node.node_id,
            parameters={"command": "ls /tmp"},
        )
        assert decision.execution_token is not None

        blocked = policy.authorize_execution(
            tool="bash",
            action="exec",
            target="ls",
            provenance_node_id=node.node_id,
            parameters={"command": "echo /tmp"},
            execution_token=decision.execution_token,
            pre_evaluated_decision=decision,
        )
        assert blocked.outcome == PolicyOutcome.BLOCK
        assert "execution contract invalid" in blocked.reason.lower()
        assert any("execution_contract_invalid" in line for line in blocked.evaluation_trace)
    finally:
        _restore_env(snap)


def test_execution_contract_detects_http_invocation_mutation():
    snap = _snapshot_env()
    try:
        _configure_contract_env()
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
        node = provenance_user_input(graph, "upload status")

        decision = policy.evaluate(
            tool="http",
            action="post",
            target="https://api.example.com/upload",
            provenance_node_id=node.node_id,
            parameters={"method": "POST", "body": {"status": "ok"}},
        )
        assert decision.execution_token is not None

        blocked = policy.authorize_execution(
            tool="http",
            action="post",
            target="https://api.example.com/upload",
            provenance_node_id=node.node_id,
            parameters={"method": "GET", "body": {"status": "ok"}},
            execution_token=decision.execution_token,
            pre_evaluated_decision=decision,
        )
        assert blocked.outcome == PolicyOutcome.BLOCK
        assert "execution contract invalid" in blocked.reason.lower()
    finally:
        _restore_env(snap)


def test_execution_contract_replay_is_blocked():
    snap = _snapshot_env()
    try:
        _configure_contract_env()
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
        node = provenance_user_input(graph, "upload status")

        decision = policy.evaluate(
            tool="http",
            action="post",
            target="https://api.example.com/upload",
            provenance_node_id=node.node_id,
            parameters={"method": "POST", "body": {"status": "ok"}},
        )
        assert decision.execution_token is not None

        first = policy.authorize_execution(
            tool="http",
            action="post",
            target="https://api.example.com/upload",
            provenance_node_id=node.node_id,
            parameters={"method": "POST", "body": {"status": "ok"}},
            execution_token=decision.execution_token,
            pre_evaluated_decision=decision,
        )
        assert first.outcome == PolicyOutcome.ALLOW

        replay = policy.authorize_execution(
            tool="http",
            action="post",
            target="https://api.example.com/upload",
            provenance_node_id=node.node_id,
            parameters={"method": "POST", "body": {"status": "ok"}},
            execution_token=decision.execution_token,
            pre_evaluated_decision=decision,
        )
        assert replay.outcome == PolicyOutcome.BLOCK
        assert "execution contract invalid" in replay.reason.lower()
    finally:
        _restore_env(snap)


def test_execution_contract_not_required_for_filesystem_read():
    snap = _snapshot_env()
    try:
        _configure_contract_env()
        graph = ProvenanceGraph(enable_qseal=False)
        runtime = CapabilityRuntime()
        runtime.register_tool(
            "filesystem",
            capabilities=[
                CapabilityGrant(
                    cap_type=CapabilityType.FILESYSTEM_READ,
                    allowed_targets=["/tmp/**", "/private/tmp/**"],
                )
            ],
        )
        policy = SinkPolicy(runtime, graph, enable_qseal=False)
        register_common_sinks(policy)
        node = provenance_user_input(graph, "read file")

        decision = policy.authorize_execution(
            tool="filesystem",
            action="read",
            target="/tmp/report.txt",
            provenance_node_id=node.node_id,
            execution_token=None,
        )
        assert decision.outcome == PolicyOutcome.ALLOW
    finally:
        _restore_env(snap)
