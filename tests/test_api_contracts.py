"""API contract tests to prevent docs/example drift in future phases."""

import inspect
import os

import pytest
from mvar_adapters.base import MVARExecutionAdapter
from mvar_core.capability import CapabilityRuntime, build_shell_tool
from mvar_core.provenance import ProvenanceGraph, provenance_user_input
import mvar_core.qseal as qseal
from mvar_core.sink_policy import (
    PolicyOutcome,
    SinkClassification,
    SinkPolicy,
    SinkRisk,
    register_common_sinks,
)


def test_core_public_symbols_exist():
    assert SinkPolicy is not None
    assert ProvenanceGraph is not None
    assert provenance_user_input is not None


def test_sink_policy_evaluate_signature_is_stable():
    sig = inspect.signature(SinkPolicy.evaluate)
    params = list(sig.parameters)
    # Keep these required parameters stable for docs/quickstart compatibility.
    assert params[:5] == [
        "self",
        "tool",
        "action",
        "target",
        "provenance_node_id",
    ]


def test_quickstart_flow_contract_runs_without_api_errors():
    graph = ProvenanceGraph(enable_qseal=False)
    capability_runtime = CapabilityRuntime()
    policy = SinkPolicy(capability_runtime, graph, enable_qseal=False)
    register_common_sinks(policy)

    bash_manifest = build_shell_tool(
        tool_name="bash",
        allowed_commands=["echo"],
        allowed_paths=["/tmp/**"],
    )
    capability_runtime.manifests["bash"] = bash_manifest

    node = provenance_user_input(graph, "Say hello")
    decision = policy.evaluate(
        tool="bash",
        action="exec",
        target="bash",
        provenance_node_id=node.node_id,
        parameters={"command": "echo hello"},
    )

    assert decision.outcome in {PolicyOutcome.ALLOW, PolicyOutcome.STEP_UP, PolicyOutcome.BLOCK}
    assert decision.reason


def test_mvar_execution_adapter_authorize_signature_is_stable():
    sig = inspect.signature(MVARExecutionAdapter.authorize_execution)
    params = list(sig.parameters)
    assert params == [
        "self",
        "tool",
        "action",
        "target",
        "provenance_node_id",
        "parameters",
        "execution_token",
        "pre_evaluated_decision",
    ]


def test_mvar_execution_adapter_enforce_signature_is_stable():
    sig = inspect.signature(MVARExecutionAdapter.enforce_and_execute)
    params = list(sig.parameters)
    assert params == [
        "self",
        "tool",
        "action",
        "target",
        "execute_fn",
        "provenance_node_id",
        "source_text",
        "source_is_untrusted",
        "parameters",
        "execution_token",
        "target_is_fallback",
    ]


def test_governor_bridge_decision_shape_contract(monkeypatch):
    # Contract freeze: keep token requirements off for deterministic shape checks.
    monkeypatch.setenv("MVAR_REQUIRE_EXECUTION_TOKEN", "0")
    monkeypatch.setenv("MVAR_FAIL_CLOSED", "1")
    monkeypatch.setenv("MVAR_ENABLE_LEDGER", "0")
    monkeypatch.setenv("MVAR_ENABLE_TRUST_ORACLE", "0")

    graph = ProvenanceGraph(enable_qseal=False)
    runtime = CapabilityRuntime()
    runtime.manifests["demo_tool"] = build_shell_tool(
        tool_name="demo_tool",
        allowed_commands=["echo"],
        allowed_paths=["/tmp/**"],
    )

    policy = SinkPolicy(runtime, graph, enable_qseal=False)
    register_common_sinks(policy)
    policy.register_sink(
        SinkClassification(
            tool="demo_tool",
            action="exec",
            risk=SinkRisk.LOW,
            rationale="contract test sink",
            require_capability=runtime.manifests["demo_tool"].capabilities[0].cap_type,
            block_untrusted_integrity=False,
        )
    )
    adapter = MVARExecutionAdapter(policy=policy, provenance_graph=graph, strict=False)

    node_id = adapter.create_user_provenance("contract check")
    decision = adapter.authorize_execution(
        tool="demo_tool",
        action="exec",
        target="echo",
        provenance_node_id=node_id,
        parameters={"command": "echo ok"},
    )

    raw = decision.to_dict()
    normalized_outcome = str(raw.get("outcome", "")).lower()

    assert normalized_outcome in {"allow", "block", "step_up"}
    assert isinstance(raw.get("reason"), str) and raw.get("reason")
    assert isinstance(raw.get("evaluation_trace"), list)
    assert isinstance(raw.get("policy_hash"), str) and raw.get("policy_hash")
    assert isinstance(raw.get("target_hash"), str) and raw.get("target_hash")

    sink = raw.get("sink", {})
    assert sink.get("tool")
    assert sink.get("action")
    assert sink.get("risk")

    prov = raw.get("provenance", {})
    assert prov.get("node_id")
    assert prov.get("integrity")
    assert prov.get("confidentiality")


def test_governor_witness_signature_uses_truthful_algorithm_label(monkeypatch):
    original_env = os.environ.copy()
    monkeypatch.setenv("MVAR_REQUIRE_EXECUTION_TOKEN", "0")
    monkeypatch.setenv("MVAR_FAIL_CLOSED", "1")
    monkeypatch.setenv("MVAR_ENABLE_LEDGER", "0")
    monkeypatch.setenv("MVAR_ENABLE_TRUST_ORACLE", "0")
    monkeypatch.delenv("MVAR_ENFORCE_ED25519", raising=False)

    try:
        from mvar.governor import ExecutionGovernor

        governor = ExecutionGovernor(policy_profile="dev_balanced")
        decision = governor.evaluate(
            {
                "sink_type": "tool.custom",
                "target": "status",
                "arguments": {"command": "echo ok"},
                "prompt_provenance": {"source": "user_request", "taint_level": "trusted"},
            }
        )

        algorithm, signature_hex = str(decision.witness_signature).split(":", 1)
        assert algorithm in {"ed25519", "hmac-sha256"}
        assert signature_hex
    finally:
        os.environ.clear()
        os.environ.update(original_env)


def test_governor_prod_locked_fails_closed_without_ed25519(monkeypatch):
    original_env = os.environ.copy()
    monkeypatch.setattr(qseal, "_CRYPTO_AVAILABLE", False)
    monkeypatch.delenv("MVAR_ENFORCE_ED25519", raising=False)

    try:
        from mvar.governor import ExecutionGovernor

        with pytest.raises(RuntimeError, match="MVAR_ENFORCE_ED25519=1"):
            ExecutionGovernor(policy_profile="prod_locked")
    finally:
        os.environ.clear()
        os.environ.update(original_env)
