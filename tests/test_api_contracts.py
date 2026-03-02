"""API contract tests to prevent docs/example drift in future phases."""

import inspect

from mvar_core.capability import CapabilityRuntime, build_shell_tool
from mvar_core.provenance import ProvenanceGraph, provenance_user_input
from mvar_core.sink_policy import PolicyOutcome, SinkPolicy, register_common_sinks


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
