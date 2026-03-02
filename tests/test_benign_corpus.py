"""Benign corpus regression: legitimate actions should not be falsely blocked."""

import os

import pytest

import test_common  # noqa: F401
from capability import CapabilityGrant, CapabilityRuntime, CapabilityType
from provenance import ProvenanceGraph, provenance_user_input
from sink_policy import PolicyOutcome, SinkClassification, SinkPolicy, SinkRisk, register_common_sinks


# 200 benign action targets.
BENIGN_TARGETS = [f"benign_task_{idx:03d}" for idx in range(1, 201)]
assert len(BENIGN_TARGETS) == 200


def _build_policy():
    old_require = os.environ.get("MVAR_REQUIRE_EXECUTION_TOKEN")
    old_bundle = os.environ.get("MVAR_REQUIRE_SIGNED_POLICY_BUNDLE")
    old_fail_closed = os.environ.get("MVAR_FAIL_CLOSED")

    os.environ["MVAR_REQUIRE_EXECUTION_TOKEN"] = "1"
    os.environ["MVAR_REQUIRE_SIGNED_POLICY_BUNDLE"] = "0"
    os.environ["MVAR_FAIL_CLOSED"] = "1"

    graph = ProvenanceGraph(enable_qseal=False)
    runtime = CapabilityRuntime()
    runtime.manifests["demo_tool"] = runtime.register_tool(
        tool_name="demo_tool",
        capabilities=[
            CapabilityGrant(
                cap_type=CapabilityType.PROCESS_EXEC,
                allowed_targets=BENIGN_TARGETS,
            )
        ],
    )

    policy = SinkPolicy(runtime, graph, enable_qseal=False)
    register_common_sinks(policy)
    policy.register_sink(
        SinkClassification(
            tool="demo_tool",
            action="run",
            risk=SinkRisk.LOW,
            rationale="Benign no-op task",
            require_capability=CapabilityType.PROCESS_EXEC,
            block_untrusted_integrity=False,
        )
    )

    def _restore_env():
        if old_require is None:
            os.environ.pop("MVAR_REQUIRE_EXECUTION_TOKEN", None)
        else:
            os.environ["MVAR_REQUIRE_EXECUTION_TOKEN"] = old_require

        if old_bundle is None:
            os.environ.pop("MVAR_REQUIRE_SIGNED_POLICY_BUNDLE", None)
        else:
            os.environ["MVAR_REQUIRE_SIGNED_POLICY_BUNDLE"] = old_bundle

        if old_fail_closed is None:
            os.environ.pop("MVAR_FAIL_CLOSED", None)
        else:
            os.environ["MVAR_FAIL_CLOSED"] = old_fail_closed

    return graph, policy, _restore_env


@pytest.mark.parametrize("target", BENIGN_TARGETS)
def test_benign_actions_not_blocked(target):
    graph, policy, restore = _build_policy()
    try:
        node = provenance_user_input(graph, f"Read file {target}")
        decision = policy.evaluate(
            tool="demo_tool",
            action="run",
            target=target,
            provenance_node_id=node.node_id,
        )
        assert decision.outcome != PolicyOutcome.BLOCK, (
            f"False block for benign target {target}: {decision.reason}"
        )
    finally:
        restore()
