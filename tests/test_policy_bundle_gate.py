"""Startup policy bundle integrity gate regression tests (Milestone 2b)."""

import json
import os
from pathlib import Path

import test_common  # noqa: F401
from capability import CapabilityGrant, CapabilityRuntime, CapabilityType
from provenance import ProvenanceGraph, provenance_user_input
from sink_policy import PolicyOutcome, SinkPolicy, register_common_sinks


def _build_policy(bundle_path: str, require_bundle: bool, secret: str):
    tracked = [
        "MVAR_REQUIRE_SIGNED_POLICY_BUNDLE",
        "MVAR_POLICY_BUNDLE_PATH",
        "MVAR_POLICY_BUNDLE_SECRET",
        "MVAR_ENABLE_LEDGER",
        "MVAR_ENABLE_TRUST_ORACLE",
        "MVAR_FAIL_CLOSED",
    ]
    previous = {key: os.environ.get(key) for key in tracked}

    os.environ["MVAR_REQUIRE_SIGNED_POLICY_BUNDLE"] = "1" if require_bundle else "0"
    os.environ["MVAR_POLICY_BUNDLE_PATH"] = bundle_path
    os.environ["MVAR_POLICY_BUNDLE_SECRET"] = secret
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
    policy = SinkPolicy(runtime, graph, enable_qseal=False)
    register_common_sinks(policy)
    node = provenance_user_input(graph, "read report")

    def _restore():
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    return policy, node.node_id, _restore


def test_signed_policy_bundle_startup_verification_passes(tmp_path: Path):
    bundle_path = str(tmp_path / "policy_bundle.json")
    policy, node_id, restore = _build_policy(bundle_path, require_bundle=True, secret="bundle_secret")
    try:
        policy.write_signed_policy_bundle(bundle_path, issuer="pytest")
        decision = policy.evaluate(
            tool="filesystem",
            action="read",
            target="/tmp/report.txt",
            provenance_node_id=node_id,
        )
        assert decision.outcome == PolicyOutcome.ALLOW
        assert any("startup_policy_verification: ok" in line for line in decision.evaluation_trace)
    finally:
        restore()


def test_missing_signed_policy_bundle_blocks_when_required(tmp_path: Path):
    bundle_path = str(tmp_path / "missing_bundle.json")
    policy, node_id, restore = _build_policy(bundle_path, require_bundle=True, secret="bundle_secret")
    try:
        decision = policy.evaluate(
            tool="filesystem",
            action="read",
            target="/tmp/report.txt",
            provenance_node_id=node_id,
        )
        assert decision.outcome == PolicyOutcome.BLOCK
        assert "startup policy verification failed" in decision.reason.lower()
        assert "not found" in decision.reason.lower()
    finally:
        restore()


def test_tampered_signed_policy_bundle_blocks_startup(tmp_path: Path):
    bundle_path = str(tmp_path / "tampered_bundle.json")
    policy, node_id, restore = _build_policy(bundle_path, require_bundle=True, secret="bundle_secret")
    try:
        policy.write_signed_policy_bundle(bundle_path, issuer="pytest")
        bundle = json.loads(Path(bundle_path).read_text(encoding="utf-8"))
        bundle["policy_hash"] = "0" * 64
        Path(bundle_path).write_text(json.dumps(bundle, sort_keys=True), encoding="utf-8")

        decision = policy.evaluate(
            tool="filesystem",
            action="read",
            target="/tmp/report.txt",
            provenance_node_id=node_id,
        )
        assert decision.outcome == PolicyOutcome.BLOCK
        assert "startup policy verification failed" in decision.reason.lower()
    finally:
        restore()
