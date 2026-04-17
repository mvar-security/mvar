"""Policy lineage + drift detection contract tests (Item 3)."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import test_common  # noqa: F401
from capability import CapabilityGrant, CapabilityRuntime, CapabilityType
from provenance import ProvenanceGraph, provenance_user_input
from sink_policy import PolicyOutcome, SinkPolicy, register_common_sinks


_TRACKED_ENV = [
    "MVAR_RUNTIME_PROFILE",
    "MVAR_FAIL_CLOSED",
    "MVAR_REQUIRE_SIGNED_POLICY_BUNDLE",
    "MVAR_POLICY_BUNDLE_ENFORCE_ED25519",
    "MVAR_POLICY_BUNDLE_AUTO_BOOTSTRAP",
    "MVAR_POLICY_BUNDLE_PATH",
    "MVAR_POLICY_LINEAGE_PATH",
    "MVAR_POLICY_BUNDLE_SECRET",
    "MVAR_POLICY_BUNDLE_KEY_DIR",
    "MVAR_POLICY_DRIFT_THRESHOLD",
    "MVAR_POLICY_DRIFT_THRESHOLD_PROD_LOCKED",
    "MVAR_POLICY_DRIFT_THRESHOLD_DEV_STRICT",
    "MVAR_POLICY_DRIFT_THRESHOLD_DEV_BALANCED",
    "MVAR_HTTP_DEFAULT_DENY",
    "MVAR_ENABLE_LEDGER",
    "MVAR_ENABLE_TRUST_ORACLE",
]


def _build_policy(tmp_path: Path, *, runtime_profile: str, enable_qseal: bool = False) -> tuple[SinkPolicy, str, callable]:
    previous = {key: os.environ.get(key) for key in _TRACKED_ENV}

    bundle_path = tmp_path / f"{runtime_profile}_bundle.json"
    lineage_path = tmp_path / f"{runtime_profile}_lineage.jsonl"

    os.environ["MVAR_RUNTIME_PROFILE"] = runtime_profile
    os.environ["MVAR_FAIL_CLOSED"] = "1"
    os.environ["MVAR_REQUIRE_SIGNED_POLICY_BUNDLE"] = "1"
    os.environ["MVAR_POLICY_BUNDLE_ENFORCE_ED25519"] = "1"
    os.environ["MVAR_POLICY_BUNDLE_AUTO_BOOTSTRAP"] = "1"
    os.environ["MVAR_POLICY_BUNDLE_PATH"] = str(bundle_path)
    os.environ["MVAR_POLICY_LINEAGE_PATH"] = str(lineage_path)
    os.environ["MVAR_POLICY_BUNDLE_SECRET"] = "policy_bundle_test_secret"
    os.environ["MVAR_POLICY_BUNDLE_KEY_DIR"] = str(tmp_path / "bundle_keys")
    os.environ["MVAR_ENABLE_LEDGER"] = "0"
    os.environ["MVAR_ENABLE_TRUST_ORACLE"] = "0"

    graph = ProvenanceGraph(enable_qseal=enable_qseal)
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
    policy = SinkPolicy(runtime, graph, enable_qseal=enable_qseal)
    register_common_sinks(policy)
    node = provenance_user_input(graph, "read file")

    def _restore() -> None:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    return policy, node.node_id, _restore


def test_policy_lineage_links_successor_to_predecessor_signature(tmp_path: Path):
    policy, node_id, restore = _build_policy(tmp_path, runtime_profile="dev_balanced")
    try:
        first = policy.write_signed_policy_bundle(issuer="pytest_first")
        second = policy.write_signed_policy_bundle(issuer="pytest_second")

        first_signature = f"{first['algorithm']}:{first['signature']}"
        second_lineage = second.get("lineage", {})

        assert first["algorithm"] == "ed25519"
        assert second["algorithm"] == "ed25519"
        assert second_lineage.get("node_id")
        assert second_lineage.get("predecessor_signatures") == [first_signature]
        assert second_lineage.get("security_context_hash")

        lineage_rows = [
            json.loads(line)
            for line in Path(os.environ["MVAR_POLICY_LINEAGE_PATH"]).read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        assert len(lineage_rows) >= 2
        assert lineage_rows[-1]["predecessor_signatures"] == [first_signature]
        assert lineage_rows[-1]["bundle_signature"] == f"{second['algorithm']}:{second['signature']}"
    finally:
        restore()


def test_prod_locked_context_drift_escalates_allow_to_step_up(tmp_path: Path):
    policy, node_id, restore = _build_policy(tmp_path, runtime_profile="prod_locked")
    try:
        policy.policy_drift_thresholds["prod_locked"] = 0.01
        policy.http_default_deny = True
        policy.write_signed_policy_bundle(issuer="pytest")

        # Drift after policy creation snapshot.
        policy.http_default_deny = False

        decision = policy.evaluate(
            tool="filesystem",
            action="read",
            target="/tmp/report.txt",
            provenance_node_id=node_id,
        )

        assert decision.outcome == PolicyOutcome.STEP_UP
        assert any("policy_context_drift_detected" in step for step in decision.evaluation_trace)
        assert any("policy_context_drift_escalation: ALLOW→STEP_UP" in step for step in decision.evaluation_trace)
    finally:
        restore()


def test_dev_strict_context_drift_logs_advisory_without_forced_escalation(tmp_path: Path):
    policy, node_id, restore = _build_policy(tmp_path, runtime_profile="dev_strict")
    try:
        policy.policy_drift_thresholds["dev_strict"] = 0.01
        policy.http_default_deny = True
        policy.write_signed_policy_bundle(issuer="pytest")
        policy.http_default_deny = False

        decision = policy.evaluate(
            tool="filesystem",
            action="read",
            target="/tmp/report.txt",
            provenance_node_id=node_id,
        )

        assert decision.outcome == PolicyOutcome.ALLOW
        assert any("policy_context_drift_detected" in step for step in decision.evaluation_trace)
        assert any("policy_context_drift_advisory_step_up_recommended" in step for step in decision.evaluation_trace)
    finally:
        restore()


def test_dev_balanced_context_drift_is_telemetry_only(tmp_path: Path):
    policy, node_id, restore = _build_policy(tmp_path, runtime_profile="dev_balanced")
    try:
        policy.policy_drift_thresholds["dev_balanced"] = 0.01
        policy.http_default_deny = True
        policy.write_signed_policy_bundle(issuer="pytest")
        policy.http_default_deny = False

        decision = policy.evaluate(
            tool="filesystem",
            action="read",
            target="/tmp/report.txt",
            provenance_node_id=node_id,
        )

        assert decision.outcome == PolicyOutcome.ALLOW
        assert any("policy_context_drift_detected" in step for step in decision.evaluation_trace)
        assert any("policy_context_drift_telemetry_only" in step for step in decision.evaluation_trace)
    finally:
        restore()


def test_prod_locked_rejects_broken_lineage_chain_with_signed_rejection_event(tmp_path: Path):
    policy, node_id, restore = _build_policy(tmp_path, runtime_profile="prod_locked", enable_qseal=True)
    try:
        os.environ["MVAR_POLICY_BUNDLE_AUTO_BOOTSTRAP"] = "0"
        policy.write_signed_policy_bundle(issuer="pytest_first")
        policy.write_signed_policy_bundle(issuer="pytest_second")

        # Break lineage evidence store while keeping bundle intact.
        Path(os.environ["MVAR_POLICY_LINEAGE_PATH"]).write_text("", encoding="utf-8")

        decision = policy.evaluate(
            tool="filesystem",
            action="read",
            target="/tmp/report.txt",
            provenance_node_id=node_id,
        )

        assert decision.outcome == PolicyOutcome.BLOCK
        assert "lineage chain broken" in decision.reason.lower()
        assert decision.qseal_signature is not None
        assert decision.qseal_signature.get("algorithm") in {"ed25519", "hmac-sha256"}
        assert any("policy_artifact_rejected:" in step for step in decision.evaluation_trace)
    finally:
        restore()
