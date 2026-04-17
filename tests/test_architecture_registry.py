"""Architecture registry + signed self-report contracts (Item 6)."""

from __future__ import annotations

import os

import pytest

from mvar.governor import ExecutionGovernor
from mvar_core.architecture import ArchitectureRegistry, RuntimeState


def _layer_map(report: dict) -> dict[int, dict]:
    layers = report["payload"]["architecture_registry"]["layers"]
    return {int(layer["layer_id"]): layer for layer in layers}


@pytest.fixture(autouse=True)
def _restore_env():
    snapshot = os.environ.copy()
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(snapshot)


def test_architecture_registry_layer_statuses_are_full_across_profiles():
    for profile_name in ("dev_balanced", "dev_strict", "prod_locked"):
        governor = ExecutionGovernor(policy_profile=profile_name)
        report = governor.architecture_self_report()
        assert report["payload"]["active_profile"] == profile_name

        layers = _layer_map(report)
        assert set(layers.keys()) == {1, 2, 3, 4, 5, 6}
        for layer_id in range(1, 7):
            assert layers[layer_id]["status"] == "FULL"


def test_architecture_self_report_is_signed_and_verifiable():
    governor = ExecutionGovernor(policy_profile="prod_locked")
    registry = ArchitectureRegistry.from_governor(governor)
    report = registry.runtime_self_report()

    assert report["payload"]["signing_mode"] == "ED25519"
    assert report["signature"]["algorithm"] == "ed25519"
    assert report["signature"]["signature"].startswith("ed25519:")
    assert report["signature"]["verified"] is True
    assert registry.verify_self_report(report) is True


def test_architecture_self_report_reflects_runtime_degradation_state():
    degraded_state = RuntimeState(
        active_profile="dev_balanced",
        signing_algorithm="hmac-sha256",
        vault_mode="DIRECT",
        risk_mode="MONITOR",
        policy_lineage_status="ADVISORY",
        drift_detection_status="OFF",
        capability_runtime_active=True,
        provenance_system_active=True,
        sink_policy_active=True,
        vaulted_execution_active=False,
        advanced_risk_active=False,
        taint_laundering_proof_reference="tests/integration/test_taint_laundering_prevention.py",
        raw_credential_invariant=(
            "agents never receive raw credential material; vault returns token references only"
        ),
    )
    registry = ArchitectureRegistry(profile_name="dev_balanced", runtime_state=degraded_state)
    report = registry.runtime_self_report()
    layers = _layer_map(report)

    assert report["payload"]["signing_mode"] == "HMAC_FALLBACK"
    assert report["payload"]["vault_mode"] == "DIRECT"
    assert report["payload"]["policy_lineage_status"] == "ADVISORY"
    assert layers[4]["status"] == "PARTIAL"
    assert layers[5]["status"] == "PARTIAL"
    assert layers[6]["status"] == "NOT_ACTIVE"


def test_architecture_self_report_reflects_live_governor_degradation():
    governor = ExecutionGovernor(policy_profile="dev_balanced")
    governor._advanced_risk = None
    governor._mediate_credentials_access = None  # type: ignore[assignment]
    governor.sink_policy.require_signed_policy_bundle = False

    registry = ArchitectureRegistry.from_governor(governor)
    report = registry.runtime_self_report()
    layers = _layer_map(report)

    assert report["payload"]["policy_lineage_status"] == "ADVISORY"
    assert report["payload"]["vault_mode"] == "DIRECT"
    assert layers[4]["status"] == "PARTIAL"
    assert layers[5]["status"] == "PARTIAL"
    assert layers[6]["status"] == "NOT_ACTIVE"


def test_architecture_self_report_tamper_fails_verification():
    governor = ExecutionGovernor(policy_profile="dev_strict")
    registry = ArchitectureRegistry.from_governor(governor)
    report = registry.runtime_self_report()

    tampered = {
        "payload": dict(report["payload"]),
        "signature": dict(report["signature"]),
    }
    tampered["payload"]["risk_scoring_mode"] = "BLOCKING"

    assert registry.verify_self_report(report) is True
    assert registry.verify_self_report(tampered) is False


def test_compatibility_matrix_present_and_parseable():
    governor = ExecutionGovernor(policy_profile="dev_balanced")
    registry = ArchitectureRegistry.from_governor(governor)
    matrix = registry.compatibility_matrix()

    assert matrix["schema_version"] == "mvar.compatibility.v1"
    assert isinstance(matrix["entries"], list)
    assert matrix["entries"]
    for row in matrix["entries"]:
        assert "mvar_primitive_version" in row
        assert "clawzero_module_version" in row
        assert "compatibility_status" in row
