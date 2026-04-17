import json
import os
from dataclasses import dataclass
from typing import Any, Dict

import pytest

from mvar.governor import ExecutionGovernor
from mvar_core.credential_vault import CredentialVault
from mvar_core.sink_policy import PolicyOutcome


@dataclass
class _FakePreDecision:
    execution_token: Dict[str, Any] | None = None


@dataclass
class _FakeAuthDecision:
    outcome: PolicyOutcome = PolicyOutcome.ALLOW
    evaluation_trace: list[str] | None = None
    policy_hash: str = "policy_hash_test"


class _FakeToken:
    def __init__(self, payload: dict[str, Any]):
        self._payload = payload

    def to_reference_dict(self) -> dict[str, Any]:
        return dict(self._payload)


class _VaultClientSuccess:
    def __init__(self, socket_path: str):
        self.socket_path = socket_path

    def issue_token(self, **kwargs: Any):
        payload = {
            "token_id": "tok_abc123",
            "credential_id": kwargs["credential_id"],
            "credential_version": 1,
            "credential_type": "api_key",
            "scope": kwargs["scope"],
            "issued_at": 1.0,
            "expires_at": 301.0,
            "revoked": False,
            "single_use": kwargs["single_use"],
            "verification_context": kwargs["verification_context"],
            "qseal_signature": {"algorithm": "ed25519", "signature": "ed25519:abcd"},
            "is_valid": True,
            "time_remaining": 300.0,
        }
        return _FakeToken(payload)

    def validate_token_use(self, *_args: Any, **_kwargs: Any):
        return {"success": True, "valid": True}


class _VaultClientUnavailable:
    def __init__(self, socket_path: str):
        raise OSError(f"unreachable socket {socket_path}")


@pytest.fixture
def _restore_env():
    snapshot = os.environ.copy()
    yield
    os.environ.clear()
    os.environ.update(snapshot)


def _force_governor_allow(governor: ExecutionGovernor) -> None:
    governor.adapter.evaluate = lambda **_kwargs: _FakePreDecision()  # type: ignore[assignment]
    governor.adapter.authorize_execution = lambda **_kwargs: _FakeAuthDecision(  # type: ignore[assignment]
        outcome=PolicyOutcome.ALLOW,
        evaluation_trace=["forced_allow_for_vault_mediation"],
        policy_hash="policy_hash_test",
    )


def test_governor_credentials_access_returns_vault_token_reference_without_raw_material(monkeypatch, _restore_env):
    monkeypatch.setattr("mvar.governor.CredentialVaultClient", _VaultClientSuccess)
    governor = ExecutionGovernor(policy_profile="dev_balanced")
    _force_governor_allow(governor)

    decision = governor.evaluate(
        {
            "sink_type": "credentials.access",
            "target": "payments_api_key",
            "session_id": "sess-1",
            "arguments": {
                "credential_id": "payments_api_key",
                "scope": "read",
                "single_use": True,
            },
            "prompt_provenance": {"source": "user_request", "taint_level": "trusted"},
        }
    )

    assert decision.decision == "allow"
    assert decision.reason_code == "VAULT_TOKEN_ISSUED"
    assert decision.vault_token_reference is not None
    ref = dict(decision.vault_token_reference)
    assert ref["credential_id"] == "payments_api_key"
    assert ref["scope"] == "read"
    assert "verification_context" in ref
    assert "provenance_node_hash" in ref["verification_context"]
    assert "policy_hash" in ref["verification_context"]
    assert "encrypted_payload" not in ref
    assert "raw_credential" not in ref


def test_governor_prod_locked_fails_closed_when_vault_unavailable(monkeypatch, _restore_env):
    monkeypatch.setattr("mvar.governor.CredentialVaultClient", _VaultClientUnavailable)
    governor = ExecutionGovernor(policy_profile="prod_locked")
    _force_governor_allow(governor)

    decision = governor.evaluate(
        {
            "sink_type": "credentials.access",
            "target": "db_password",
            "arguments": {"credential_id": "db_password"},
            "prompt_provenance": {"source": "user_request", "taint_level": "trusted"},
        }
    )

    assert decision.decision == "block"
    assert decision.reason_code == "VAULT_UNAVAILABLE_FAIL_CLOSED"
    assert decision.vault_token_reference is None


def test_governor_dev_strict_requires_explicit_override_for_vault_fallback(monkeypatch, _restore_env):
    monkeypatch.setattr("mvar.governor.CredentialVaultClient", _VaultClientUnavailable)
    governor = ExecutionGovernor(policy_profile="dev_strict")
    _force_governor_allow(governor)

    blocked = governor.evaluate(
        {
            "sink_type": "credentials.access",
            "target": "prod_key",
            "arguments": {"credential_id": "prod_key"},
            "prompt_provenance": {"source": "user_request", "taint_level": "trusted"},
        }
    )
    assert blocked.decision == "block"
    assert blocked.reason_code == "VAULT_OVERRIDE_REQUIRED"

    allowed = governor.evaluate(
        {
            "sink_type": "credentials.access",
            "target": "prod_key",
            "arguments": {
                "credential_id": "prod_key",
                "vault_fallback_override": True,
            },
            "prompt_provenance": {"source": "user_request", "taint_level": "trusted"},
        }
    )
    assert allowed.decision == "allow"
    assert allowed.reason_code == "VAULT_FALLBACK_OVERRIDE"
    assert allowed.vault_token_reference is not None
    assert allowed.vault_token_reference.get("mode") == "fallback_no_vault"


def test_vault_persists_credentials_encrypted_at_rest(tmp_path):
    vault = CredentialVault(vault_dir=str(tmp_path), require_caller_auth=False)
    vault.add_credential("service_token", "super-secret-material")

    encrypted_path = tmp_path / "credentials.enc"
    assert encrypted_path.exists()
    raw_bytes = encrypted_path.read_bytes()
    assert b"super-secret-material" not in raw_bytes

    reloaded = CredentialVault(vault_dir=str(tmp_path), require_caller_auth=False)
    assert "service_token" in reloaded.credentials
    assert reloaded.credentials["service_token"].encrypted_payload == "super-secret-material"


def test_vault_rotation_and_revocation_invalidate_existing_tokens(tmp_path):
    vault = CredentialVault(vault_dir=str(tmp_path), require_caller_auth=False)
    vault.add_credential("ops_key", "ciphertext-v1")

    issued = vault._handle_issue_token(
        {
            "credential_id": "ops_key",
            "credential_type": "api_key",
            "scope": "read",
            "ttl_seconds": 300,
            "single_use": False,
            "verification_context": {
                "session_id": "s1",
                "provenance_node_hash": "prov",
                "policy_hash": "phash",
                "integrity_at_issue": "trusted",
                "sink_risk": "critical",
            },
        }
    )
    assert issued["success"] is True
    token_id = issued["token"]["token_id"]

    rotated = vault.rotate_credential("ops_key", "ciphertext-v2")
    assert rotated is not None
    assert rotated["version"] == 2

    stale = vault._handle_verify_token({"token_id": token_id})
    assert stale["success"] is False
    assert stale["error"] == "credential_rotated_token_stale"

    assert vault.revoke_credential("ops_key", reason="incident_response") is True
    refused = vault._handle_issue_token(
        {
            "credential_id": "ops_key",
            "credential_type": "api_key",
            "scope": "read",
            "ttl_seconds": 300,
            "single_use": False,
            "verification_context": {},
        }
    )
    assert refused["success"] is False


def test_vault_circuit_breaker_revokes_all_credentials_and_blocks_subsequent_access(tmp_path):
    vault = CredentialVault(vault_dir=str(tmp_path), require_caller_auth=False)
    vault.add_credential("a", "enc-a")
    vault.add_credential("b", "enc-b")

    vault._handle_issue_token(
        {
            "credential_id": "a",
            "credential_type": "api_key",
            "scope": "read",
            "ttl_seconds": 300,
            "single_use": False,
            "verification_context": {"session_id": "sess-x"},
        }
    )

    anomaly = vault._handle_psi_anomaly(
        {
            "psi_current": 0.95,
            "psi_baseline": 0.45,
            "psi_sigma": 0.05,
            "session_id": "sess-x",
        }
    )
    assert anomaly["success"] is True
    assert anomaly["anomaly_detected"] is True

    denied = vault._handle_issue_token(
        {
            "credential_id": "a",
            "credential_type": "api_key",
            "scope": "read",
            "ttl_seconds": 300,
            "single_use": False,
            "verification_context": {"session_id": "sess-x"},
        }
    )
    assert denied["success"] is False


def test_vault_token_validation_blocks_untrusted_provenance_at_critical_sink(tmp_path):
    vault = CredentialVault(vault_dir=str(tmp_path), require_caller_auth=False)
    vault.add_credential("ci_secret", "enc-ci")

    issued = vault._handle_issue_token(
        {
            "credential_id": "ci_secret",
            "credential_type": "api_key",
            "scope": "read",
            "ttl_seconds": 300,
            "single_use": False,
            "verification_context": {
                "session_id": "sess-9",
                "provenance_node_hash": "prov-hash",
                "policy_hash": "policy-hash",
                "integrity_at_issue": "untrusted",
                "sink_risk": "critical",
            },
        }
    )
    assert issued["success"] is True
    token_id = issued["token"]["token_id"]

    blocked = vault._handle_validate_token_use(
        {
            "token_id": token_id,
            "sink_risk": "critical",
            "request_integrity": "trusted",
            "provenance_node_hash": "prov-hash",
            "policy_hash": "policy-hash",
            "session_id": "sess-9",
        }
    )
    assert blocked["success"] is False
    assert blocked["error"] == "untrusted_to_critical_sink"


def test_vault_audit_log_is_signed_append_only_chain(tmp_path):
    vault = CredentialVault(vault_dir=str(tmp_path), require_caller_auth=False)
    vault.add_credential("audit_key", "enc-audit")
    vault._handle_issue_token(
        {
            "credential_id": "audit_key",
            "credential_type": "api_key",
            "scope": "read",
            "ttl_seconds": 300,
            "single_use": True,
            "verification_context": {"session_id": "audit-sess"},
        }
    )

    entries = vault.get_audit_log()
    assert len(entries) >= 2
    previous_signature = ""
    for entry in entries:
        algorithm = entry["qseal_algorithm"]
        signature = entry["qseal_signature"]
        assert signature.startswith(f"{algorithm}:")
        assert isinstance(entry.get("qseal_verified"), bool)
        assert entry.get("prev_signature", "") == previous_signature
        previous_signature = signature

    assert (tmp_path / "audit.jsonl").exists()
    raw_text = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    parsed = [json.loads(line) for line in raw_text.splitlines() if line.strip()]
    assert parsed == entries
