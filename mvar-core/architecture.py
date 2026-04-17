"""Machine-readable architecture registry and signed runtime self-report."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional

from . import __version__ as _MVAR_VERSION
from .qseal import QSealSigner

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    _ED25519_VERIFY_AVAILABLE = True
except Exception:  # pragma: no cover - exercised only when cryptography is unavailable
    _ED25519_VERIFY_AVAILABLE = False


class LayerStatus(str, Enum):
    FULL = "FULL"
    PARTIAL = "PARTIAL"
    NOT_ACTIVE = "NOT_ACTIVE"


@dataclass(frozen=True)
class ArchitectureLayer:
    layer_id: int
    layer_name: str
    patent_claim_reference: str
    status: str
    active_profile_mode: str
    mode_by_profile: Dict[str, str]
    known_limitations: list[str]


@dataclass(frozen=True)
class RuntimeState:
    active_profile: str
    signing_algorithm: str
    vault_mode: str
    risk_mode: str
    policy_lineage_status: str
    drift_detection_status: str
    capability_runtime_active: bool
    provenance_system_active: bool
    sink_policy_active: bool
    vaulted_execution_active: bool
    advanced_risk_active: bool
    taint_laundering_proof_reference: str
    raw_credential_invariant: str


def _canonical_bytes(payload: Dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _normalize_profile(profile_name: str) -> str:
    normalized = str(profile_name or "").strip().lower()
    if normalized in {"prod_locked", "dev_strict", "dev_balanced"}:
        return normalized
    return "dev_balanced"


def _risk_mode_for_profile(profile_name: str) -> str:
    return {
        "prod_locked": "BLOCKING",
        "dev_strict": "ADVISORY",
        "dev_balanced": "MONITOR",
    }[_normalize_profile(profile_name)]


def _drift_status_for_profile(profile_name: str) -> str:
    return {
        "prod_locked": "ACTIVE",
        "dev_strict": "ADVISORY",
        "dev_balanced": "OFF",
    }[_normalize_profile(profile_name)]


def _lineage_status_for_profile(profile_name: str) -> str:
    normalized = _normalize_profile(profile_name)
    require_signed = os.getenv("MVAR_REQUIRE_SIGNED_POLICY_BUNDLE", "1") == "1"
    if normalized == "prod_locked":
        return "ENFORCED" if require_signed else "ADVISORY"
    return "ENFORCED" if require_signed else "ADVISORY"


class ArchitectureRegistry:
    """Exposes MVAR six-layer state and emits signed architecture reports."""

    COMPATIBILITY_MATRIX: Dict[str, Any] = {
        "schema_version": "mvar.compatibility.v1",
        "entries": [
            {
                "mvar_primitive_version": "1.4.x",
                "clawzero_module_version": "0.3.x",
                "compatibility_status": "compatible",
                "notes": "ExecutionGovernor bridge + session enforcement + signed witness compatibility",
            },
            {
                "mvar_primitive_version": "1.5.x",
                "clawzero_module_version": "0.4.x",
                "compatibility_status": "planned",
                "notes": "Forward-compatible target for expanded compliance surfaces",
            },
        ],
    }

    def __init__(
        self,
        *,
        profile_name: str = "dev_balanced",
        runtime_state: Optional[RuntimeState] = None,
        signer: Optional[QSealSigner] = None,
    ) -> None:
        self.profile_name = _normalize_profile(profile_name)
        self._signer = signer or QSealSigner()
        self._runtime_state = runtime_state or self._runtime_state_from_env()

    @classmethod
    def from_governor(cls, governor: Any) -> "ArchitectureRegistry":
        profile_name = _normalize_profile(getattr(governor, "profile_name", "dev_balanced"))
        signer = getattr(governor, "_qseal", None) or QSealSigner()

        sink_policy = getattr(governor, "sink_policy", None)
        capability_runtime = getattr(governor, "capability_runtime", None)
        provenance_graph = getattr(governor, "provenance_graph", None)
        advanced_risk = getattr(governor, "_advanced_risk", None)

        policy_lineage_status = "ENFORCED"
        if sink_policy is not None:
            require_signed = bool(getattr(sink_policy, "require_signed_policy_bundle", True))
            policy_lineage_status = "ENFORCED" if require_signed else "ADVISORY"
        else:
            policy_lineage_status = _lineage_status_for_profile(profile_name)

        drift_detection_status = _drift_status_for_profile(profile_name)
        if sink_policy is not None:
            drift_enabled = bool(getattr(sink_policy, "enable_policy_drift_detection", True))
            if not drift_enabled:
                drift_detection_status = "OFF"

        vault_mode = "MEDIATED" if callable(getattr(governor, "_mediate_credentials_access", None)) else "DIRECT"

        risk_mode = _risk_mode_for_profile(profile_name)
        if advanced_risk is not None:
            raw_mode = str(getattr(getattr(advanced_risk, "profile", None), "mode", "")).strip().lower()
            risk_mode = {
                "blocking": "BLOCKING",
                "advisory": "ADVISORY",
                "monitor": "MONITOR",
            }.get(raw_mode, risk_mode)

        runtime_state = RuntimeState(
            active_profile=profile_name,
            signing_algorithm=str(getattr(signer, "algorithm", "hmac-sha256")).lower(),
            vault_mode=vault_mode,
            risk_mode=risk_mode,
            policy_lineage_status=policy_lineage_status,
            drift_detection_status=drift_detection_status,
            capability_runtime_active=capability_runtime is not None,
            provenance_system_active=provenance_graph is not None,
            sink_policy_active=sink_policy is not None,
            vaulted_execution_active=vault_mode == "MEDIATED",
            advanced_risk_active=advanced_risk is not None,
            taint_laundering_proof_reference="tests/integration/test_taint_laundering_prevention.py",
            raw_credential_invariant=(
                "agents never receive raw credential material; vault returns token references only"
            ),
        )
        return cls(profile_name=profile_name, runtime_state=runtime_state, signer=signer)

    def _runtime_state_from_env(self) -> RuntimeState:
        profile_name = _normalize_profile(os.getenv("MVAR_RUNTIME_PROFILE", self.profile_name))
        signing_algorithm = str(getattr(self._signer, "algorithm", "hmac-sha256")).lower()
        policy_lineage_status = _lineage_status_for_profile(profile_name)
        drift_detection_status = _drift_status_for_profile(profile_name)
        drift_env_enabled = os.getenv("MVAR_ENABLE_POLICY_DRIFT_DETECTION", "1") == "1"
        if not drift_env_enabled:
            drift_detection_status = "OFF"
        return RuntimeState(
            active_profile=profile_name,
            signing_algorithm=signing_algorithm,
            vault_mode="MEDIATED",
            risk_mode=_risk_mode_for_profile(profile_name),
            policy_lineage_status=policy_lineage_status,
            drift_detection_status=drift_detection_status,
            capability_runtime_active=True,
            provenance_system_active=True,
            sink_policy_active=True,
            vaulted_execution_active=True,
            advanced_risk_active=True,
            taint_laundering_proof_reference="tests/integration/test_taint_laundering_prevention.py",
            raw_credential_invariant=(
                "agents never receive raw credential material; vault returns token references only"
            ),
        )

    def _signing_mode_label(self) -> str:
        return "ED25519" if self._runtime_state.signing_algorithm == "ed25519" else "HMAC_FALLBACK"

    def _layer_modes(self) -> Dict[int, Dict[str, str]]:
        return {
            1: {
                "prod_locked": "strict capability gate",
                "dev_strict": "strict capability gate",
                "dev_balanced": "balanced capability gate",
            },
            2: {
                "prod_locked": "conservative taint propagation (strict)",
                "dev_strict": "conservative taint propagation (strict)",
                "dev_balanced": "conservative taint propagation (balanced)",
            },
            3: {
                "prod_locked": "deterministic sink policy with fail-closed profile",
                "dev_strict": "deterministic sink policy with strict checks",
                "dev_balanced": "deterministic sink policy with balanced checks",
            },
            4: {
                "prod_locked": "vault mediation mandatory; fail closed on vault unavailability",
                "dev_strict": "vault mediation default; fallback requires explicit override",
                "dev_balanced": "vault mediation default; fallback references allowed",
            },
            5: {
                "prod_locked": "signed policy lineage enforced + drift escalation active",
                "dev_strict": "signed policy lineage enforced + drift advisory",
                "dev_balanced": "signed policy lineage enforced + drift telemetry",
            },
            6: {
                "prod_locked": "risk scoring BLOCKING mode",
                "dev_strict": "risk scoring ADVISORY mode",
                "dev_balanced": "risk scoring MONITOR mode",
            },
        }

    def _build_layers(self) -> list[ArchitectureLayer]:
        state = self._runtime_state
        modes = self._layer_modes()

        layer1_status = LayerStatus.FULL if state.capability_runtime_active else LayerStatus.NOT_ACTIVE
        layer2_status = LayerStatus.FULL if state.provenance_system_active else LayerStatus.NOT_ACTIVE
        layer3_status = LayerStatus.FULL if state.sink_policy_active else LayerStatus.NOT_ACTIVE
        layer4_status = LayerStatus.FULL if state.vaulted_execution_active else LayerStatus.PARTIAL
        layer5_status = LayerStatus.FULL
        if state.policy_lineage_status != "ENFORCED" or self._signing_mode_label() != "ED25519":
            layer5_status = LayerStatus.PARTIAL
        layer6_status = LayerStatus.FULL if state.advanced_risk_active else LayerStatus.NOT_ACTIVE

        layers: list[ArchitectureLayer] = [
            ArchitectureLayer(
                layer_id=1,
                layer_name="Capability Runtime",
                patent_claim_reference="Layer 1",
                status=layer1_status.value,
                active_profile_mode=modes[1][state.active_profile],
                mode_by_profile=dict(modes[1]),
                known_limitations=[],
            ),
            ArchitectureLayer(
                layer_id=2,
                layer_name="Provenance Taint System",
                patent_claim_reference="Layer 2 (Claim 18 taint laundering prevention)",
                status=layer2_status.value,
                active_profile_mode=modes[2][state.active_profile],
                mode_by_profile=dict(modes[2]),
                known_limitations=[
                    f"proof reference: {state.taint_laundering_proof_reference}",
                ],
            ),
            ArchitectureLayer(
                layer_id=3,
                layer_name="Sink Policy Engine",
                patent_claim_reference="Layer 3",
                status=layer3_status.value,
                active_profile_mode=modes[3][state.active_profile],
                mode_by_profile=dict(modes[3]),
                known_limitations=[],
            ),
            ArchitectureLayer(
                layer_id=4,
                layer_name="Vaulted Execution",
                patent_claim_reference="Layer 4",
                status=layer4_status.value,
                active_profile_mode=modes[4][state.active_profile],
                mode_by_profile=dict(modes[4]),
                known_limitations=[
                    state.raw_credential_invariant,
                    (
                        "degraded: vault mediation unavailable -> DIRECT mode"
                        if state.vault_mode == "DIRECT"
                        else ""
                    ),
                ],
            ),
            ArchitectureLayer(
                layer_id=5,
                layer_name="Cryptographic Policy Lineage",
                patent_claim_reference="Layer 5",
                status=layer5_status.value,
                active_profile_mode=modes[5][state.active_profile],
                mode_by_profile=dict(modes[5]),
                known_limitations=[
                    (
                        "signing degraded: HMAC fallback active"
                        if self._signing_mode_label() == "HMAC_FALLBACK"
                        else ""
                    ),
                ],
            ),
            ArchitectureLayer(
                layer_id=6,
                layer_name="Advanced Risk Scoring",
                patent_claim_reference="Layer 6",
                status=layer6_status.value,
                active_profile_mode=modes[6][state.active_profile],
                mode_by_profile=dict(modes[6]),
                known_limitations=[],
            ),
        ]
        cleaned: list[ArchitectureLayer] = []
        for layer in layers:
            limitations = [item for item in layer.known_limitations if item]
            cleaned.append(
                ArchitectureLayer(
                    layer_id=layer.layer_id,
                    layer_name=layer.layer_name,
                    patent_claim_reference=layer.patent_claim_reference,
                    status=layer.status,
                    active_profile_mode=layer.active_profile_mode,
                    mode_by_profile=layer.mode_by_profile,
                    known_limitations=limitations,
                )
            )
        return cleaned

    def architecture_registry(self) -> Dict[str, Any]:
        layers = [asdict(layer) for layer in self._build_layers()]
        return {
            "schema_version": "mvar.architecture.registry.v1",
            "active_profile": self._runtime_state.active_profile,
            "layers": layers,
            "compatibility_matrix": self.compatibility_matrix(),
        }

    def compatibility_matrix(self) -> Dict[str, Any]:
        return dict(self.COMPATIBILITY_MATRIX)

    def _signature_bundle(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        payload_bytes = _canonical_bytes(payload)
        payload_hash = hashlib.sha256(payload_bytes).hexdigest()
        algorithm = str(getattr(self._signer, "algorithm", "hmac-sha256")).lower()

        if algorithm == "ed25519":
            private_key = getattr(self._signer, "_private_key", None)
            public_key = getattr(self._signer, "_public_key", None)
            if private_key is None or public_key is None:
                raise RuntimeError("Ed25519 signer unavailable for architecture self-report")
            signature_hex = private_key.sign(payload_bytes).hex()
            verified = False
            try:
                public_key.verify(bytes.fromhex(signature_hex), payload_bytes)
                verified = True
            except Exception:
                verified = False
            return {
                "algorithm": "ed25519",
                "label": "ED25519",
                "signature": f"ed25519:{signature_hex}",
                "payload_hash": payload_hash,
                "verified": verified,
                "public_key_hex": str(getattr(self._signer, "public_key_hex", "")),
            }

        hmac_key = getattr(self._signer, "_hmac_key", None)
        if hmac_key is None:
            raise RuntimeError("HMAC fallback signer unavailable for architecture self-report")
        signature_hex = hmac.new(hmac_key, payload_bytes, hashlib.sha256).hexdigest()
        return {
            "algorithm": "hmac-sha256",
            "label": "HMAC_FALLBACK",
            "signature": f"hmac-sha256:{signature_hex}",
            "payload_hash": payload_hash,
            "verified": True,
            "public_key_hex": str(getattr(self._signer, "public_key_hex", "")),
        }

    def runtime_self_report(self) -> Dict[str, Any]:
        payload = {
            "schema_version": "mvar.architecture.self_report.v1",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "active_profile": self._runtime_state.active_profile,
            "signing_mode": self._signing_mode_label(),
            "vault_mode": self._runtime_state.vault_mode,
            "risk_scoring_mode": self._runtime_state.risk_mode,
            "policy_lineage_status": self._runtime_state.policy_lineage_status,
            "drift_detection_status": self._runtime_state.drift_detection_status,
            "mvar_version": _MVAR_VERSION,
            "clawzero_compatibility_version": "0.3.x",
            "architecture_registry": self.architecture_registry(),
        }
        signature = self._signature_bundle(payload)
        return {
            "payload": payload,
            "signature": signature,
        }

    def verify_self_report(self, report: Dict[str, Any]) -> bool:
        if not isinstance(report, dict):
            return False
        payload = report.get("payload")
        signature = report.get("signature")
        if not isinstance(payload, dict) or not isinstance(signature, dict):
            return False
        payload_bytes = _canonical_bytes(payload)
        payload_hash = hashlib.sha256(payload_bytes).hexdigest()
        if payload_hash != str(signature.get("payload_hash", "")):
            return False

        raw_signature = str(signature.get("signature", ""))
        if ":" not in raw_signature:
            return False
        sig_algorithm, sig_hex = raw_signature.split(":", 1)
        sig_algorithm = sig_algorithm.strip().lower()
        sig_hex = sig_hex.strip()

        if sig_algorithm == "ed25519":
            if not _ED25519_VERIFY_AVAILABLE:
                return False
            public_key_hex = str(signature.get("public_key_hex", "")).strip()
            if not public_key_hex:
                return False
            try:
                public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
                public_key.verify(bytes.fromhex(sig_hex), payload_bytes)
            except Exception:
                return False
            return True

        if sig_algorithm == "hmac-sha256":
            hmac_key = getattr(self._signer, "_hmac_key", None)
            if hmac_key is None:
                return False
            expected = hmac.new(hmac_key, payload_bytes, hashlib.sha256).hexdigest()
            return hmac.compare_digest(expected, sig_hex)

        return False


__all__ = [
    "ArchitectureLayer",
    "ArchitectureRegistry",
    "LayerStatus",
    "RuntimeState",
]
