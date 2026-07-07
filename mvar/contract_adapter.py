"""MVAR conformance adapter — exposes the MVAR engine through the frozen core contract.

Migrate-don't-rewrite (Phase 4C): this is a thin shim over the existing ExecutionGovernor.
It maps the contract's ExecutionIntent/DecisionRecord onto MVAR's native calls, so any edge
(SDK, gateway, on-device) can drive MVAR purely through `mirra_core_contract.ExecutionAuthorizer`
without importing MVAR internals.

The contract package is an optional dependency: if it is not installed, this module still
imports (the types degrade to Any) so MVAR keeps working standalone.
"""

from __future__ import annotations

from typing import Any

try:
    from mirra_core_contract import (
        AgentIdentity,
        Decision,
        DecisionRecord,
        ExecutionIntent,
    )
    _CONTRACT = True
except Exception:  # contract not installed → standalone MVAR still works
    AgentIdentity = Any  # type: ignore
    DecisionRecord = Any  # type: ignore
    ExecutionIntent = Any  # type: ignore
    Decision = None  # type: ignore
    _CONTRACT = False

from mvar.governor import ExecutionGovernor


class MVARExecutionAuthorizer:
    """Implements the contract's ExecutionAuthorizer over MVAR's ExecutionGovernor.

    Fails closed: if the governor cannot produce a decision, returns a BLOCK DecisionRecord
    rather than raising past the boundary or defaulting to allow.
    """

    def __init__(self, profile: str = "prod_locked", governor: ExecutionGovernor | None = None):
        self._governor = governor or ExecutionGovernor(profile=profile)

    def authorize(self, intent: "ExecutionIntent", identity: "AgentIdentity") -> "DecisionRecord":
        payload = {
            "request_id": getattr(intent, "request_id", ""),
            "agent_id": getattr(intent, "agent_id", ""),
            "sink_type": getattr(intent, "sink_type", ""),
            "target": getattr(intent, "target", ""),
            "arguments": getattr(intent, "arguments", {}) or {},
            "prompt_provenance": getattr(intent, "provenance", {}) or {},
        }
        try:
            result = self._governor.evaluate(payload)
        except Exception as exc:
            return self._block(payload.get("request_id", ""), f"engine_error: {exc}")

        decision_value = str(getattr(result, "decision", "block")).lower()
        if decision_value not in {"allow", "block", "annotate"}:
            return self._block(payload.get("request_id", ""), "unnormalizable_decision")

        if not _CONTRACT:
            return result  # standalone: hand back the native decision

        return DecisionRecord(
            request_id=payload.get("request_id", ""),
            decision=decision_value,
            reason_code=str(getattr(result, "reason_code", "")),
            policy_id=str(getattr(result, "policy_id", "")),
            engine=str(getattr(result, "engine", "mvar-security")),
            witness_signature=str(getattr(result, "witness_signature", "") or ""),
            witness_public_key=getattr(result, "witness_public_key", None),
        )

    @staticmethod
    def _block(request_id: str, reason: str) -> "DecisionRecord":
        if not _CONTRACT:
            raise RuntimeError(f"MVAR authorize failed closed: {reason}")
        return DecisionRecord(
            request_id=request_id,
            decision=Decision.BLOCK.value,
            reason_code=reason,
            policy_id="mvar-security",
            engine="mvar-security",
        )
