"""Public v1 convenience API for wrapping tool callables with MVAR enforcement."""

from __future__ import annotations

from functools import wraps
from typing import Any, Callable, Dict, Optional

from mvar_adapters.base import MVARExecutionAdapter
from mvar_core import __version__
from mvar_core.profiles import SecurityProfile, create_default_runtime


class ExecutionBlocked(RuntimeError):
    """Raised when MVAR returns a BLOCK decision."""

    def __init__(self, message: str, decision: Dict[str, Any]):
        super().__init__(message)
        self.decision = decision


class StepUpRequired(RuntimeError):
    """Raised when MVAR returns a STEP_UP decision."""

    def __init__(self, message: str, decision: Dict[str, Any]):
        super().__init__(message)
        self.decision = decision


_PROFILE_MAP = {
    "strict": SecurityProfile.STRICT,
    "balanced": SecurityProfile.BALANCED,
    "permissive": SecurityProfile.MONITOR,
}


def _integrity_to_decision_value(raw_integrity: str) -> str:
    normalized = raw_integrity.strip().lower()
    if normalized == "trusted":
        return "TRUSTED"
    if normalized == "untrusted":
        return "UNTRUSTED"
    # v1 schema does not define UNKNOWN; TAINTED is the closest conservative mapping.
    return "TAINTED"


def _policy_profile_for_record(profile: SecurityProfile) -> str:
    if profile == SecurityProfile.MONITOR:
        return "permissive"
    return profile.value


def _to_decision_record(decision: Any, profile: SecurityProfile) -> Dict[str, Any]:
    raw = decision.to_dict()
    return {
        "apiVersion": "mvar.io/v1",
        "kind": "DecisionRecord",
        "metadata": {
            "decisionId": decision.decision_id or "",
            "intentId": "",
            "sessionId": "",
        },
        "outcome": str(raw.get("outcome", "")).upper(),
        "reason": str(raw.get("reason", "")),
        "integrity": _integrity_to_decision_value(
            str(raw.get("provenance", {}).get("integrity", "unknown"))
        ),
        "sinkLevel": str(raw.get("sink", {}).get("risk", "")).upper(),
        "timestamp": str(raw.get("timestamp", "")),
        "policy": {
            "profile": _policy_profile_for_record(profile),
            "rulesEvaluated": [str(item) for item in raw.get("evaluation_trace", [])],
            "matchedRule": "",
        },
        "audit": {
            "logged": True,
            "logDestination": "",
            "qsealSignature": str(raw.get("qseal_signature") or ""),
            "complianceFlags": [],
        },
        "performance": {
            "evaluationTimeMs": 0.0,
            "cacheHit": False,
        },
    }


def protect(
    tool_fn: Callable,
    *,
    profile: str = "balanced",
    trusted: bool = False,
    tool_name: Optional[str] = None,
) -> Callable:
    """Wrap a tool callable with MVAR policy enforcement.

    The wrapped callable preserves the original invocation signature and passes
    all positional/keyword arguments through unchanged.
    """

    if not callable(tool_fn):
        raise TypeError("tool_fn must be callable")

    profile_key = profile.strip().lower()
    if profile_key not in _PROFILE_MAP:
        allowed = ", ".join(sorted(_PROFILE_MAP))
        raise ValueError(f"Unsupported profile '{profile}'. Expected one of: {allowed}")

    mapped_profile = _PROFILE_MAP[profile_key]
    graph, policy, _capability_runtime = create_default_runtime(profile=mapped_profile)
    adapter = MVARExecutionAdapter(policy, graph)

    resolved_tool_name = tool_name or getattr(tool_fn, "__name__", "tool")
    if trusted:
        provenance_node_id = adapter.create_user_provenance(resolved_tool_name)
    else:
        provenance_node_id = adapter.create_untrusted_provenance(
            resolved_tool_name,
            source="protect-wrapper",
        )

    @wraps(tool_fn)
    def _wrapped(*args: Any, **kwargs: Any) -> Any:
        # v1 heuristic: derive target from first positional argument; expose
        # explicit metadata overrides in a future version.
        target = str(args[0]) if args else "unknown"
        decision = adapter.authorize_execution(
            tool=resolved_tool_name,
            action="execute",
            target=target,
            provenance_node_id=provenance_node_id,
        )
        decision_record = _to_decision_record(decision, mapped_profile)

        outcome = decision_record["outcome"]
        if outcome == "ALLOW":
            return tool_fn(*args, **kwargs)
        if outcome == "BLOCK":
            raise ExecutionBlocked(decision_record["reason"], decision_record)
        if outcome == "STEP_UP":
            raise StepUpRequired(decision_record["reason"], decision_record)
        raise RuntimeError(f"Unexpected policy outcome: {outcome}")

    return _wrapped


__all__ = ["protect", "ExecutionBlocked", "StepUpRequired", "__version__"]
