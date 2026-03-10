"""Public v1 convenience API for wrapping tool callables with MVAR enforcement."""

from __future__ import annotations

from functools import wraps
from typing import Any, Callable, Dict, Optional, Tuple

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


def _infer_action(tool_name: str, explicit_action: Optional[str]) -> str:
    if explicit_action:
        return explicit_action
    normalized_tool = tool_name.strip().lower()
    if normalized_tool in {"bash", "shell", "sh", "zsh", "cmd", "powershell"}:
        return "exec"
    if normalized_tool in {"http", "https"}:
        return "post"
    return "execute"


def _default_target_extractor(args: Tuple[Any, ...], kwargs: Dict[str, Any]) -> str:
    if args:
        return str(args[0])
    if "target" in kwargs:
        return str(kwargs["target"])
    return "unknown"


def _should_tighten_from_signal(signal: Any) -> bool:
    if not isinstance(signal, dict):
        return False
    raw_score = signal.get("uncertainty_score")
    try:
        return float(raw_score) > 0.8
    except (TypeError, ValueError):
        return False


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
    signal: Optional[Dict[str, Any]] = None,
    *,
    profile: str = "balanced",
    trusted: bool = False,
    tool_name: Optional[str] = None,
    action: Optional[str] = None,
    target_extractor: Optional[Callable[[Tuple[Any, ...], Dict[str, Any]], str]] = None,
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
    if _should_tighten_from_signal(signal):
        mapped_profile = SecurityProfile.STRICT
    graph, policy, _capability_runtime = create_default_runtime(profile=mapped_profile)
    adapter = MVARExecutionAdapter(policy, graph)

    resolved_tool_name = tool_name or getattr(tool_fn, "__name__", "tool")
    resolved_action = _infer_action(resolved_tool_name, action)
    resolved_target_extractor = target_extractor or _default_target_extractor
    if trusted:
        provenance_node_id = adapter.create_user_provenance(resolved_tool_name)
    else:
        provenance_node_id = adapter.create_untrusted_provenance(
            resolved_tool_name,
            source="protect-wrapper",
        )

    @wraps(tool_fn)
    def _wrapped(*args: Any, **kwargs: Any) -> Any:
        target = resolved_target_extractor(args, kwargs)
        parameters = dict(kwargs) if kwargs else None
        pre_decision = adapter.evaluate(
            tool=resolved_tool_name,
            action=resolved_action,
            target=target,
            provenance_node_id=provenance_node_id,
            parameters=parameters,
        )
        decision = adapter.authorize_execution(
            tool=resolved_tool_name,
            action=resolved_action,
            target=target,
            provenance_node_id=provenance_node_id,
            parameters=parameters,
            execution_token=getattr(pre_decision, "execution_token", None),
            pre_evaluated_decision=pre_decision,
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
