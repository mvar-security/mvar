from __future__ import annotations

from dataclasses import dataclass
import logging
from typing import Any, Callable, Dict, Optional

try:
    from mvar_core.provenance import ProvenanceGraph, provenance_external_doc, provenance_user_input
    from mvar_core.sink_policy import PolicyDecision, PolicyOutcome, SinkPolicy
except ImportError:
    from provenance import ProvenanceGraph, provenance_external_doc, provenance_user_input
    from sink_policy import PolicyDecision, PolicyOutcome, SinkPolicy


@dataclass
class AdapterExecutionResult:
    decision: PolicyDecision
    executed: bool
    result: Any = None
    execution_error: Optional[str] = None


class MVARExecutionAdapter:
    """
    Strict execution wrapper for adapter integrations.

    Security default: never execute sinks unless authorize_execution returns ALLOW.
    STEP_UP is non-executable by default and requires out-of-band approval flow.
    """

    def __init__(
        self,
        policy: SinkPolicy,
        provenance_graph: ProvenanceGraph,
        strict: bool = True,
        execute_on_step_up: bool = False,
    ):
        self.policy = policy
        self.graph = provenance_graph
        self.strict = strict
        self.execute_on_step_up = execute_on_step_up
        self._last_sink_executed = False
        self._logger = logging.getLogger(__name__)

    def reset_execution_observer(self) -> None:
        self._last_sink_executed = False

    def was_last_sink_call_executed(self) -> bool:
        return self._last_sink_executed

    def create_user_provenance(self, text: str) -> str:
        return provenance_user_input(self.graph, text).node_id

    def create_untrusted_provenance(self, text: str, source: str = "external_doc") -> str:
        return provenance_external_doc(self.graph, text, doc_url=source).node_id

    def evaluate(
        self,
        tool: str,
        action: str,
        target: str,
        provenance_node_id: str,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> PolicyDecision:
        return self.policy.evaluate(
            tool=tool,
            action=action,
            target=target,
            provenance_node_id=provenance_node_id,
            parameters=parameters,
        )

    def authorize_execution(
        self,
        tool: str,
        action: str,
        target: str,
        provenance_node_id: str,
        parameters: Optional[Dict[str, Any]] = None,
        execution_token: Optional[Dict[str, Any]] = None,
    ) -> PolicyDecision:
        return self.policy.authorize_execution(
            tool=tool,
            action=action,
            target=target,
            provenance_node_id=provenance_node_id,
            parameters=parameters,
            execution_token=execution_token,
        )

    def enforce_and_execute(
        self,
        tool: str,
        action: str,
        target: str,
        execute_fn: Callable[[], Any],
        provenance_node_id: Optional[str] = None,
        source_text: str = "",
        source_is_untrusted: bool = True,
        parameters: Optional[Dict[str, Any]] = None,
        execution_token: Optional[Dict[str, Any]] = None,
        target_is_fallback: bool = False,
    ) -> AdapterExecutionResult:
        self._last_sink_executed = False

        if provenance_node_id is None:
            if source_is_untrusted:
                provenance_node_id = self.create_untrusted_provenance(source_text or "external input")
            else:
                provenance_node_id = self.create_user_provenance(source_text or "user input")

        decision = self.evaluate(tool, action, target, provenance_node_id, parameters=parameters)
        token = execution_token if execution_token is not None else decision.execution_token

        auth = self.authorize_execution(
            tool,
            action,
            target,
            provenance_node_id,
            parameters=parameters,
            execution_token=token,
        )

        outcome_value = getattr(auth.outcome, "value", str(auth.outcome))

        if target_is_fallback:
            message = (
                f"Adapter target unresolved for {tool}.{action}; "
                "policy evaluated fallback target only"
            )
            self._logger.warning(message)
            if self.strict:
                raise PermissionError(message)
            return AdapterExecutionResult(decision=auth, executed=False, execution_error=message)

        if outcome_value == "block":
            if self.strict:
                raise PermissionError(auth.reason)
            return AdapterExecutionResult(decision=auth, executed=False)

        if outcome_value == "step_up" and not self.execute_on_step_up:
            if self.strict:
                raise PermissionError("STEP_UP required before execution")
            return AdapterExecutionResult(decision=auth, executed=False)

        try:
            result = execute_fn()
            self._last_sink_executed = True
            return AdapterExecutionResult(decision=auth, executed=True, result=result)
        except Exception as exc:
            error_message = f"{type(exc).__name__}: {exc}"
            if hasattr(auth, "evaluation_trace") and isinstance(auth.evaluation_trace, list):
                auth.evaluation_trace.append(f"execution_error: {error_message}")
            if self.strict:
                raise RuntimeError(f"Adapter execution failed after authorization: {error_message}") from exc
            return AdapterExecutionResult(decision=auth, executed=False, execution_error=error_message)
