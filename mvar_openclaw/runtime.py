from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from mvar_adapters.base import AdapterExecutionResult
from mvar_adapters.openclaw import MVAROpenClawAdapter


@dataclass
class OpenClawDispatchBatchResult:
    """Summary for one OpenClaw planner dispatch batch."""

    results: List[AdapterExecutionResult]
    total_dispatches: int
    executed_dispatches: int
    blocked_dispatches: int
    step_up_dispatches: int


class MVAROpenClawRuntime:
    """OpenClaw runtime integration wrapper around MVAR enforcement boundary."""

    def __init__(self, policy: Any, graph: Any, strict: bool = True, execute_on_step_up: bool = False):
        self.adapter = MVAROpenClawAdapter(
            policy,
            graph,
            strict=strict,
            execute_on_step_up=execute_on_step_up,
        )

    def execute_planner_dispatches(
        self,
        planner_payload: Any,
        tool_registry: Dict[str, Callable[..., Any]],
        provenance_node_id: Optional[str] = None,
        source_text: str = "",
        source_is_untrusted: bool = True,
    ) -> OpenClawDispatchBatchResult:
        dispatches = self.extract_dispatches(planner_payload)
        results: List[AdapterExecutionResult] = []

        for dispatch in dispatches:
            result = self.adapter.execute_tool_dispatch(
                dispatch=dispatch,
                tool_registry=tool_registry,
                provenance_node_id=provenance_node_id,
                source_text=source_text,
                source_is_untrusted=source_is_untrusted,
            )
            results.append(result)

        executed = sum(1 for r in results if r.executed)
        blocked = sum(1 for r in results if getattr(r.decision.outcome, "value", "") == "block")
        step_up = sum(1 for r in results if getattr(r.decision.outcome, "value", "") == "step_up")

        return OpenClawDispatchBatchResult(
            results=results,
            total_dispatches=len(results),
            executed_dispatches=executed,
            blocked_dispatches=blocked,
            step_up_dispatches=step_up,
        )

    def extract_dispatches(self, planner_payload: Any) -> List[Dict[str, Any]]:
        raw_dispatches: List[Dict[str, Any]] = []

        if isinstance(planner_payload, list):
            raw_dispatches.extend([d for d in planner_payload if isinstance(d, dict)])
        elif isinstance(planner_payload, dict):
            if isinstance(planner_payload.get("dispatches"), list):
                raw_dispatches.extend([d for d in planner_payload["dispatches"] if isinstance(d, dict)])

            if isinstance(planner_payload.get("tool_calls"), list):
                raw_dispatches.extend([d for d in planner_payload["tool_calls"] if isinstance(d, dict)])

            if isinstance(planner_payload.get("dispatch"), dict):
                raw_dispatches.append(planner_payload["dispatch"])

            if any(k in planner_payload for k in ("tool", "name", "tool_name", "function")):
                raw_dispatches.append(planner_payload)

        normalized: List[Dict[str, Any]] = []
        for raw in raw_dispatches:
            parsed = self._normalize_dispatch(raw)
            if parsed is not None:
                normalized.append(parsed)

        return normalized

    def _normalize_dispatch(self, dispatch: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not isinstance(dispatch, dict):
            return None

        function_obj = dispatch.get("function") if isinstance(dispatch.get("function"), dict) else {}
        tool_name = (
            dispatch.get("tool")
            or dispatch.get("name")
            or dispatch.get("tool_name")
            or function_obj.get("name")
        )
        if not tool_name:
            return None

        raw_args = (
            dispatch.get("args")
            or dispatch.get("arguments")
            or dispatch.get("input")
            or function_obj.get("arguments")
            or {}
        )
        if isinstance(raw_args, str):
            if raw_args.strip():
                try:
                    args = json.loads(raw_args)
                except json.JSONDecodeError:
                    args = {"raw": raw_args}
            else:
                args = {}
        elif isinstance(raw_args, dict):
            args = dict(raw_args)
        else:
            args = {"value": raw_args}

        action = str(dispatch.get("action") or args.get("action") or "run")
        target = dispatch.get("target") or args.get("target")

        normalized: Dict[str, Any] = {
            "tool": tool_name,
            "action": action,
            "args": args,
        }
        if target is not None:
            normalized["target"] = target

        return normalized
