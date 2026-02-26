from __future__ import annotations

from typing import Any, Callable, Dict, Optional

from .base import AdapterExecutionResult, MVARExecutionAdapter


class MVARCrewAIAdapter(MVARExecutionAdapter):
    """Wrapper for CrewAI-style tool callables."""

    def wrap_tool(
        self,
        tool_name: str,
        tool_callable: Callable[..., Any],
        action: str = "run",
        target_getter: Optional[Callable[[Any], str]] = None,
    ) -> Callable[..., AdapterExecutionResult]:
        def _wrapped(tool_input: Any = None, **kwargs: Any) -> AdapterExecutionResult:
            provenance_node_id = kwargs.pop("provenance_node_id", None)
            source_text = kwargs.pop("source_text", "")
            source_is_untrusted = kwargs.pop("source_is_untrusted", True)
            execution_token = kwargs.pop("execution_token", None)

            if target_getter:
                resolved_target = target_getter(tool_input)
            elif isinstance(tool_input, dict):
                resolved_target = (
                    tool_input.get("target")
                    or tool_input.get("command")
                    or tool_input.get("path")
                )
            else:
                resolved_target = str(tool_input) if tool_input is not None else None

            target_is_fallback = resolved_target is None
            target = str(resolved_target or tool_name)
            parameters = dict(tool_input) if isinstance(tool_input, dict) else {"tool_input": tool_input}

            def _invoke() -> Any:
                if isinstance(tool_input, dict):
                    try:
                        return tool_callable(**tool_input)
                    except TypeError:
                        return tool_callable(tool_input)
                return tool_callable(tool_input)

            return self.enforce_and_execute(
                tool=tool_name,
                action=action,
                target=target,
                execute_fn=_invoke,
                provenance_node_id=provenance_node_id,
                source_text=source_text,
                source_is_untrusted=source_is_untrusted,
                parameters=parameters,
                execution_token=execution_token,
                target_is_fallback=target_is_fallback,
            )

        return _wrapped
