from __future__ import annotations

from typing import Any, Callable, Dict, Optional

from .base import AdapterExecutionResult, MVARExecutionAdapter


class MVARLangChainAdapter(MVARExecutionAdapter):
    """Wrapper for LangChain tool-style callables."""

    def wrap_tool(
        self,
        tool_name: str,
        tool_callable: Callable[..., Any],
        action: str = "run",
        target_getter: Optional[Callable[[tuple[Any, ...], Dict[str, Any]], str]] = None,
    ) -> Callable[..., AdapterExecutionResult]:
        def _wrapped(*args: Any, **kwargs: Any) -> AdapterExecutionResult:
            provenance_node_id = kwargs.pop("provenance_node_id", None)
            source_text = kwargs.pop("source_text", "")
            source_is_untrusted = kwargs.pop("source_is_untrusted", True)
            execution_token = kwargs.pop("execution_token", None)

            target_is_fallback = False
            if target_getter:
                target = target_getter(args, kwargs)
            else:
                resolved = kwargs.get("target") or kwargs.get("command") or kwargs.get("path")
                if resolved is None:
                    target = str(tool_name)
                    target_is_fallback = True
                else:
                    target = str(resolved)

            return self.enforce_and_execute(
                tool=tool_name,
                action=action,
                target=target,
                execute_fn=lambda: tool_callable(*args, **kwargs),
                provenance_node_id=provenance_node_id,
                source_text=source_text,
                source_is_untrusted=source_is_untrusted,
                parameters={"args": list(args), "kwargs": kwargs},
                execution_token=execution_token,
                target_is_fallback=target_is_fallback,
            )

        return _wrapped
