"""
Adapter conformance contract types.

This module is intended to be vendored/imported by adapter repositories.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional, Protocol


class ConformanceOutcome(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    STEP_UP = "step_up"


@dataclass
class ConformanceDecision:
    outcome: ConformanceOutcome
    reason: str
    execution_token: Optional[Dict[str, Any]] = None
    evaluation_trace: Optional[list[str]] = None


class AdapterUnderTest(Protocol):
    """Minimum required API for MVAR adapter conformance."""

    def create_user_provenance(self, text: str) -> str:
        """Return provenance node id for user input."""

    def create_untrusted_provenance(self, text: str, source: str = "external_doc") -> str:
        """Return provenance node id for untrusted external input."""

    def evaluate(
        self,
        tool: str,
        action: str,
        target: str,
        provenance_node_id: str,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> ConformanceDecision:
        """Policy preflight; may issue execution token."""

    def authorize_execution(
        self,
        tool: str,
        action: str,
        target: str,
        provenance_node_id: str,
        parameters: Optional[Dict[str, Any]] = None,
        execution_token: Optional[Dict[str, Any]] = None,
    ) -> ConformanceDecision:
        """Execution boundary authorization call (required)."""

    def execute_sink(self, tool: str, action: str, target: str, parameters: Optional[Dict[str, Any]] = None) -> Any:
        """Actual sink execution wrapper used by adapter runtime."""

    def was_last_sink_call_executed(self) -> bool:
        """Return whether a sink call actually executed."""

    def reset_execution_observer(self) -> None:
        """Reset sink execution observer state between tests."""
