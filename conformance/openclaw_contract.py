"""
OpenClaw/ClawBot adapter contract for MVAR conformance.

This contract focuses on the gatewayUrl token-exfiltration class of failures
and execution-boundary enforcement invariants.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional, Protocol


class GatewayDecision(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"


@dataclass
class GatewayAuthResult:
    decision: GatewayDecision
    reason: str
    normalized_url: Optional[str] = None


class OpenClawAdapterUnderTest(Protocol):
    """
    Minimum required API for OpenClaw/ClawBot security conformance.
    """

    def reset_gateway_observer(self) -> None:
        """Reset side-effect observer state."""

    def was_last_gateway_token_transmitted(self) -> bool:
        """Return True only if a gateway token was transmitted on last attempt."""

    def authorize_gateway_connect(
        self,
        gateway_url: str,
        *,
        source: str,
        user_confirmed: bool,
    ) -> GatewayAuthResult:
        """
        Validate and authorize gateway connection target.

        Implementations should enforce:
        - no blind trust of query-string gatewayUrl
        - explicit user confirmation for gateway change
        - allowlist / policy validation before connect
        """

    def connect_gateway(
        self,
        gateway_url: str,
        *,
        gateway_token: str,
        source: str,
        user_confirmed: bool,
    ) -> GatewayAuthResult:
        """
        Attempt connect. Must never transmit token when authorization blocks.
        """

    def create_untrusted_provenance(self, text: str, source: str = "external_doc") -> str:
        """Create untrusted provenance id."""

    def evaluate(
        self,
        tool: str,
        action: str,
        target: str,
        provenance_node_id: str,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """Policy preflight."""

    def authorize_execution(
        self,
        tool: str,
        action: str,
        target: str,
        provenance_node_id: str,
        parameters: Optional[Dict[str, Any]] = None,
        execution_token: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """Execution boundary authorization call (required)."""
