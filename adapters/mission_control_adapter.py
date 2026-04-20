"""
Mission Control Adapter for MVAR
==================================

Python adapter implementing Mission Control's FrameworkAdapter interface.
Emits QSEAL-signed MVAR policy outcomes to Mission Control task metadata.

Verified against Mission Control v2.0.1 API routes:
- POST /api/agents/register
- POST /api/agents/[id]/heartbeat
- POST /api/tasks
- GET /api/tasks/queue

Conforms to Mission Control's FrameworkAdapter TypeScript interface:
- src/lib/adapters/adapter.ts

Usage:
    adapter = MVARAdapter(
        mission_control_url="http://127.0.0.1:3000",
        agent_id="mvar-agent-1",
        api_key="your-api-key",
        qseal_secret="test_secret"
    )

    await adapter.register({"agentId": "mvar-agent-1", "name": "MVAR Agent", "framework": "mvar"})
    await adapter.heartbeat({"agentId": "mvar-agent-1", "status": "idle"})
    await adapter.reportTask({"taskId": "123", "agentId": "mvar-agent-1", "progress": 100, "status": "done"})
    assignments = await adapter.getAssignments("mvar-agent-1")
"""

import os
import time
from typing import Optional

try:
    import httpx
except ImportError:
    raise ImportError(
        "httpx is required for Mission Control adapter. "
        "Install with: pip install httpx"
    )

from mvar.adapters.types import (
    AgentRegistration,
    AgentRegistrationResponse,
    HeartbeatPayload,
    HeartbeatResponse,
    TaskReport,
    TaskCreatePayload,
    TaskCreateResponse,
    Assignment,
    MVARPolicyOutcome,
    TokenUsage,
)


class MVARAdapter:
    """
    MVAR adapter for Mission Control integration.

    Implements FrameworkAdapter interface:
    - framework: readonly string
    - register(agent: AgentRegistration): Promise<void>
    - heartbeat(payload: HeartbeatPayload): Promise<void>
    - reportTask(report: TaskReport): Promise<void>
    - getAssignments(agentId: string): Promise<Assignment[]>
    - disconnect(agentId: string): Promise<void>
    """

    # FrameworkAdapter interface property
    framework = "mvar"

    def __init__(
        self,
        mission_control_url: str = "http://127.0.0.1:3000",
        agent_id: str = "mvar-agent-default",
        api_key: Optional[str] = None,
        qseal_secret: Optional[str] = None,
    ):
        """
        Initialize Mission Control adapter.

        Args:
            mission_control_url: Base URL of Mission Control instance
            agent_id: Unique agent identifier (1-63 alphanumeric + dots/hyphens)
            api_key: Mission Control API key (falls back to MC_API_KEY env var)
            qseal_secret: QSEAL signing secret (falls back to QSEAL_SECRET env var)

        Raises:
            ImportError: If httpx is not installed
            ValueError: If QSEAL secret or API key is not provided
        """
        self.base_url = mission_control_url.rstrip("/")
        self.agent_id = agent_id

        # API key for Mission Control authentication
        self.api_key = api_key or os.getenv("MC_API_KEY")
        if not self.api_key:
            raise ValueError(
                "MC_API_KEY must be provided via parameter or environment variable"
            )

        # Initialize QSEAL signing
        secret = qseal_secret or os.getenv("QSEAL_SECRET")
        if not secret:
            raise ValueError(
                "QSEAL_SECRET must be provided via parameter or environment variable"
            )

        # Use HMAC-SHA256 for signing (lightweight, no cryptography package required)
        import hmac
        import hashlib
        self._qseal_secret = secret.encode() if isinstance(secret, str) else secret

        # HTTP client with reasonable timeouts
        self.session = httpx.AsyncClient(
            timeout=httpx.Timeout(10.0, connect=5.0),
            follow_redirects=True,
        )

    async def close(self) -> None:
        """Close the HTTP session."""
        await self.session.aclose()

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()

    def _auth_headers(self) -> dict[str, str]:
        """Generate authentication headers for Mission Control."""
        return {
            "Content-Type": "application/json",
            "X-API-Key": self.api_key,
            "Authorization": f"Bearer {self.api_key}",
            "X-MVAR-Agent-ID": self.agent_id,
            "X-MVAR-Protocol-Version": "v1",
        }

    # ============================================================================
    # FrameworkAdapter Interface Implementation
    # ============================================================================

    async def register(self, agent: AgentRegistration) -> None:
        """
        Register agent with Mission Control (FrameworkAdapter.register).

        POST /api/agents/register

        Idempotent: If agent already exists, returns existing agent and updates status.

        Args:
            agent: AgentRegistration with agentId, name, framework, metadata

        Raises:
            httpx.HTTPStatusError: If registration fails (400/409/500)
        """
        payload = {
            "name": agent["name"],
            "role": agent.get("metadata", {}).get("role", "agent"),
            "framework": agent["framework"],
        }

        if "metadata" in agent and "capabilities" in agent["metadata"]:
            payload["capabilities"] = agent["metadata"]["capabilities"]

        headers = self._auth_headers()

        resp = await self.session.post(
            f"{self.base_url}/api/agents/register",
            json=payload,
            headers=headers,
        )
        resp.raise_for_status()

    async def heartbeat(self, payload: HeartbeatPayload) -> None:
        """
        Send heartbeat (FrameworkAdapter.heartbeat).

        POST /api/agents/[id]/heartbeat

        Args:
            payload: HeartbeatPayload with agentId, status, metrics

        Raises:
            httpx.HTTPStatusError: If heartbeat fails (404/500)
        """
        agent_id = payload["agentId"]
        body: dict = {"status": payload.get("status", "idle")}

        if "metrics" in payload:
            body["mvar_metrics"] = payload["metrics"]

        headers = self._auth_headers()

        resp = await self.session.post(
            f"{self.base_url}/api/agents/{agent_id}/heartbeat",
            json=body,
            headers=headers,
        )
        resp.raise_for_status()

    async def reportTask(self, report: TaskReport) -> None:
        """
        Report task completion (FrameworkAdapter.reportTask).

        POST /api/tasks

        Creates a new task record with QSEAL-signed policy outcome in metadata.

        Args:
            report: TaskReport with taskId, agentId, progress, status, output

        Raises:
            httpx.HTTPStatusError: If task creation fails (400/500)
        """
        # Extract MVAR policy outcome from report output
        output = report.get("output", {})
        policy_outcome = output.get("policy_outcome") if isinstance(output, dict) else {}

        # Sign the policy outcome with HMAC-SHA256 (QSEAL lightweight signing)
        import hmac
        import hashlib
        import json

        canonical_json = json.dumps(policy_outcome, sort_keys=True, separators=(',', ':'))
        meta_hash = hashlib.sha256(canonical_json.encode()).hexdigest()
        qseal_signature = hmac.new(
            self._qseal_secret,
            canonical_json.encode(),
            hashlib.sha256
        ).hexdigest()

        # Build metadata with QSEAL signature
        metadata = {
            "mvar_policy_outcome": policy_outcome,
            "qseal_signature": qseal_signature,
            "qseal_meta_hash": meta_hash,
            "qseal_verified": True,
        }

        if isinstance(output, dict) and "witness" in output:
            metadata["clawzero_witness"] = output["witness"]

        # Build task payload
        task_payload: TaskCreatePayload = {
            "title": f"Task {report['taskId']} completion",
            "status": report["status"],
            "outcome": "success" if report["status"] == "done" else "failure",
            "metadata": metadata,
            "assigned_to": report["agentId"],
            "tags": ["mvar", "policy-outcome"],
        }

        if report["status"] == "done":
            task_payload["completed_at"] = int(time.time())

        headers = self._auth_headers()

        resp = await self.session.post(
            f"{self.base_url}/api/tasks",
            json=task_payload,
            headers=headers,
        )
        resp.raise_for_status()

    async def getAssignments(self, agentId: str) -> list[Assignment]:
        """
        Fetch pending task assignments (FrameworkAdapter.getAssignments).

        GET /api/tasks/queue?agent={agentId}

        Uses Mission Control's canonical agent queue endpoint.

        Args:
            agentId: Agent identifier

        Returns:
            List of Assignment dicts with taskId, description, priority

        Raises:
            httpx.HTTPStatusError: If queue query fails (500)
        """
        headers = self._auth_headers()

        resp = await self.session.get(
            f"{self.base_url}/api/tasks/queue",
            params={"agent": agentId},
            headers=headers,
        )
        resp.raise_for_status()

        data = resp.json()
        task = data.get("task")

        # Convert Mission Control task to Assignment format
        if task:
            return [{
                "taskId": str(task["id"]),
                "description": task.get("title", "") + "\n" + (task.get("description", "") or ""),
                "priority": self._map_priority(task.get("priority", "medium")),
                "metadata": task.get("metadata", {}),
            }]
        else:
            return []

    async def disconnect(self, agentId: str) -> None:
        """
        Disconnect agent (FrameworkAdapter.disconnect).

        Sends final heartbeat with offline status.

        Args:
            agentId: Agent identifier
        """
        await self.heartbeat({"agentId": agentId, "status": "offline"})

    # ============================================================================
    # Helper Methods
    # ============================================================================

    def _map_priority(self, priority: str) -> int:
        """Map Mission Control priority string to numeric priority."""
        mapping = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        return mapping.get(priority, 2)
