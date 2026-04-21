"""
Mission Control Adapter Type Definitions
==========================================

TypedDict definitions matching Mission Control's TypeScript interfaces.
Based on verified API routes in mission-control/src/app/api/.

Reference:
- POST /api/agents/register
- POST /api/agents/[id]/heartbeat
- POST /api/tasks
- GET /api/tasks
"""

from typing import TypedDict, Optional, Literal


# Agent Registration (POST /api/agents/register)
class AgentRegistration(TypedDict, total=False):
    """Agent self-registration payload."""
    name: str  # Required: /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}$/
    role: Literal["coder", "reviewer", "tester", "devops", "researcher", "assistant", "agent"]
    capabilities: list[str]
    framework: str  # e.g. "mvar"


class AgentRegistrationResponse(TypedDict):
    """Response from POST /api/agents/register."""
    agent: dict
    registered: bool
    message: str


# Heartbeat (POST /api/agents/[id]/heartbeat)
class TokenUsage(TypedDict, total=False):
    """Token usage reporting in heartbeat."""
    model: str
    inputTokens: int
    outputTokens: int
    taskId: Optional[int]


class HeartbeatPayload(TypedDict, total=False):
    """Heartbeat payload with optional fields."""
    connection_id: Optional[str]
    status: Optional[str]
    last_activity: Optional[str]
    token_usage: Optional[TokenUsage]
    mvar_metrics: Optional[dict]  # MVAR-specific metrics


class WorkItem(TypedDict):
    """Work item returned in heartbeat response."""
    type: str  # "mentions" | "assigned_tasks" | "notifications" | "urgent_activities"
    count: int
    items: list[dict]


class HeartbeatResponse(TypedDict):
    """Response from POST /api/agents/[id]/heartbeat."""
    status: Literal["WORK_ITEMS_FOUND", "HEARTBEAT_OK"]
    agent: str
    checked_at: int
    work_items: list[WorkItem]
    total_items: int
    token_recorded: bool


# Task Creation (POST /api/tasks)
class TaskCreatePayload(TypedDict, total=False):
    """Task creation payload."""
    title: str  # Required
    description: Optional[str]
    status: Optional[str]
    priority: Literal["critical", "high", "medium", "low"]
    project_id: Optional[int]
    assigned_to: Optional[str]
    due_date: Optional[int]
    estimated_hours: Optional[float]
    actual_hours: Optional[float]
    outcome: Optional[Literal["success", "failure"]]
    error_message: Optional[str]
    resolution: Optional[str]
    feedback_rating: Optional[int]
    feedback_notes: Optional[str]
    retry_count: Optional[int]
    completed_at: Optional[int]
    tags: list[str]
    metadata: dict  # MVAR policy outcome + QSEAL signature goes here


class Task(TypedDict):
    """Task object returned from API."""
    id: int
    title: str
    description: Optional[str]
    status: str
    priority: str
    assigned_to: Optional[str]
    created_at: int
    updated_at: int
    metadata: dict
    tags: list[str]
    ticket_ref: Optional[str]


class TaskCreateResponse(TypedDict):
    """Response from POST /api/tasks."""
    task: Task


class TaskListResponse(TypedDict):
    """Response from GET /api/tasks."""
    tasks: list[Task]
    total: int
    page: int
    limit: int


# MVAR-specific types
class MVARPolicyOutcome(TypedDict):
    """MVAR execution decision embedded in task metadata."""
    decision: Literal["allow", "block", "audit"]
    violations: list[dict]
    continuity_hash: Optional[str]
    protocol_version: str
    timestamp: int


class MVARTaskMetadata(TypedDict):
    """Task metadata structure for MVAR adapter."""
    mvar_policy_outcome: MVARPolicyOutcome
    qseal_signature: str
    qseal_meta_hash: str
    clawzero_witness: Optional[dict]


# FrameworkAdapter Interface Types
class TaskReport(TypedDict, total=False):
    """Task completion report (FrameworkAdapter.reportTask)."""
    taskId: str
    agentId: str
    progress: int  # 0-100
    status: str  # "done" | "failed" | "in_progress"
    output: Optional[dict]  # Contains policy_outcome and witness


class Assignment(TypedDict, total=False):
    """Task assignment from queue (FrameworkAdapter.getAssignments)."""
    taskId: str
    description: str
    priority: Optional[int]  # 0=critical, 1=high, 2=medium, 3=low
    metadata: Optional[dict]
