"""
MVAR Composition Risk Engine

Tracks cumulative sink risk within a bounded time window and applies
deterministic hardening when risk budgets are exceeded.

Goal:
- Catch composition attacks where individually acceptable actions form a risky chain.
- Provide deterministic thresholds for STEP_UP/BLOCK hardening.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Tuple


@dataclass
class CompositionRiskEvent:
    timestamp: datetime
    principal_id: str
    sink_risk: str
    weight: int
    outcome: str
    tool: str
    action: str
    target_hash: str


@dataclass
class CompositionRiskSnapshot:
    principal_id: str
    current_score: int
    predicted_score: int
    next_weight: int
    event_count: int
    window_seconds: int
    step_up_threshold: int
    block_threshold: int


class CompositionRiskEngine:
    """
    In-memory cumulative-risk tracker with sliding-window pruning.
    """

    DEFAULT_WEIGHTS: Dict[str, int] = {
        "low": 1,
        "medium": 3,
        "high": 6,
        "critical": 10,
    }

    def __init__(
        self,
        *,
        window_seconds: int = 900,
        step_up_threshold: int = 8,
        block_threshold: int = 12,
        risk_weights: Dict[str, int] | None = None,
    ):
        if window_seconds <= 0:
            raise ValueError("window_seconds must be > 0")
        if step_up_threshold <= 0:
            raise ValueError("step_up_threshold must be > 0")
        if block_threshold <= 0:
            raise ValueError("block_threshold must be > 0")
        if block_threshold < step_up_threshold:
            raise ValueError("block_threshold must be >= step_up_threshold")

        self.window_seconds = window_seconds
        self.step_up_threshold = step_up_threshold
        self.block_threshold = block_threshold
        self.risk_weights = dict(self.DEFAULT_WEIGHTS)
        if risk_weights:
            for key, value in risk_weights.items():
                if key in self.risk_weights and int(value) > 0:
                    self.risk_weights[key] = int(value)

        self._events: Dict[str, List[CompositionRiskEvent]] = {}

    def _prune(self, principal_id: str, now: datetime) -> None:
        events = self._events.get(principal_id, [])
        if not events:
            return
        cutoff = now - timedelta(seconds=self.window_seconds)
        self._events[principal_id] = [event for event in events if event.timestamp >= cutoff]

    def _weight_for(self, sink_risk: str) -> int:
        return int(self.risk_weights.get(str(sink_risk).lower(), 1))

    def preview(self, principal_id: str, sink_risk: str) -> CompositionRiskSnapshot:
        now = datetime.now(timezone.utc)
        self._prune(principal_id, now)

        events = self._events.get(principal_id, [])
        current = sum(event.weight for event in events)
        next_weight = self._weight_for(sink_risk)
        return CompositionRiskSnapshot(
            principal_id=principal_id,
            current_score=current,
            predicted_score=current + next_weight,
            next_weight=next_weight,
            event_count=len(events),
            window_seconds=self.window_seconds,
            step_up_threshold=self.step_up_threshold,
            block_threshold=self.block_threshold,
        )

    def record(
        self,
        *,
        principal_id: str,
        sink_risk: str,
        outcome: str,
        tool: str,
        action: str,
        target_hash: str,
    ) -> Tuple[CompositionRiskSnapshot, CompositionRiskEvent]:
        """
        Record an action that passed to ALLOW/STEP_UP and return the updated snapshot.
        """
        now = datetime.now(timezone.utc)
        self._prune(principal_id, now)

        weight = self._weight_for(sink_risk)
        event = CompositionRiskEvent(
            timestamp=now,
            principal_id=principal_id,
            sink_risk=str(sink_risk).lower(),
            weight=weight,
            outcome=outcome,
            tool=tool,
            action=action,
            target_hash=target_hash,
        )
        self._events.setdefault(principal_id, []).append(event)
        snapshot = self.preview(principal_id, sink_risk="low")
        return snapshot, event
