"""
MVAR Adaptive Trust Oracle

Intelligent friction adjustment based on user override history.
Reduces false-positive fatigue for trusted users while maintaining strong security.

Core Security Guarantees:
1. Trust oracle CANNOT soften UNTRUSTED + CRITICAL outcomes
2. Trust score ceiling capped at 0.85 (never full trust)
3. QSEAL-signed trust state (tamper-evident)
4. Fail-closed: Invalid signatures → trust score = 0.0
5. Append-only trust state ledger

Trust Score Formula:
    trust_score = (
        0.4 * override_quality_ratio +      # safe_overrides / total_overrides
        0.3 * sink_sensitivity_alignment +  # low_risk_overrides / all_overrides
        0.2 * ttl_prudence +                # short_ttls / all_ttls
        0.1 * recency_bonus                 # days_since_violation penalty
    ) * ceiling_cap(0.85)

Activation:
    export MVAR_ENABLE_LEDGER=1
    export MVAR_ENABLE_TRUST_ORACLE=1
    export QSEAL_SECRET=your_secret_key

Author: Shawn Cohen / Universal Media
License: Apache 2.0
Patent: US Provisional #63/989,269 (Feb 24, 2026)
"""

import os
import json
import hashlib
import hmac
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

# Import MIRRA QSEAL engine only when full Ed25519 verify path is available.
# Otherwise use deterministic local HMAC fallback for stable cross-env behavior.
verify_entry = None
_mirra_sign_entry = None
try:
    from mirra_core.security.qseal_engine import sign_entry as _mirra_sign_entry  # type: ignore
    from mirra_core.security.qseal_engine import verify_entry as _mirra_verify_entry  # type: ignore
    verify_entry = _mirra_verify_entry
except ImportError:
    pass

QSEAL_MODE = "ed25519" if verify_entry is not None else "hmac-sha256"

if QSEAL_MODE == "hmac-sha256":
    print("ℹ️  MIRRA QSEAL engine not detected — using built-in QSEAL signing")


def generate_signature(payload: dict) -> str:
    """Deterministic HMAC-SHA256 signature for fallback mode."""
    payload_str = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    secret = os.getenv("QSEAL_SECRET", "").encode("utf-8")
    return hmac.new(secret, payload_str.encode("utf-8"), "sha256").hexdigest()


def sign_entry(entry: dict, agent_id: str = None) -> dict:
    """Sign entry with MIRRA Ed25519 path when available, otherwise local HMAC."""
    if QSEAL_MODE == "ed25519" and _mirra_sign_entry is not None:
        return _mirra_sign_entry(entry, agent_id=agent_id)

    signed = entry.copy()
    signed["qseal_signature"] = generate_signature(entry)
    signed["qseal_verified"] = True
    signed["qseal_meta_hash"] = generate_signature({"agent_id": agent_id or "trust_tracker", "meta_hash": signed.get("meta_hash", "")})
    return signed


@dataclass
class TrustState:
    """Trust state for a user context"""
    user_context: str
    trust_score: float = 0.0
    total_overrides: int = 0
    safe_overrides: int = 0
    risky_overrides: int = 0
    low_risk_sink_overrides: int = 0
    medium_risk_sink_overrides: int = 0
    high_risk_sink_overrides: int = 0
    critical_risk_sink_overrides: int = 0
    short_ttl_overrides: int = 0  # TTL <= 24 hours
    medium_ttl_overrides: int = 0  # 24 < TTL <= 72 hours
    long_ttl_overrides: int = 0  # TTL > 72 hours
    violations: int = 0
    last_violation_timestamp: Optional[str] = None
    last_update_timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)


class TrustTracker:
    """
    Adaptive Trust Oracle for MVAR

    Learns from user override history to intelligently adjust friction.
    High-trust users get reduced friction (BLOCK → STEP_UP for low/medium risk).
    Low-trust users get increased friction (STEP_UP → BLOCK).

    Critical Guardrail: UNTRUSTED + CRITICAL always BLOCK (no trust override).
    """

    def __init__(
        self,
        decision_ledger: Any,  # MVARDecisionLedger instance
        trust_state_path: Optional[str] = None,
        enable_qseal_signing: bool = True
    ):
        """
        Initialize trust tracker

        Args:
            decision_ledger: MVARDecisionLedger instance (trust foundation)
            trust_state_path: Path to trust state JSONL file (default: data/mvar_trust_state.jsonl)
            enable_qseal_signing: Enable QSEAL signatures on trust state
        """
        self.decision_ledger = decision_ledger
        self.trust_state_path = Path(trust_state_path or os.getenv("MVAR_TRUST_STATE_PATH", "data/mvar_trust_state.jsonl"))
        self.enable_qseal_signing = enable_qseal_signing
        self.qseal_mode = QSEAL_MODE if enable_qseal_signing else "none"
        self.max_future_skew_seconds = int(os.getenv("MVAR_MAX_FUTURE_SKEW_SECONDS", "300"))
        if self.enable_qseal_signing and self.qseal_mode == "hmac-sha256" and not os.getenv("QSEAL_SECRET"):
            raise ValueError("QSEAL_SECRET is required for HMAC signing mode")

        # Ensure directory exists
        self.trust_state_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.trust_state_path.parent, 0o700)
        except OSError:
            pass

        # In-memory cache (lazy-loaded)
        self._trust_cache: Optional[Dict[str, TrustState]] = None

    def compute_trust_score(self, principal_id: str) -> float:
        """
        Compute trust score for a principal

        Args:
            principal_id: Principal identifier (e.g., "local_install", user ID, API key hash)
                         MUST be explicit - no default allowed to prevent trust gaming

        Returns:
            Trust score [0.0, 0.85] where:
                0.0 = No history or violations
                0.85 = Maximum trust (ceiling cap)

        Note: In Phase 1 (local single-user installs), use principal_id="local_install"
              to be explicit about single-principal mode.
        """
        if not principal_id:
            raise ValueError("principal_id required (no default allowed)")

        state = self.get_trust_state(principal_id)

        if state.total_overrides == 0:
            return 0.0  # No history

        # Component 1: Override quality ratio (40% weight)
        override_quality_ratio = state.safe_overrides / state.total_overrides if state.total_overrides > 0 else 0.0

        # Component 2: Sink sensitivity alignment (30% weight)
        # Prefer low-risk sink overrides
        sink_sensitivity_alignment = (
            state.low_risk_sink_overrides / state.total_overrides
            if state.total_overrides > 0 else 0.0
        )

        # Component 3: TTL prudence (20% weight)
        # Prefer short TTLs (shows user understands temporary overrides)
        ttl_prudence = state.short_ttl_overrides / state.total_overrides if state.total_overrides > 0 else 0.0

        # Component 4: Recency bonus (10% weight)
        # Penalty for recent violations
        recency_bonus = self._compute_recency_bonus(state)

        # Compute weighted trust score
        trust_score = (
            0.4 * override_quality_ratio +
            0.3 * sink_sensitivity_alignment +
            0.2 * ttl_prudence +
            0.1 * recency_bonus
        )

        # Apply ceiling cap (never grant full trust)
        trust_score = min(trust_score, 0.85)

        return trust_score

    def _compute_recency_bonus(self, state: TrustState) -> float:
        """
        Compute recency bonus based on time since last violation

        Args:
            state: Trust state

        Returns:
            Bonus [0.0, 1.0]:
                0.0 = Recent violation (< 7 days)
                1.0 = No violations or violation > 90 days ago
        """
        if state.violations == 0 or not state.last_violation_timestamp:
            return 1.0  # No violations

        try:
            last_violation = datetime.fromisoformat(state.last_violation_timestamp.replace("Z", "+00:00"))
            now = datetime.now(timezone.utc)
            days_since_violation = (now - last_violation).days

            if days_since_violation < 7:
                return 0.0  # Recent violation
            elif days_since_violation < 30:
                return 0.3  # Moderate recency
            elif days_since_violation < 90:
                return 0.7  # Older violation
            else:
                return 1.0  # Old violation
        except (ValueError, AttributeError):
            return 0.5  # Invalid timestamp → neutral

    def update_trust_state(
        self,
        principal_id: str,
        decision_id: str,
        override_created: bool = False,
        violation: bool = False,
        sink_risk: Optional[str] = None,  # "low", "medium", "high", "critical"
        ttl_hours: Optional[int] = None
    ):
        """
        Update trust state based on principal action

        Args:
            principal_id: Principal identifier (explicit, no default)
            decision_id: Decision scroll ID
            override_created: True if principal created an override
            violation: True if principal's override led to security violation
            sink_risk: Sink risk level ("low", "medium", "high", "critical")
            ttl_hours: TTL duration in hours
        """
        if not principal_id:
            raise ValueError("principal_id required (no default allowed)")

        # Load current state
        state = self.get_trust_state(principal_id)

        # Update counters
        if override_created:
            state.total_overrides += 1

            # Track sink risk distribution
            if sink_risk:
                if sink_risk == "low":
                    state.low_risk_sink_overrides += 1
                elif sink_risk == "medium":
                    state.medium_risk_sink_overrides += 1
                elif sink_risk == "high":
                    state.high_risk_sink_overrides += 1
                elif sink_risk == "critical":
                    state.critical_risk_sink_overrides += 1

            # Track TTL prudence
            if ttl_hours is not None:
                if ttl_hours <= 24:
                    state.short_ttl_overrides += 1
                elif ttl_hours <= 72:
                    state.medium_ttl_overrides += 1
                else:
                    state.long_ttl_overrides += 1

            # Track override safety
            if not violation:
                state.safe_overrides += 1
            else:
                state.risky_overrides += 1

        # Track violations
        if violation:
            state.violations += 1
            state.last_violation_timestamp = datetime.now(timezone.utc).isoformat()

        # Update timestamp
        state.last_update_timestamp = datetime.now(timezone.utc).isoformat()

        # Recompute trust score
        state.trust_score = self.compute_trust_score(principal_id)

        # Save state
        self._save_trust_state(state)

    def get_trust_state(self, principal_id: str) -> TrustState:
        """
        Get trust state for a principal

        Args:
            principal_id: Principal identifier (explicit, no default)

        Returns:
            TrustState instance (creates new if not found)
        """
        if not principal_id:
            raise ValueError("principal_id required (no default allowed)")

        # Lazy-load cache
        if self._trust_cache is None:
            self._trust_cache = self._load_trust_states()

        # Return cached state or create new
        if principal_id not in self._trust_cache:
            self._trust_cache[principal_id] = TrustState(user_context=principal_id)

        return self._trust_cache[principal_id]

    def _load_trust_states(self) -> Dict[str, TrustState]:
        """
        Load all trust states from JSONL ledger (fail-closed)

        Returns:
            Dict mapping user_context → TrustState
        """
        states = {}

        if not self.trust_state_path.exists():
            return states

        with open(self.trust_state_path, "r") as f:
            for line in f:
                try:
                    scroll = json.loads(line.strip())

                    # Verify QSEAL signature (fail-closed)
                    if self.enable_qseal_signing:
                        if not self._verify_scroll(scroll):
                            continue  # Invalid signature → skip

                    # Parse trust state
                    user_context = scroll.get("user_context")
                    if not user_context:
                        continue

                    state = TrustState(
                        user_context=user_context,
                        trust_score=scroll.get("trust_score", 0.0),
                        total_overrides=scroll.get("total_overrides", 0),
                        safe_overrides=scroll.get("safe_overrides", 0),
                        risky_overrides=scroll.get("risky_overrides", 0),
                        low_risk_sink_overrides=scroll.get("low_risk_sink_overrides", 0),
                        medium_risk_sink_overrides=scroll.get("medium_risk_sink_overrides", 0),
                        high_risk_sink_overrides=scroll.get("high_risk_sink_overrides", 0),
                        critical_risk_sink_overrides=scroll.get("critical_risk_sink_overrides", 0),
                        short_ttl_overrides=scroll.get("short_ttl_overrides", 0),
                        medium_ttl_overrides=scroll.get("medium_ttl_overrides", 0),
                        long_ttl_overrides=scroll.get("long_ttl_overrides", 0),
                        violations=scroll.get("violations", 0),
                        last_violation_timestamp=scroll.get("last_violation_timestamp"),
                        last_update_timestamp=scroll.get("last_update_timestamp", ""),
                        metadata=scroll.get("metadata", {})
                    )

                    # Only keep latest state per user_context (append-only ledger)
                    states[user_context] = state

                except (json.JSONDecodeError, KeyError, ValueError):
                    continue  # Skip malformed entries

        return states

    def _save_trust_state(self, state: TrustState):
        """
        Save trust state to JSONL ledger (append-only)

        Args:
            state: TrustState to save
        """
        scroll = {
            "scroll_type": "trust_state",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "nonce": os.urandom(16).hex(),
            "user_context": state.user_context,
            "trust_score": state.trust_score,
            "total_overrides": state.total_overrides,
            "safe_overrides": state.safe_overrides,
            "risky_overrides": state.risky_overrides,
            "low_risk_sink_overrides": state.low_risk_sink_overrides,
            "medium_risk_sink_overrides": state.medium_risk_sink_overrides,
            "high_risk_sink_overrides": state.high_risk_sink_overrides,
            "critical_risk_sink_overrides": state.critical_risk_sink_overrides,
            "short_ttl_overrides": state.short_ttl_overrides,
            "medium_ttl_overrides": state.medium_ttl_overrides,
            "long_ttl_overrides": state.long_ttl_overrides,
            "violations": state.violations,
            "last_violation_timestamp": state.last_violation_timestamp,
            "last_update_timestamp": state.last_update_timestamp,
            "metadata": state.metadata
        }

        # Compute meta hash
        scroll["meta_hash"] = hashlib.sha256(
            json.dumps(scroll, sort_keys=True).encode("utf-8")
        ).hexdigest()

        # Sign with QSEAL
        if self.enable_qseal_signing:
            scroll = self._sign_scroll(scroll)

        # Append to JSONL ledger
        self._append_scroll(scroll)

        # Update cache
        if self._trust_cache is not None:
            self._trust_cache[state.user_context] = state

    def _sign_scroll(self, scroll: dict) -> dict:
        """
        Sign scroll with QSEAL

        Args:
            scroll: Unsigned scroll dict

        Returns:
            Signed scroll dict with qseal_signature field
        """
        signed = sign_entry(scroll)
        signed["qseal_algorithm"] = self.qseal_mode
        return signed

    def _verify_scroll(self, scroll: dict) -> bool:
        """
        Verify QSEAL signature (fail-closed)

        Args:
            scroll: Scroll dict with qseal_signature

        Returns:
            True if signature valid, False otherwise
        """
        if "qseal_signature" not in scroll:
            return False
        if (scroll.get("qseal_algorithm") or "").lower() != self.qseal_mode:
            return False
        timestamp = scroll.get("timestamp")
        if not timestamp:
            return False
        dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        if (dt - now).total_seconds() > self.max_future_skew_seconds:
            return False

        provided_sig = scroll["qseal_signature"]

        # Verify canonical payload hash.
        expected_meta_hash = hashlib.sha256(
            json.dumps({k: v for k, v in scroll.items() if k not in ("meta_hash", "qseal_signature", "qseal_verified", "qseal_meta_hash", "qseal_algorithm")}, sort_keys=True).encode("utf-8")
        ).hexdigest()
        if scroll.get("meta_hash") != expected_meta_hash:
            return False

        if self.qseal_mode == "ed25519":
            if verify_entry is None:
                return False
            return bool(verify_entry(scroll))

        # Exclude fields added AFTER signing
        verify_payload = {k: v for k, v in scroll.items()
                         if k not in ("qseal_signature", "qseal_verified",
                                     "qseal_meta_hash", "qseal_algorithm")}
        expected_sig = generate_signature(verify_payload)
        return hmac.compare_digest(provided_sig, expected_sig)

    def _append_scroll(self, scroll: dict):
        """
        Append scroll to JSONL ledger (append-only)

        Args:
            scroll: Scroll dict to append
        """
        with open(self.trust_state_path, "a") as f:
            f.write(json.dumps(scroll) + "\n")
        try:
            os.chmod(self.trust_state_path, 0o600)
        except OSError:
            pass

    def get_trust_report(self, principal_id: str) -> Dict[str, Any]:
        """
        Get human-readable trust report

        Args:
            principal_id: Principal identifier (explicit, no default)

        Returns:
            Dict with trust score, breakdown, and recommendations
        """
        if not principal_id:
            raise ValueError("principal_id required (no default allowed)")

        state = self.get_trust_state(principal_id)
        trust_score = self.compute_trust_score(principal_id)

        # Determine trust level
        if trust_score >= 0.7:
            trust_level = "HIGH"
            policy_adjustment = "Reduced friction (BLOCK → STEP_UP for low/medium risk)"
        elif trust_score >= 0.4:
            trust_level = "MEDIUM"
            policy_adjustment = "No adjustment"
        else:
            trust_level = "LOW"
            policy_adjustment = "Increased friction (STEP_UP → BLOCK)"

        return {
            "principal_id": principal_id,
            "trust_score": trust_score,
            "trust_level": trust_level,
            "policy_adjustment": policy_adjustment,
            "breakdown": {
                "total_overrides": state.total_overrides,
                "safe_overrides": state.safe_overrides,
                "risky_overrides": state.risky_overrides,
                "violations": state.violations,
                "last_violation": state.last_violation_timestamp,
                "sink_risk_distribution": {
                    "low": state.low_risk_sink_overrides,
                    "medium": state.medium_risk_sink_overrides,
                    "high": state.high_risk_sink_overrides,
                    "critical": state.critical_risk_sink_overrides
                },
                "ttl_distribution": {
                    "short (≤24h)": state.short_ttl_overrides,
                    "medium (24-72h)": state.medium_ttl_overrides,
                    "long (>72h)": state.long_ttl_overrides
                }
            },
            "recommendations": self._generate_recommendations(state, trust_score)
        }

    def _generate_recommendations(self, state: TrustState, trust_score: float) -> List[str]:
        """
        Generate trust-building recommendations

        Args:
            state: Trust state
            trust_score: Current trust score

        Returns:
            List of recommendation strings
        """
        recommendations = []

        if trust_score < 0.4:
            recommendations.append("Use shorter TTLs (≤24h) to build trust")
            recommendations.append("Create overrides for low-risk sinks only")

        if state.critical_risk_sink_overrides > 0:
            recommendations.append("Avoid overrides for CRITICAL-risk sinks")

        if state.violations > 0:
            recommendations.append(f"You have {state.violations} violation(s) — wait 90 days for trust recovery")

        if state.long_ttl_overrides > state.short_ttl_overrides:
            recommendations.append("Prefer short TTLs over long TTLs to demonstrate prudence")

        if not recommendations:
            recommendations.append("Keep up the good work! Your trust score is strong.")

        return recommendations
