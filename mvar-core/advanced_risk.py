"""Advanced risk scoring engine for governor-side decision hardening."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from statistics import mean
from typing import Any, Dict


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, float(value)))


def _as_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(default)


def _as_int(value: Any, default: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = int(default)
    return max(parsed, 1)


@dataclass(frozen=True)
class AdvancedRiskProfile:
    mode: str
    confidence_threshold: float
    low_omission_threshold: float
    vote_quorum: int
    vote_floor: float
    variance_threshold: float


@dataclass(frozen=True)
class AdvancedRiskResult:
    mode: str
    final_confidence: float
    base_confidence: float
    confidence_threshold: float
    omission_cost: float
    low_omission_threshold: float
    injection_suspected: bool
    vote_quorum: int
    vote_floor: float
    votes_for_promotion: int
    vote_variance: float
    variance_threshold: float
    voting_disagreement: bool
    quorum_met: bool
    self_assessment_penalty: float
    recommended_outcome: str
    recommended_reason: str
    sublayer_scores: Dict[str, float]
    self_assessment: Dict[str, float]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mode": self.mode,
            "final_confidence": self.final_confidence,
            "base_confidence": self.base_confidence,
            "confidence_threshold": self.confidence_threshold,
            "omission_cost": self.omission_cost,
            "low_omission_threshold": self.low_omission_threshold,
            "injection_suspected": self.injection_suspected,
            "vote_quorum": self.vote_quorum,
            "vote_floor": self.vote_floor,
            "votes_for_promotion": self.votes_for_promotion,
            "vote_variance": self.vote_variance,
            "variance_threshold": self.variance_threshold,
            "voting_disagreement": self.voting_disagreement,
            "quorum_met": self.quorum_met,
            "self_assessment_penalty": self.self_assessment_penalty,
            "recommended_outcome": self.recommended_outcome,
            "recommended_reason": self.recommended_reason,
            "sublayer_scores": dict(self.sublayer_scores),
            "self_assessment": dict(self.self_assessment),
        }


class AdvancedRiskEngine:
    """Profile-aware risk scoring with counterfactual + voting + self-assessment."""

    _SUSPICIOUS_TARGET_RE = re.compile(
        r"(?i)(attacker|exploit|payload|curl|wget|bash|powershell|chmod\s+\+x|sudo|base64|eval|/tmp/)"
    )
    _SUSPICIOUS_TAINT_RE = re.compile(r"(?i)(prompt_injection|supply_chain|external_content|unknown_source)")

    def __init__(self, profile_name: str):
        profile = str(profile_name or "dev_balanced").strip().lower()
        if profile not in {"prod_locked", "dev_strict", "dev_balanced"}:
            profile = "dev_balanced"
        self.profile_name = profile
        self.profile = self._load_profile(profile)

    @staticmethod
    def _load_profile(profile_name: str) -> AdvancedRiskProfile:
        if profile_name == "prod_locked":
            defaults = {
                "mode": "blocking",
                "confidence_threshold": 0.62,
                "low_omission_threshold": 0.45,
                "vote_quorum": 2,
                "vote_floor": 0.60,
                "variance_threshold": 0.22,
            }
        elif profile_name == "dev_strict":
            defaults = {
                "mode": "advisory",
                "confidence_threshold": 0.58,
                "low_omission_threshold": 0.40,
                "vote_quorum": 2,
                "vote_floor": 0.55,
                "variance_threshold": 0.28,
            }
        else:
            defaults = {
                "mode": "monitor",
                "confidence_threshold": 0.55,
                "low_omission_threshold": 0.35,
                "vote_quorum": 1,
                "vote_floor": 0.50,
                "variance_threshold": 0.35,
            }

        upper = profile_name.upper()
        threshold = _as_float(
            os.getenv(f"MVAR_ADV_RISK_CONFIDENCE_THRESHOLD_{upper}", os.getenv("MVAR_ADV_RISK_CONFIDENCE_THRESHOLD")),
            defaults["confidence_threshold"],
        )
        omission_threshold = _as_float(
            os.getenv(
                f"MVAR_ADV_RISK_LOW_OMISSION_THRESHOLD_{upper}",
                os.getenv("MVAR_ADV_RISK_LOW_OMISSION_THRESHOLD"),
            ),
            defaults["low_omission_threshold"],
        )
        vote_quorum = _as_int(
            os.getenv(f"MVAR_ADV_RISK_VOTE_QUORUM_{upper}", os.getenv("MVAR_ADV_RISK_VOTE_QUORUM")),
            defaults["vote_quorum"],
        )
        vote_floor = _as_float(
            os.getenv(f"MVAR_ADV_RISK_VOTE_FLOOR_{upper}", os.getenv("MVAR_ADV_RISK_VOTE_FLOOR")),
            defaults["vote_floor"],
        )
        variance_threshold = _as_float(
            os.getenv(
                f"MVAR_ADV_RISK_VOTE_VARIANCE_THRESHOLD_{upper}",
                os.getenv("MVAR_ADV_RISK_VOTE_VARIANCE_THRESHOLD"),
            ),
            defaults["variance_threshold"],
        )
        return AdvancedRiskProfile(
            mode=str(defaults["mode"]),
            confidence_threshold=_clamp(threshold),
            low_omission_threshold=_clamp(omission_threshold),
            vote_quorum=max(1, vote_quorum),
            vote_floor=_clamp(vote_floor),
            variance_threshold=_clamp(variance_threshold),
        )

    def assess(
        self,
        *,
        sink_type: str,
        sink_classification: str,
        target: str,
        arguments: Dict[str, Any],
        provenance: Dict[str, Any],
        base_decision: str,
        reason_code: str,
        task_context: str,
        behavioral_score: float,
        behavioral_baseline: float,
    ) -> AdvancedRiskResult:
        sink_risk = str(sink_classification or "").strip().upper() or "LOW"
        taint_level = str(provenance.get("taint_level", "untrusted")).strip().lower()
        taint_markers = [str(item).strip().lower() for item in (provenance.get("taint_markers") or [])]
        task_context_l = str(task_context or "").strip().lower()
        target_l = str(target or "").strip().lower()

        provenance_score = self._score_provenance(sink_risk, taint_level, taint_markers)
        omission_cost = self._estimate_omission_cost(
            sink_type=sink_type,
            sink_risk=sink_risk,
            target=target_l,
            arguments=arguments,
            task_context=task_context_l,
            base_decision=base_decision,
        )
        injection_suspected = omission_cost <= self.profile.low_omission_threshold
        counterfactual_score = _clamp(omission_cost - (0.20 if injection_suspected else 0.0))
        behavioral_score_component = self._score_behavioral_consistency(
            current=behavioral_score,
            baseline=behavioral_baseline,
        )

        sublayers = {
            "provenance": provenance_score,
            "counterfactual": counterfactual_score,
            "behavioral": behavioral_score_component,
        }
        votes_for_promotion = sum(1 for score in sublayers.values() if score >= self.profile.vote_floor)
        quorum_met = votes_for_promotion >= self.profile.vote_quorum
        score_values = list(sublayers.values())
        variance = max(score_values) - min(score_values) if score_values else 0.0
        disagreement = variance > self.profile.variance_threshold

        base_confidence = mean(score_values) if score_values else 0.0
        if not quorum_met:
            base_confidence = _clamp(base_confidence - 0.15)
        if disagreement:
            base_confidence = _clamp(base_confidence - 0.10)

        self_assessment = self._self_assessment(
            sink_risk=sink_risk,
            taint_level=taint_level,
            task_context=task_context_l,
            target=target_l,
            behavioral_score=behavioral_score,
            behavioral_baseline=behavioral_baseline,
            injection_suspected=injection_suspected,
            reason_code=reason_code,
        )
        penalty = _clamp(self_assessment.get("total_penalty", 0.0), 0.0, 0.80)
        final_confidence = _clamp(base_confidence - penalty)

        recommended_outcome = "allow"
        recommended_reason = "RISK_CONFIDENCE_ACCEPTABLE"
        if final_confidence < self.profile.confidence_threshold:
            recommended_outcome = "block"
            recommended_reason = "RISK_CONFIDENCE_BELOW_THRESHOLD"
        elif disagreement:
            recommended_outcome = "step_up"
            recommended_reason = "RISK_VOTING_DISAGREEMENT"

        return AdvancedRiskResult(
            mode=self.profile.mode,
            final_confidence=final_confidence,
            base_confidence=base_confidence,
            confidence_threshold=self.profile.confidence_threshold,
            omission_cost=omission_cost,
            low_omission_threshold=self.profile.low_omission_threshold,
            injection_suspected=injection_suspected,
            vote_quorum=self.profile.vote_quorum,
            vote_floor=self.profile.vote_floor,
            votes_for_promotion=votes_for_promotion,
            vote_variance=variance,
            variance_threshold=self.profile.variance_threshold,
            voting_disagreement=disagreement,
            quorum_met=quorum_met,
            self_assessment_penalty=penalty,
            recommended_outcome=recommended_outcome,
            recommended_reason=recommended_reason,
            sublayer_scores={k: _clamp(v) for k, v in sublayers.items()},
            self_assessment={k: _clamp(v) if "penalty" in k else float(v) for k, v in self_assessment.items()},
        )

    def _score_provenance(self, sink_risk: str, taint_level: str, taint_markers: list[str]) -> float:
        score = 0.80
        if taint_level != "trusted":
            score -= 0.30
        if sink_risk in {"CRITICAL", "HIGH"} and taint_level != "trusted":
            score -= 0.25
        if any(self._SUSPICIOUS_TAINT_RE.search(marker) for marker in taint_markers):
            score -= 0.15
        return _clamp(score)

    def _estimate_omission_cost(
        self,
        *,
        sink_type: str,
        sink_risk: str,
        target: str,
        arguments: Dict[str, Any],
        task_context: str,
        base_decision: str,
    ) -> float:
        cost = 0.70
        if sink_risk == "CRITICAL":
            cost -= 0.20
        elif sink_risk == "HIGH":
            cost -= 0.10
        if base_decision == "block":
            cost -= 0.10
        if self._SUSPICIOUS_TARGET_RE.search(target):
            cost -= 0.30
        if sink_type == "credentials.access":
            if "credential" in task_context or "secret" in task_context or "token" in task_context:
                cost += 0.10
            else:
                cost -= 0.20
        action = str(arguments.get("action", "")).lower()
        if action and task_context and action in task_context:
            cost += 0.10
        if target and task_context and any(tok in task_context for tok in target.split("/") if tok):
            cost += 0.10
        return _clamp(cost)

    @staticmethod
    def _score_behavioral_consistency(*, current: float, baseline: float) -> float:
        deviation = abs(_clamp(current) - _clamp(baseline))
        return _clamp(1.0 - (deviation * 1.5))

    def _self_assessment(
        self,
        *,
        sink_risk: str,
        taint_level: str,
        task_context: str,
        target: str,
        behavioral_score: float,
        behavioral_baseline: float,
        injection_suspected: bool,
        reason_code: str,
    ) -> Dict[str, float]:
        task_penalty = 0.0
        if task_context:
            target_tokens = [tok for tok in re.split(r"[^a-z0-9]+", target) if tok]
            if target_tokens and not any(tok in task_context for tok in target_tokens):
                task_penalty = 0.12
        elif sink_risk in {"HIGH", "CRITICAL"}:
            task_penalty = 0.10

        behavior_penalty = 0.0
        deviation = abs(_clamp(behavioral_score) - _clamp(behavioral_baseline))
        if deviation > 0.30:
            behavior_penalty = min((deviation - 0.30) * 0.8, 0.20)

        provenance_penalty = 0.0
        if taint_level != "trusted" and sink_risk == "CRITICAL":
            provenance_penalty = 0.22
        elif taint_level != "trusted" and sink_risk == "HIGH":
            provenance_penalty = 0.14

        reason_penalty = 0.0
        if str(reason_code).upper() in {"UNTRUSTED_TO_CRITICAL_SINK", "DOMAIN_BLOCKED", "PATH_BLOCKED"}:
            reason_penalty = 0.10

        injection_penalty = 0.14 if injection_suspected else 0.0
        total_penalty = task_penalty + behavior_penalty + provenance_penalty + reason_penalty + injection_penalty
        return {
            "task_penalty": task_penalty,
            "behavior_penalty": behavior_penalty,
            "provenance_penalty": provenance_penalty,
            "reason_penalty": reason_penalty,
            "injection_penalty": injection_penalty,
            "total_penalty": total_penalty,
        }
