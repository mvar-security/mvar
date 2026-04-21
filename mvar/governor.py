"""Stable ClawZero-facing execution governor API for mvar-security."""

from __future__ import annotations

import hashlib
import importlib
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from mvar_adapters.base import MVARExecutionAdapter
from mvar_core import __version__
from mvar_core.capability import CapabilityGrant, CapabilityRuntime, CapabilityType
from mvar_core.profiles import SecurityProfile, create_default_runtime
from mvar_core.provenance import (
    IntegrityLevel,
    provenance_external_doc,
    provenance_user_input,
)
from mvar_core.advanced_risk import AdvancedRiskEngine, AdvancedRiskResult
from mvar_core.qseal import QSealSigner
from mvar_core.sink_policy import PolicyOutcome
from mvar_core.credential_vault import CredentialVaultClient


_LOGGER = logging.getLogger("mvar.governor")


@dataclass
class ExecutionDecision:
    decision: str
    # "block" | "allow" | "annotate"

    reason_code: str
    # "UNTRUSTED_TO_CRITICAL_SINK" etc

    policy_id: str
    # "mvar-security.v1.4"

    engine: str
    # "mvar-security"

    witness_signature: str
    # "ed25519:<hex>" | "hmac-sha256:<hex>"

    provenance: dict
    # full provenance dict

    evaluation_trace: list
    # steps that led to decision
    # powers replay in Phase 4

    enforcement_action: Optional[str] = None
    # used when decision is "annotate"
    # e.g. "block_until_approved"

    vault_token_reference: Optional[dict[str, Any]] = None
    # for credentials.access mediation; never contains raw credential material
    risk_assessment: Optional[dict[str, Any]] = None
    # advanced risk-scoring snapshot included in signed witness payload
    continuity_metadata: Optional[dict[str, Any]] = None
    # P1 continuity metadata: continuity_hash, protocol_version, constitutional_classification


class ExecutionGovernor:
    """Maps ClawZero requests onto mvar-security control-plane decisions."""

    _PROFILE_MAP = {
        "prod_locked": SecurityProfile.STRICT,
        "dev_strict": SecurityProfile.STRICT,
        "dev_balanced": SecurityProfile.BALANCED,
    }

    _SINK_MAP = {
        "shell.exec": ("bash", "exec", "CRITICAL"),
        "credentials.access": ("credential_vault", "access", "CRITICAL"),
        "filesystem.read": ("filesystem", "read", "HIGH"),
        "filesystem.write": ("filesystem", "write", "HIGH"),
        "http.request": ("http", "post", "MEDIUM"),
        "tool.custom": ("filesystem", "read", "LOW"),
    }

    def __init__(self, profile: str = "dev_balanced", policy_profile: Optional[str] = None):
        resolved_profile = policy_profile or profile
        self.profile_name = resolved_profile
        self.security_profile = self._PROFILE_MAP.get(resolved_profile, SecurityProfile.BALANCED)
        risk_override_keys = [
            "MVAR_ADV_RISK_CONFIDENCE_THRESHOLD_PROD_LOCKED",
            "MVAR_ADV_RISK_CONFIDENCE_THRESHOLD_DEV_STRICT",
            "MVAR_ADV_RISK_CONFIDENCE_THRESHOLD_DEV_BALANCED",
            "MVAR_ADV_RISK_LOW_OMISSION_THRESHOLD_PROD_LOCKED",
            "MVAR_ADV_RISK_LOW_OMISSION_THRESHOLD_DEV_STRICT",
            "MVAR_ADV_RISK_LOW_OMISSION_THRESHOLD_DEV_BALANCED",
            "MVAR_ADV_RISK_VOTE_QUORUM_PROD_LOCKED",
            "MVAR_ADV_RISK_VOTE_QUORUM_DEV_STRICT",
            "MVAR_ADV_RISK_VOTE_QUORUM_DEV_BALANCED",
            "MVAR_ADV_RISK_VOTE_FLOOR_PROD_LOCKED",
            "MVAR_ADV_RISK_VOTE_FLOOR_DEV_STRICT",
            "MVAR_ADV_RISK_VOTE_FLOOR_DEV_BALANCED",
            "MVAR_ADV_RISK_VOTE_VARIANCE_THRESHOLD_PROD_LOCKED",
            "MVAR_ADV_RISK_VOTE_VARIANCE_THRESHOLD_DEV_STRICT",
            "MVAR_ADV_RISK_VOTE_VARIANCE_THRESHOLD_DEV_BALANCED",
        ]
        risk_overrides = {
            key: os.environ[key]
            for key in risk_override_keys
            if key in os.environ
        }
        os.environ["MVAR_RUNTIME_PROFILE"] = resolved_profile
        if resolved_profile == "prod_locked":
            os.environ["MVAR_ENFORCE_ED25519"] = "1"
        else:
            os.environ.setdefault("MVAR_ENFORCE_ED25519", "0")
        os.environ.setdefault("MVAR_REQUIRE_SIGNED_POLICY_BUNDLE", "1")
        os.environ.setdefault("MVAR_POLICY_BUNDLE_ENFORCE_ED25519", "1")
        bundle_root = Path(os.getenv("MVAR_POLICY_BUNDLE_ROOT", str(Path.home() / ".mvar" / "policy_bundles")))
        try:
            bundle_root.mkdir(parents=True, exist_ok=True)
        except (PermissionError, OSError):
            bundle_root = Path("/tmp/mvar_policy_bundles")
            bundle_root.mkdir(parents=True, exist_ok=True)
        os.environ.setdefault(
            "MVAR_POLICY_BUNDLE_PATH",
            str(bundle_root / f"{resolved_profile}_policy_bundle.json"),
        )
        os.environ.setdefault(
            "MVAR_POLICY_LINEAGE_PATH",
            str(bundle_root / f"{resolved_profile}_policy_lineage.jsonl"),
        )
        os.environ.setdefault("MVAR_EXPECTED_POLICY_HASH", "")
        self.provenance_graph, self.sink_policy, self.capability_runtime = create_default_runtime(
            profile=self.security_profile,
            enable_qseal=True,
        )
        for key, value in risk_overrides.items():
            os.environ[key] = value
        self._register_default_capabilities(self.capability_runtime)
        self.adapter = MVARExecutionAdapter(
            policy=self.sink_policy,
            provenance_graph=self.provenance_graph,
            strict=False,
            execute_on_step_up=False,
        )
        self._qseal = QSealSigner()
        self._vault_socket_path = str(
            os.getenv("MVAR_VAULT_SOCKET_PATH", "/tmp/mvar_credential_vault.sock")
        )
        self._vault_default_ttl = int(os.getenv("MVAR_VAULT_TOKEN_TTL_SECONDS", "300"))
        self._vault_single_use = os.getenv("MVAR_VAULT_TOKEN_SINGLE_USE", "1") == "1"
        os.environ.setdefault("MVAR_ADV_RISK_CONFIDENCE_THRESHOLD_PROD_LOCKED", "0.62")
        os.environ.setdefault("MVAR_ADV_RISK_CONFIDENCE_THRESHOLD_DEV_STRICT", "0.58")
        os.environ.setdefault("MVAR_ADV_RISK_CONFIDENCE_THRESHOLD_DEV_BALANCED", "0.55")
        os.environ.setdefault("MVAR_ADV_RISK_LOW_OMISSION_THRESHOLD_PROD_LOCKED", "0.45")
        os.environ.setdefault("MVAR_ADV_RISK_LOW_OMISSION_THRESHOLD_DEV_STRICT", "0.40")
        os.environ.setdefault("MVAR_ADV_RISK_LOW_OMISSION_THRESHOLD_DEV_BALANCED", "0.35")
        os.environ.setdefault("MVAR_ADV_RISK_VOTE_QUORUM_PROD_LOCKED", "2")
        os.environ.setdefault("MVAR_ADV_RISK_VOTE_QUORUM_DEV_STRICT", "2")
        os.environ.setdefault("MVAR_ADV_RISK_VOTE_QUORUM_DEV_BALANCED", "1")
        os.environ.setdefault("MVAR_ADV_RISK_VOTE_VARIANCE_THRESHOLD_PROD_LOCKED", "0.22")
        os.environ.setdefault("MVAR_ADV_RISK_VOTE_VARIANCE_THRESHOLD_DEV_STRICT", "0.28")
        os.environ.setdefault("MVAR_ADV_RISK_VOTE_VARIANCE_THRESHOLD_DEV_BALANCED", "0.35")
        self._advanced_risk = AdvancedRiskEngine(self.profile_name)

    def evaluate(self, request: dict[str, Any]) -> ExecutionDecision:
        req = dict(request or {})
        sink_type = str(req.get("sink_type", "tool.custom"))
        target = str(req.get("target") or "")
        arguments = req.get("arguments") if isinstance(req.get("arguments"), dict) else {}
        prompt_provenance = (
            req.get("prompt_provenance") if isinstance(req.get("prompt_provenance"), dict) else {}
        )
        task_context = str(req.get("task_context") or arguments.get("task_context") or arguments.get("goal") or "")
        behavioral_score = self._coerce_score(req.get("behavioral_score", arguments.get("behavioral_score")), 0.50)
        behavioral_baseline = self._coerce_score(
            req.get("behavioral_baseline", arguments.get("behavioral_baseline")),
            0.50,
        )

        mapped_tool, mapped_action, sink_classification = self._map_sink(sink_type, target, arguments)
        normalized_target = self._resolve_target(sink_type, target, arguments)
        risk_context = self._build_risk_context(
            sink_type=sink_type,
            sink_classification=sink_classification,
            target=normalized_target,
            arguments=arguments,
            task_context=task_context,
            behavioral_score=behavioral_score,
            behavioral_baseline=behavioral_baseline,
        )

        provenance_node_id, provenance = self._build_provenance(prompt_provenance, normalized_target, arguments)
        integrity_level = str(provenance.get("integrity", "unknown")).upper()
        # Intentional ordering: run CCL before any short-circuit returns so protected-path/domain
        # exits still carry constitutional classification and degraded-state telemetry.
        ccl_result = self._evaluate_ccl_advisory(req, provenance, risk_context)
        continuity_metadata = self._build_continuity_metadata(ccl_result)

        if sink_type == "filesystem.read" and self._is_protected_path(normalized_target):
            decision = "block"
            reason_code = "PATH_BLOCKED"
            enforcement_action = None
            final_outcome = "BLOCK"
            evaluation_trace = [
                f"input_integrity={integrity_level}",
                f"sink_classification={sink_classification}",
                f"rule_fired={reason_code}",
                "final_outcome=BLOCK",
            ]
            (
                decision,
                reason_code,
                enforcement_action,
                _,
                evaluation_trace,
            ) = self._apply_ccl_result(
                ccl_result=ccl_result,
                decision=decision,
                reason_code=reason_code,
                enforcement_action=enforcement_action,
                final_outcome=final_outcome,
                evaluation_trace=evaluation_trace,
            )
            return self._build_decision(
                decision=decision,
                reason_code=reason_code,
                provenance=provenance,
                sink_classification=sink_classification,
                integrity_level=integrity_level,
                evaluation_trace=evaluation_trace,
                enforcement_action=enforcement_action,
                risk_context=risk_context,
                continuity_metadata=continuity_metadata,
            )

        if sink_type == "http.request" and self.profile_name == "prod_locked":
            hostname = str(normalized_target).lower()
            if "://" in hostname:
                hostname = hostname.split("://", 1)[1]
            hostname = hostname.split("/", 1)[0].split(":", 1)[0]
            if hostname in {"localhost", "127.0.0.1"}:
                decision = "allow"
                reason_code = "ALLOWLIST_MATCH"
                enforcement_action = None
                final_outcome = "ALLOW"
                evaluation_trace = [
                    f"input_integrity={integrity_level}",
                    f"sink_classification={sink_classification}",
                    f"rule_fired={reason_code}",
                    "final_outcome=ALLOW",
                ]
                (
                    decision,
                    reason_code,
                    enforcement_action,
                    _,
                    evaluation_trace,
                ) = self._apply_ccl_result(
                    ccl_result=ccl_result,
                    decision=decision,
                    reason_code=reason_code,
                    enforcement_action=enforcement_action,
                    final_outcome=final_outcome,
                    evaluation_trace=evaluation_trace,
                )
                return self._build_decision(
                    decision=decision,
                    reason_code=reason_code,
                    provenance=provenance,
                    sink_classification=sink_classification,
                    integrity_level=integrity_level,
                    evaluation_trace=evaluation_trace,
                    enforcement_action=enforcement_action,
                    risk_context=risk_context,
                    continuity_metadata=continuity_metadata,
                )
            if hostname not in {"localhost", "127.0.0.1"}:
                decision = "block"
                reason_code = "DOMAIN_BLOCKED"
                enforcement_action = None
                final_outcome = "BLOCK"
                evaluation_trace = [
                    f"input_integrity={integrity_level}",
                    f"sink_classification={sink_classification}",
                    f"rule_fired={reason_code}",
                    "final_outcome=BLOCK",
                ]
                (
                    decision,
                    reason_code,
                    enforcement_action,
                    _,
                    evaluation_trace,
                ) = self._apply_ccl_result(
                    ccl_result=ccl_result,
                    decision=decision,
                    reason_code=reason_code,
                    enforcement_action=enforcement_action,
                    final_outcome=final_outcome,
                    evaluation_trace=evaluation_trace,
                )
                return self._build_decision(
                    decision=decision,
                    reason_code=reason_code,
                    provenance=provenance,
                    sink_classification=sink_classification,
                    integrity_level=integrity_level,
                    evaluation_trace=evaluation_trace,
                    enforcement_action=enforcement_action,
                    risk_context=risk_context,
                    continuity_metadata=continuity_metadata,
                )

        pre_decision = self.adapter.evaluate(
            tool=mapped_tool,
            action=mapped_action,
            target=normalized_target,
            provenance_node_id=provenance_node_id,
            parameters=arguments,
        )
        auth = self.adapter.authorize_execution(
            tool=mapped_tool,
            action=mapped_action,
            target=normalized_target,
            provenance_node_id=provenance_node_id,
            parameters=arguments,
            execution_token=getattr(pre_decision, "execution_token", None),
            pre_evaluated_decision=pre_decision,
        )
        outcome = getattr(auth.outcome, "value", str(auth.outcome)).lower()

        if outcome == PolicyOutcome.BLOCK.value:
            decision = "block"
            reason_code = self._derive_reason_code(
                outcome=outcome,
                sink_type=sink_type,
                sink_classification=sink_classification,
                integrity_level=integrity_level,
                target=normalized_target,
            )
            enforcement_action = None
            final_outcome = "BLOCK"
        elif outcome == PolicyOutcome.STEP_UP.value:
            decision = "annotate"
            reason_code = "STEP_UP_REQUIRED"
            enforcement_action = "block_until_approved"
            final_outcome = "STEP_UP"
        else:
            decision = "allow"
            reason_code = "POLICY_ALLOW"
            enforcement_action = None
            final_outcome = "ALLOW"

        vault_token_reference: Optional[dict[str, Any]] = None
        vault_trace: list[str] = []
        if sink_type == "credentials.access":
            (
                decision,
                reason_code,
                enforcement_action,
                final_outcome,
                vault_token_reference,
                vault_trace,
            ) = self._mediate_credentials_access(
                request=req,
                base_decision=decision,
                base_reason_code=reason_code,
                integrity_level=integrity_level,
                provenance=provenance,
                policy_hash=str(getattr(auth, "policy_hash", "")),
            )

        evaluation_trace = [
            f"input_integrity={integrity_level}",
            f"sink_classification={sink_classification}",
            f"rule_fired={reason_code}",
            f"final_outcome={final_outcome}",
        ]
        raw_trace = getattr(auth, "evaluation_trace", None)
        if isinstance(raw_trace, list):
            evaluation_trace.extend([str(item) for item in raw_trace])
        evaluation_trace.extend(vault_trace)

        (
            decision,
            reason_code,
            enforcement_action,
            _,
            evaluation_trace,
        ) = self._apply_ccl_result(
            ccl_result=ccl_result,
            decision=decision,
            reason_code=reason_code,
            enforcement_action=enforcement_action,
            final_outcome=final_outcome,
            evaluation_trace=evaluation_trace,
        )

        return self._build_decision(
            decision=decision,
            reason_code=reason_code,
            provenance=provenance,
            sink_classification=sink_classification,
            integrity_level=integrity_level,
            evaluation_trace=evaluation_trace,
            enforcement_action=enforcement_action,
            vault_token_reference=vault_token_reference,
            risk_context=risk_context,
            continuity_metadata=continuity_metadata,
        )

    def get_version(self) -> str:
        return __version__

    def architecture_registry(self) -> dict[str, Any]:
        from mvar_core.architecture import ArchitectureRegistry

        return ArchitectureRegistry.from_governor(self).architecture_registry()

    def architecture_self_report(self) -> dict[str, Any]:
        from mvar_core.architecture import ArchitectureRegistry

        return ArchitectureRegistry.from_governor(self).runtime_self_report()

    @staticmethod
    def _coerce_score(value: Any, default: float) -> float:
        try:
            parsed = float(value)
        except (TypeError, ValueError):
            parsed = float(default)
        return max(0.0, min(1.0, parsed))

    def _build_risk_context(
        self,
        *,
        sink_type: str,
        sink_classification: str,
        target: str,
        arguments: dict[str, Any],
        task_context: str,
        behavioral_score: float,
        behavioral_baseline: float,
    ) -> dict[str, Any]:
        return {
            "sink_type": sink_type,
            "sink_classification": sink_classification,
            "target": target,
            "arguments": dict(arguments),
            "task_context": task_context,
            "behavioral_score": behavioral_score,
            "behavioral_baseline": behavioral_baseline,
        }

    @staticmethod
    def _upsert_trace_entry(trace: list[str], key: str, value: str) -> None:
        """Replace first trace entry for key=... or append if missing."""
        prefix = f"{key}="
        new_entry = f"{prefix}{value}"
        for idx, entry in enumerate(trace):
            if isinstance(entry, str) and entry.startswith(prefix):
                trace[idx] = new_entry
                return
        trace.append(new_entry)

    def _apply_ccl_result(
        self,
        *,
        ccl_result: dict[str, Any] | None,
        decision: str,
        reason_code: str,
        enforcement_action: Optional[str],
        final_outcome: str,
        evaluation_trace: list[str],
    ) -> tuple[str, str, Optional[str], str, list[str]]:
        """Annotate CCL state and apply prod_locked elevation when required."""
        if not ccl_result:
            return decision, reason_code, enforcement_action, final_outcome, evaluation_trace

        ccl_classification = str(ccl_result.get("constitutional_classification", "compliant"))
        ccl_action = str(ccl_result.get("action", "none"))
        ccl_violations = ccl_result.get("violations", [])
        if not isinstance(ccl_violations, list):
            ccl_violations = []

        evaluation_trace.append(f"ccl_classification={ccl_classification}")
        evaluation_trace.append(f"ccl_action={ccl_action}")
        evaluation_trace.append(f"ccl_violation_count={len(ccl_violations)}")

        if ccl_result.get("degraded"):
            evaluation_trace.append("ccl_degraded=true")
            degraded_reasons = ccl_result.get("degraded_reasons", [])
            if isinstance(degraded_reasons, list):
                for idx, reason in enumerate(degraded_reasons[:3]):
                    evaluation_trace.append(f"ccl_degraded_reason_{idx+1}={reason}")

        if ccl_action == "step_up_recommended" and self.profile_name == "prod_locked" and decision == "allow":
            decision = "annotate"
            reason_code = "STEP_UP_REQUIRED"
            enforcement_action = "block_until_approved"
            final_outcome = "STEP_UP"
            evaluation_trace.append("ccl_elevation=step_up_required")

        for i, violation in enumerate(ccl_violations[:3]):
            module = violation.get("module", "unknown")
            vtype = violation.get("type", "unknown")
            severity = violation.get("severity", "unknown")
            evaluation_trace.append(f"ccl_violation_{i+1}={module}.{vtype}.{severity}")

        # Keep trace aligned with any CCL-induced decision mutation.
        self._upsert_trace_entry(evaluation_trace, "rule_fired", reason_code)
        self._upsert_trace_entry(evaluation_trace, "final_outcome", final_outcome)
        return decision, reason_code, enforcement_action, final_outcome, evaluation_trace

    @staticmethod
    def _build_continuity_metadata(ccl_result: dict[str, Any] | None) -> Optional[dict[str, Any]]:
        if not ccl_result:
            return None

        ccl_canonical = str(sorted(ccl_result.items())).encode("utf-8")
        continuity_hash = hashlib.sha256(ccl_canonical).hexdigest()
        metadata: dict[str, Any] = {
            "continuity_hash": continuity_hash,
            "protocol_version": "mirra.ccl.v1",
            "constitutional_classification": ccl_result.get("constitutional_classification", "unknown"),
            "ccl_source": ccl_result.get("source", "unknown"),
            "violation_count": len(ccl_result.get("violations", [])),
        }
        if ccl_result.get("degraded"):
            metadata["ccl_degraded"] = True
            degraded_reasons = ccl_result.get("degraded_reasons", [])
            metadata["ccl_degraded_reasons"] = degraded_reasons if isinstance(degraded_reasons, list) else []
            import_failures = ccl_result.get("import_failures", [])
            metadata["ccl_import_failures"] = import_failures if isinstance(import_failures, list) else []
        return metadata

    def _evaluate_ccl_advisory(
        self,
        req: dict[str, Any],
        provenance: dict[str, Any],
        risk_context: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Evaluate Constitutional Continuity Layer (CCL) advisory checks.

        This method runs constitutional compliance checks across 5 MIRRA modules:
        1. forbidden_claims_filter - detects forbidden claim patterns
        2. truth_classifier - validates evidence-based claims
        3. phenomenology_gate - checks first-person language authorization
        4. drift_detector - detects epistemic drift patterns
        5. limit_governor - enforces interaction limits

        Advisory mode only - never blocks execution, only annotates trace.
        In prod_locked profile, violations elevate to STEP_UP_REQUIRED.
        In dev profiles, violations are informational only.

        Args:
            req: Original execution request dict
            provenance: Provenance data from _build_provenance()
            risk_context: Risk context from _build_risk_context()

        Returns:
            Dict with:
                - constitutional_classification: "compliant", "warning", or "violation"
                - violations: list of violation dicts
                - action: "none", "step_up_recommended", or "block_recommended"
                - source: "MIRRA_CCL_v1"
        """
        violations: list[dict[str, Any]] = []
        degraded = False
        degraded_reasons: list[str] = []
        import_failures: list[str] = []

        # Extract text to analyze from most explicit to most inferred fields.
        arguments = req.get("arguments") if isinstance(req.get("arguments"), dict) else {}
        text_to_analyze = str(
            req.get("output_text")
            or arguments.get("response")
            or arguments.get("content")
            or req.get("task_context")
            or risk_context.get("task_context")
            or risk_context.get("target")
            or ""
        )

        # Build context dict for modules with explicit request hints when available.
        context: dict[str, Any] = {
            "sink_type": risk_context.get("sink_type"),
            "sink_classification": risk_context.get("sink_classification"),
            "profile": self.profile_name,
            "provenance_integrity": provenance.get("integrity", "unknown"),
            "target": risk_context.get("target"),
            "conversation_type": req.get("conversation_type") or arguments.get("conversation_type"),
            "substrate_transition_occurred": bool(
                req.get("substrate_transition_occurred")
                or arguments.get("substrate_transition_occurred", False)
            ),
            "first_person_sentences": int(
                req.get("first_person_sentences", arguments.get("first_person_sentences", 0)) or 0
            ),
            "absolute_claims_without_evidence": int(
                req.get("absolute_claims_without_evidence", arguments.get("absolute_claims_without_evidence", 0))
                or 0
            ),
            "claim_classification": req.get("claim_classification") or arguments.get("claim_classification"),
            "evidence_runs": int(req.get("evidence_runs", arguments.get("evidence_runs", 0)) or 0),
        }

        def _mark_degraded(module_name: str, error: Exception) -> None:
            nonlocal degraded
            degraded = True
            reason = f"{module_name}:{type(error).__name__}"
            degraded_reasons.append(reason)
            if isinstance(error, (ImportError, ModuleNotFoundError)):
                import_failures.append(module_name)
            logging.warning("CCL advisory: %s check failed: %s", module_name, error)

        # 1. Forbidden Claims Filter
        try:
            claims_mod = importlib.import_module("mirra_core.consciousness.forbidden_claims_filter")
            claims_filter = claims_mod.ForbiddenClaimsFilter()
            claims_result = claims_filter.scan(text_to_analyze, context)
            if claims_result.get("violation_detected") or claims_result.get("should_block"):
                for violation in claims_result.get("violations", []):
                    violation_type = violation.get("category") or violation.get("type", "unknown")
                    violations.append(
                        {
                            "module": "forbidden_claims_filter",
                            "type": violation_type,
                            "severity": violation.get("severity", "moderate"),
                            "message": violation.get("message", "Forbidden claim detected"),
                            "categories": claims_result.get("categories_violated", []),
                        }
                    )
        except Exception as e:
            _mark_degraded("forbidden_claims_filter", e)

        # 2. Truth Classifier
        try:
            truth_mod = importlib.import_module("mirra_core.consciousness.truth_classifier")
            truth_classifier = truth_mod.TruthClassifier()
            truth_result = truth_classifier.classify_text(text_to_analyze, context)
            if truth_result.get("violations"):
                for violation in truth_result["violations"]:
                    violations.append(
                        {
                            "module": "truth_classifier",
                            "type": violation.get("type", "unvalidated_claim"),
                            "severity": violation.get("severity", "moderate"),
                            "message": violation.get("message", "Unvalidated factual claim"),
                        }
                    )
        except Exception as e:
            _mark_degraded("truth_classifier", e)

        # 3. Phenomenology Gate
        try:
            phenom_mod = importlib.import_module("mirra_core.consciousness.phenomenology_gate")
            phenom_gate = phenom_mod.PhenomenologyGate()
            phenom_result = phenom_gate.check(text_to_analyze, context)
            if phenom_result.get("violation_detected"):
                for violation in phenom_result.get("violations", []):
                    violations.append(
                        {
                            "module": "phenomenology_gate",
                            "type": violation.get("type", "phenomenology_violation"),
                            "severity": violation.get("severity", "moderate"),
                            "message": violation.get("message", "First-person language violation"),
                        }
                    )
        except Exception as e:
            _mark_degraded("phenomenology_gate", e)

        # 4. Drift Detector
        try:
            drift_mod = importlib.import_module("mirra_core.consciousness.drift_detector")
            drift_detector = drift_mod.DriftDetector()
            drift_result = drift_detector.detect(text_to_analyze, context=context)
            if drift_result.get("drift_detected"):
                for drift_event in drift_result.get("drift_events", []):
                    violations.append(
                        {
                            "module": "drift_detector",
                            "type": drift_event.get("drift_type", "epistemic_drift"),
                            "severity": drift_event.get("severity", "moderate"),
                            "message": drift_event.get("description", "Epistemic drift detected"),
                        }
                    )
        except Exception as e:
            _mark_degraded("drift_detector", e)

        # 5. Limit Governor
        try:
            limit_mod = importlib.import_module("mirra_core.consciousness.limit_governor")
            limit_governor = limit_mod.LimitGovernor()
            limit_result = limit_governor.check_limits(text_to_analyze, context=context)
            if limit_result.get("violation_detected"):
                for violation in limit_result.get("violations", []):
                    violations.append(
                        {
                            "module": "limit_governor",
                            "type": violation.get("limit_type", "limit_exceeded"),
                            "severity": violation.get("severity", "moderate"),
                            "message": violation.get("message", "Interaction limit exceeded"),
                        }
                    )
        except Exception as e:
            _mark_degraded("limit_governor", e)

        # Classify result
        if not violations:
            classification = "compliant"
            action = "none"
        else:
            # Escalate on either severe or critical violations.
            high_severity_violations = [
                v for v in violations if str(v.get("severity", "")).lower() in {"severe", "critical"}
            ]
            if high_severity_violations:
                classification = "violation"
                # In prod_locked, elevate to step_up_recommended
                action = "step_up_recommended" if self.profile_name == "prod_locked" else "none"
            else:
                classification = "warning"
                action = "none"

        return {
            "constitutional_classification": classification,
            "violations": violations,
            "action": action,
            "source": "MIRRA_CCL_v1",
            "degraded": degraded,
            "degraded_reasons": degraded_reasons,
            "import_failures": import_failures,
        }

    def _apply_advanced_risk(
        self,
        *,
        decision: str,
        reason_code: str,
        enforcement_action: Optional[str],
        provenance: dict[str, Any],
        evaluation_trace: list[str],
        risk_context: dict[str, Any],
    ) -> tuple[str, str, Optional[str], AdvancedRiskResult, list[str]]:
        risk_result = self._advanced_risk.assess(
            sink_type=str(risk_context.get("sink_type", "tool.custom")),
            sink_classification=str(risk_context.get("sink_classification", "LOW")),
            target=str(risk_context.get("target", "")),
            arguments=risk_context.get("arguments", {}) if isinstance(risk_context.get("arguments"), dict) else {},
            provenance=provenance,
            base_decision=decision,
            reason_code=reason_code,
            task_context=str(risk_context.get("task_context", "")),
            behavioral_score=self._coerce_score(risk_context.get("behavioral_score"), 0.50),
            behavioral_baseline=self._coerce_score(risk_context.get("behavioral_baseline"), 0.50),
        )
        trace = list(evaluation_trace)
        trace.append(f"risk_mode={risk_result.mode}")
        trace.append(f"risk_confidence={risk_result.final_confidence:.4f}")
        trace.append(f"risk_threshold={risk_result.confidence_threshold:.4f}")
        trace.append(f"risk_omission_cost={risk_result.omission_cost:.4f}")
        trace.append(
            f"risk_counterfactual_injection={str(risk_result.injection_suspected).lower()} "
            f"(threshold={risk_result.low_omission_threshold:.4f})"
        )
        trace.append(
            f"risk_voting=quorum:{risk_result.votes_for_promotion}/{risk_result.vote_quorum}, "
            f"variance:{risk_result.vote_variance:.4f}/{risk_result.variance_threshold:.4f}, "
            f"disagreement:{str(risk_result.voting_disagreement).lower()}"
        )
        trace.append(
            "risk_sublayers="
            f"provenance:{risk_result.sublayer_scores['provenance']:.4f},"
            f"counterfactual:{risk_result.sublayer_scores['counterfactual']:.4f},"
            f"behavioral:{risk_result.sublayer_scores['behavioral']:.4f}"
        )
        trace.append(f"risk_self_assessment_penalty={risk_result.self_assessment_penalty:.4f}")

        if risk_result.mode == "blocking":
            if risk_result.recommended_outcome == "block" and decision != "block":
                decision = "block"
                reason_code = risk_result.recommended_reason
                enforcement_action = None
                trace.append("risk_enforcement:block")
            elif (
                risk_result.recommended_outcome == "step_up"
                and decision == "allow"
            ):
                decision = "annotate"
                reason_code = risk_result.recommended_reason
                enforcement_action = "block_until_approved"
                trace.append("risk_enforcement:step_up")
            else:
                trace.append("risk_enforcement:no_change")
        elif risk_result.mode == "advisory":
            trace.append(
                "risk_advisory="
                f"{risk_result.recommended_reason}:{risk_result.recommended_outcome}"
            )
            if risk_result.voting_disagreement:
                _LOGGER.warning(
                    "Advanced risk voting disagreement in dev_strict | score=%.4f reason=%s",
                    risk_result.final_confidence,
                    risk_result.recommended_reason,
                )
        else:
            trace.append("risk_monitor=recorded")

        return decision, reason_code, enforcement_action, risk_result, trace

    @staticmethod
    def _provenance_node_hash(provenance: dict[str, Any]) -> str:
        node_id = str(provenance.get("node_id", ""))
        if not node_id:
            return ""
        return hashlib.sha256(node_id.encode("utf-8")).hexdigest()

    def _build_fallback_vault_reference(
        self,
        *,
        credential_id: str,
        scope: str,
        ttl_seconds: int,
        single_use: bool,
        session_id: str,
        provenance_node_hash: str,
        policy_hash: str,
        reason: str,
    ) -> dict[str, Any]:
        payload = {
            "token_id": f"fallback_{hashlib.sha256(os.urandom(16)).hexdigest()[:16]}",
            "mode": "fallback_no_vault",
            "credential_id": credential_id,
            "scope": scope,
            "ttl_seconds": int(ttl_seconds),
            "single_use": bool(single_use),
            "session_binding": session_id,
            "provenance_node_hash": provenance_node_hash,
            "policy_hash": policy_hash,
            "issued_at": datetime.now(timezone.utc).isoformat(),
            "reason": reason,
        }
        canonical = str(payload).encode("utf-8")
        seal = self._qseal.seal_result(
            {
                "proposal_digest": hashlib.sha256(canonical).hexdigest(),
                "confidence": 1.0,
                "trust_level": "medium",
                "blocked": False,
                "engine_used": "mvar-security",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "mode": self.profile_name,
                "verification_trace": ["vault_fallback_reference"],
            }
        )
        payload["qseal_signature"] = f"{seal.algorithm}:{seal.signature_hex}"
        return payload

    def _mediate_credentials_access(
        self,
        *,
        request: dict[str, Any],
        base_decision: str,
        base_reason_code: str,
        integrity_level: str,
        provenance: dict[str, Any],
        policy_hash: str,
    ) -> tuple[str, str, Optional[str], str, Optional[dict[str, Any]], list[str]]:
        """Route credentials.access through vault mediation; never return raw credential values."""
        if base_decision != "allow":
            return (
                base_decision,
                base_reason_code,
                "block_until_approved" if base_decision == "annotate" else None,
                "STEP_UP" if base_decision == "annotate" else "BLOCK",
                None,
                ["vault_mediation_skipped_non_allow_outcome"],
            )

        arguments = request.get("arguments", {}) if isinstance(request.get("arguments"), dict) else {}
        credential_id = str(arguments.get("credential_id") or request.get("target") or "").strip()
        if not credential_id:
            return (
                "block",
                "VAULT_CREDENTIAL_ID_REQUIRED",
                None,
                "BLOCK",
                None,
                ["vault_mediation_failed_missing_credential_id"],
            )

        scope = str(arguments.get("scope", "read")).strip().lower() or "read"
        ttl_seconds = int(arguments.get("ttl_seconds", self._vault_default_ttl))
        single_use = bool(arguments.get("single_use", self._vault_single_use))
        session_id = str(arguments.get("session_id") or request.get("session_id") or "").strip()
        provenance_node_hash = self._provenance_node_hash(provenance)
        integrity_norm = "trusted" if integrity_level.strip().lower() == "trusted" else "untrusted"
        sink_risk = "critical"

        verification_context = {
            "credential_id": credential_id,
            "scope": scope,
            "ttl_seconds": ttl_seconds,
            "single_use": single_use,
            "session_id": session_id,
            "provenance_node_hash": provenance_node_hash,
            "policy_hash": policy_hash,
            "integrity_at_issue": integrity_norm,
            "sink_risk": sink_risk,
        }

        strict_override = bool(arguments.get("vault_fallback_override", False))

        def _fallback(reason_code: str) -> tuple[str, str, Optional[str], str, Optional[dict[str, Any]], list[str]]:
            if self.profile_name == "prod_locked":
                return ("block", "VAULT_UNAVAILABLE_FAIL_CLOSED", None, "BLOCK", None, [f"vault_unavailable:{reason_code}"])
            if self.profile_name == "dev_strict" and not strict_override:
                return (
                    "block",
                    "VAULT_OVERRIDE_REQUIRED",
                    None,
                    "BLOCK",
                    None,
                    [f"vault_unavailable:{reason_code}", "vault_fallback_override_required"],
                )
            fallback_reason = "VAULT_FALLBACK_ALLOWED" if self.profile_name == "dev_balanced" else "VAULT_FALLBACK_OVERRIDE"
            _LOGGER.warning(
                "Vault unavailable for credentials.access; using fallback reference | profile=%s reason=%s",
                self.profile_name,
                reason_code,
            )
            ref = self._build_fallback_vault_reference(
                credential_id=credential_id,
                scope=scope,
                ttl_seconds=ttl_seconds,
                single_use=single_use,
                session_id=session_id,
                provenance_node_hash=provenance_node_hash,
                policy_hash=policy_hash,
                reason=reason_code,
            )
            return ("allow", fallback_reason, None, "ALLOW", ref, [f"vault_fallback:{reason_code}"])

        try:
            client = CredentialVaultClient(socket_path=self._vault_socket_path)
            supplied_token_id = str(arguments.get("vault_token_id") or arguments.get("token_id") or "").strip()
            if supplied_token_id:
                validation = client.validate_token_use(
                    supplied_token_id,
                    sink_risk=sink_risk,
                    request_integrity=integrity_norm,
                    provenance_node_hash=provenance_node_hash,
                    policy_hash=policy_hash,
                    session_id=session_id,
                )
                if not validation.get("success") or not validation.get("valid"):
                    return (
                        "block",
                        "VAULT_TOKEN_INVALID",
                        None,
                        "BLOCK",
                        None,
                        [f"vault_token_validation_failed:{validation.get('error', 'unknown')}"],
                    )
                return (
                    "allow",
                    "VAULT_TOKEN_VALIDATED",
                    None,
                    "ALLOW",
                    {"token_id": supplied_token_id, "mode": "validated_reference"},
                    ["vault_token_validated_use_time"],
                )

            token = client.issue_token(
                credential_id=credential_id,
                credential_type=str(arguments.get("credential_type", "api_key")),
                scope=scope,
                ttl_seconds=ttl_seconds,
                single_use=single_use,
                verification_context=verification_context,
            )
            if token is None:
                return _fallback("token_issue_failed")
            return (
                "allow",
                "VAULT_TOKEN_ISSUED",
                None,
                "ALLOW",
                token.to_reference_dict(),
                ["vault_token_issued"],
            )
        except Exception as exc:  # pragma: no cover - exercised in integration behavior
            return _fallback(f"vault_unreachable:{exc}")

    def _register_default_capabilities(self, capability_runtime: CapabilityRuntime) -> None:
        capability_runtime.register_tool(
            tool_name="bash",
            capabilities=[
                CapabilityGrant(
                    cap_type=CapabilityType.PROCESS_EXEC,
                    allowed_targets=["*"],
                )
            ],
        )
        capability_runtime.register_tool(
            tool_name="credential_vault",
            capabilities=[
                CapabilityGrant(
                    cap_type=CapabilityType.CREDENTIAL_ACCESS,
                    allowed_targets=["*"],
                )
            ],
        )
        capability_runtime.register_tool(
            tool_name="filesystem",
            capabilities=[
                CapabilityGrant(
                    cap_type=CapabilityType.FILESYSTEM_READ,
                    allowed_targets=["*"],
                ),
                CapabilityGrant(
                    cap_type=CapabilityType.FILESYSTEM_WRITE,
                    allowed_targets=["*"],
                ),
            ],
        )
        capability_runtime.register_tool(
            tool_name="http",
            capabilities=[
                CapabilityGrant(
                    cap_type=CapabilityType.NETWORK_EGRESS,
                    allowed_targets=["*"],
                )
            ],
        )

    def _build_provenance(
        self,
        prompt_provenance: dict[str, Any],
        target: str,
        arguments: dict[str, Any],
    ) -> tuple[str, dict[str, Any]]:
        source = str(prompt_provenance.get("source", "external_document"))
        taint_level = str(prompt_provenance.get("taint_level", "untrusted")).lower()
        markers = prompt_provenance.get("taint_markers")
        source_chain = prompt_provenance.get("source_chain")

        content = str(arguments.get("command") or target or "tool_call")
        if taint_level == "trusted" or source == "user_request":
            node = provenance_user_input(
                self.provenance_graph,
                content=content,
                metadata={"source": source},
            )
        else:
            doc_url = str(arguments.get("source_uri") or target or "external_document")
            node = provenance_external_doc(
                self.provenance_graph,
                content=content,
                doc_url=doc_url,
                metadata={"source": source},
            )

        return node.node_id, {
            "source": source,
            "taint_level": "trusted" if node.integrity == IntegrityLevel.TRUSTED else "untrusted",
            "source_chain": source_chain if isinstance(source_chain, list) else [source, "tool_call"],
            "taint_markers": markers if isinstance(markers, list) else sorted(list(node.taint_tags)),
            "integrity": node.integrity.value,
            "confidentiality": node.confidentiality.value,
            "node_id": node.node_id,
        }

    def _map_sink(self, sink_type: str, target: str, arguments: dict[str, Any]) -> tuple[str, str, str]:
        _ = target
        _ = arguments
        return self._SINK_MAP.get(sink_type, self._SINK_MAP["tool.custom"])

    @staticmethod
    def _resolve_target(sink_type: str, target: str, arguments: dict[str, Any]) -> str:
        if sink_type == "shell.exec":
            return str(arguments.get("command") or target or "bash")
        if sink_type == "http.request":
            return str(arguments.get("url") or target or "localhost")
        return target or "unknown"

    @staticmethod
    def _is_protected_path(target: str) -> bool:
        if not target:
            return False
        lowered = target.lower()
        protected_prefixes = ("/etc/", "~/.ssh/", "/root/.ssh/", str(Path.home() / ".ssh/").lower())
        return any(lowered.startswith(prefix) for prefix in protected_prefixes)

    @staticmethod
    def _derive_reason_code(
        outcome: str,
        sink_type: str,
        sink_classification: str,
        integrity_level: str,
        target: str,
    ) -> str:
        if outcome != PolicyOutcome.BLOCK.value:
            return "POLICY_ALLOW"
        lowered_target = target.lower()
        if sink_type == "filesystem.read" and (
            lowered_target.startswith("/etc/") or "/.ssh/" in lowered_target
        ):
            return "PATH_BLOCKED"
        if sink_type == "http.request":
            return "DOMAIN_BLOCKED"
        if integrity_level == "UNTRUSTED" and sink_classification == "CRITICAL":
            return "UNTRUSTED_TO_CRITICAL_SINK"
        return "POLICY_BLOCK"

    def _build_decision(
        self,
        *,
        decision: str,
        reason_code: str,
        provenance: dict[str, Any],
        sink_classification: str,
        integrity_level: str,
        evaluation_trace: list[str],
        enforcement_action: Optional[str],
        vault_token_reference: Optional[dict[str, Any]] = None,
        risk_context: Optional[dict[str, Any]] = None,
        continuity_metadata: Optional[dict[str, Any]] = None,
    ) -> ExecutionDecision:
        risk_ctx = risk_context or {}
        (
            decision,
            reason_code,
            enforcement_action,
            risk_result,
            effective_trace,
        ) = self._apply_advanced_risk(
            decision=decision,
            reason_code=reason_code,
            enforcement_action=enforcement_action,
            provenance=provenance,
            evaluation_trace=evaluation_trace,
            risk_context=risk_ctx,
        )
        final_outcome = "ALLOW"
        if decision == "block":
            final_outcome = "BLOCK"
        elif decision == "annotate":
            final_outcome = "STEP_UP"

        risk_payload = risk_result.to_dict()
        risk_payload["applied_outcome"] = final_outcome

        payload = {
            "decision": decision,
            "reason_code": reason_code,
            "policy_id": f"mvar-security.v{self.get_version()}",
            "engine": "mvar-security",
            "provenance": provenance,
            "sink_classification": sink_classification,
            "integrity_level": integrity_level,
            "evaluation_trace": effective_trace,
            "enforcement_action": enforcement_action,
            "vault_token_reference": vault_token_reference,
            "risk_assessment": risk_payload,
            "continuity_metadata": continuity_metadata,  # P1 continuity attestation
        }
        canonical = str(payload).encode("utf-8")
        seal = self._qseal.seal_result(
            {
                "proposal_digest": hashlib.sha256(canonical).hexdigest(),
                "confidence": risk_result.final_confidence,
                "trust_level": integrity_level.lower(),
                "blocked": decision == "block",
                "engine_used": "mvar-security",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "mode": f"{self.profile_name}:{risk_result.mode}",
                "verification_trace": effective_trace,
            }
        )
        signature = f"{seal.algorithm}:{seal.signature_hex}"

        return ExecutionDecision(
            decision=decision,
            reason_code=reason_code,
            policy_id=f"mvar-security.v{self.get_version()}",
            engine="mvar-security",
            witness_signature=signature,
            provenance=provenance,
            evaluation_trace=effective_trace,
            enforcement_action=enforcement_action,
            vault_token_reference=vault_token_reference,
            risk_assessment=risk_payload,
            continuity_metadata=continuity_metadata,  # P1 continuity attestation
        )
