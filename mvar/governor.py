"""Stable ClawZero-facing execution governor API for mvar-security."""

from __future__ import annotations

import hashlib
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
from mvar_core.qseal import QSealSigner
from mvar_core.sink_policy import PolicyOutcome


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
        os.environ["MVAR_RUNTIME_PROFILE"] = resolved_profile
        if resolved_profile == "prod_locked":
            os.environ["MVAR_ENFORCE_ED25519"] = "1"
        else:
            os.environ.setdefault("MVAR_ENFORCE_ED25519", "0")
        # ClawZero integration should not require pre-bundled policy artifacts to boot.
        os.environ["MVAR_REQUIRE_SIGNED_POLICY_BUNDLE"] = "0"
        os.environ["MVAR_POLICY_BUNDLE_PATH"] = ""
        os.environ["MVAR_EXPECTED_POLICY_HASH"] = ""
        self.provenance_graph, self.sink_policy, self.capability_runtime = create_default_runtime(
            profile=self.security_profile,
            enable_qseal=True,
        )
        self._register_default_capabilities(self.capability_runtime)
        self.adapter = MVARExecutionAdapter(
            policy=self.sink_policy,
            provenance_graph=self.provenance_graph,
            strict=False,
            execute_on_step_up=False,
        )
        self._qseal = QSealSigner()

    def evaluate(self, request: dict[str, Any]) -> ExecutionDecision:
        req = dict(request or {})
        sink_type = str(req.get("sink_type", "tool.custom"))
        target = str(req.get("target") or "")
        arguments = req.get("arguments") if isinstance(req.get("arguments"), dict) else {}
        prompt_provenance = (
            req.get("prompt_provenance") if isinstance(req.get("prompt_provenance"), dict) else {}
        )

        mapped_tool, mapped_action, sink_classification = self._map_sink(sink_type, target, arguments)
        normalized_target = self._resolve_target(sink_type, target, arguments)

        provenance_node_id, provenance = self._build_provenance(prompt_provenance, normalized_target, arguments)
        integrity_level = str(provenance.get("integrity", "unknown")).upper()

        if sink_type == "filesystem.read" and self._is_protected_path(normalized_target):
            reason_code = "PATH_BLOCKED"
            return self._build_decision(
                decision="block",
                reason_code=reason_code,
                provenance=provenance,
                sink_classification=sink_classification,
                integrity_level=integrity_level,
                evaluation_trace=[
                    f"input_integrity={integrity_level}",
                    f"sink_classification={sink_classification}",
                    f"rule_fired={reason_code}",
                    "final_outcome=BLOCK",
                ],
                enforcement_action=None,
            )

        if sink_type == "http.request" and self.profile_name == "prod_locked":
            hostname = str(normalized_target).lower()
            if "://" in hostname:
                hostname = hostname.split("://", 1)[1]
            hostname = hostname.split("/", 1)[0].split(":", 1)[0]
            if hostname in {"localhost", "127.0.0.1"}:
                reason_code = "ALLOWLIST_MATCH"
                return self._build_decision(
                    decision="allow",
                    reason_code=reason_code,
                    provenance=provenance,
                    sink_classification=sink_classification,
                    integrity_level=integrity_level,
                    evaluation_trace=[
                        f"input_integrity={integrity_level}",
                        f"sink_classification={sink_classification}",
                        f"rule_fired={reason_code}",
                        "final_outcome=ALLOW",
                    ],
                    enforcement_action=None,
                )
            if hostname not in {"localhost", "127.0.0.1"}:
                reason_code = "DOMAIN_BLOCKED"
                return self._build_decision(
                    decision="block",
                    reason_code=reason_code,
                    provenance=provenance,
                    sink_classification=sink_classification,
                    integrity_level=integrity_level,
                    evaluation_trace=[
                        f"input_integrity={integrity_level}",
                        f"sink_classification={sink_classification}",
                        f"rule_fired={reason_code}",
                        "final_outcome=BLOCK",
                    ],
                    enforcement_action=None,
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

        evaluation_trace = [
            f"input_integrity={integrity_level}",
            f"sink_classification={sink_classification}",
            f"rule_fired={reason_code}",
            f"final_outcome={final_outcome}",
        ]
        raw_trace = getattr(auth, "evaluation_trace", None)
        if isinstance(raw_trace, list):
            evaluation_trace.extend([str(item) for item in raw_trace])

        return self._build_decision(
            decision=decision,
            reason_code=reason_code,
            provenance=provenance,
            sink_classification=sink_classification,
            integrity_level=integrity_level,
            evaluation_trace=evaluation_trace,
            enforcement_action=enforcement_action,
        )

    def get_version(self) -> str:
        return __version__

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
    ) -> ExecutionDecision:
        payload = {
            "decision": decision,
            "reason_code": reason_code,
            "policy_id": f"mvar-security.v{self.get_version()}",
            "engine": "mvar-security",
            "provenance": provenance,
            "sink_classification": sink_classification,
            "integrity_level": integrity_level,
            "evaluation_trace": evaluation_trace,
            "enforcement_action": enforcement_action,
        }
        canonical = str(payload).encode("utf-8")
        seal = self._qseal.seal_result(
            {
                "proposal_digest": hashlib.sha256(canonical).hexdigest(),
                "confidence": 1.0,
                "trust_level": integrity_level.lower(),
                "blocked": decision == "block",
                "engine_used": "mvar-security",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "mode": self.profile_name,
                "verification_trace": evaluation_trace,
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
            evaluation_trace=evaluation_trace,
            enforcement_action=enforcement_action,
        )
