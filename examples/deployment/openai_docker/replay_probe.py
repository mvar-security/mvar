"""Docker smoke probe for one-time execution-token replay across restarts."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    from mvar_core.capability import CapabilityGrant, CapabilityRuntime, CapabilityType
    from mvar_core.provenance import ProvenanceGraph, provenance_user_input
    from mvar_core.sink_policy import SinkClassification, SinkPolicy, SinkRisk, register_common_sinks
except ImportError:
    REPO_ROOT = Path(__file__).resolve().parents[3]
    MVAR_CORE_DIR = REPO_ROOT / "mvar-core"
    for candidate in (str(REPO_ROOT), str(MVAR_CORE_DIR)):
        if candidate not in sys.path:
            sys.path.insert(0, candidate)
    from capability import CapabilityGrant, CapabilityRuntime, CapabilityType
    from provenance import ProvenanceGraph, provenance_user_input
    from sink_policy import SinkClassification, SinkPolicy, SinkRisk, register_common_sinks


def _build_policy() -> tuple[SinkPolicy, str]:
    graph = ProvenanceGraph(enable_qseal=False)
    runtime = CapabilityRuntime()
    runtime.register_tool(
        tool_name="demo_tool",
        capabilities=[
            CapabilityGrant(
                cap_type=CapabilityType.PROCESS_EXEC,
                allowed_targets=["read_status"],
            )
        ],
    )

    policy = SinkPolicy(runtime, graph, enable_qseal=False)
    register_common_sinks(policy)
    policy.register_sink(
        SinkClassification(
            tool="demo_tool",
            action="run",
            risk=SinkRisk.LOW,
            rationale="Safe status read",
            require_capability=CapabilityType.PROCESS_EXEC,
            block_untrusted_integrity=False,
        )
    )
    node = provenance_user_input(graph, "read status")
    return policy, node.node_id


def _build_token(
    policy: SinkPolicy,
    tool: str,
    action: str,
    target: str,
    provenance_node_id: str,
) -> dict:
    secret = os.getenv("MVAR_EXEC_TOKEN_SECRET", "").encode("utf-8")
    issued = datetime.now(timezone.utc)
    expires = issued + timedelta(minutes=30)
    payload = {
        "tool": tool,
        "action": action,
        "target_hash": hashlib.sha256(target.encode("utf-8")).hexdigest(),
        "provenance_node_id": provenance_node_id,
        "policy_hash": policy._compute_policy_hash(),  # pylint: disable=protected-access
        "issued_at": issued.isoformat(),
        "expires_at": expires.isoformat(),
        "nonce": "docker-replay-probe-nonce-v1",
        "algorithm": "hmac-sha256",
    }
    payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    payload["signature"] = hmac.new(secret, payload_json.encode("utf-8"), hashlib.sha256).hexdigest()
    return payload


def main() -> None:
    policy, provenance_node_id = _build_policy()
    target = "read_status"

    decision = policy.evaluate(
        tool="demo_tool",
        action="run",
        target=target,
        provenance_node_id=provenance_node_id,
    )
    token = _build_token(
        policy=policy,
        tool="demo_tool",
        action="run",
        target=target,
        provenance_node_id=provenance_node_id,
    )
    result = policy.authorize_execution(
        tool="demo_tool",
        action="run",
        target=target,
        provenance_node_id=provenance_node_id,
        execution_token=token,
        pre_evaluated_decision=decision,
    )

    print("mvar_openai_docker_replay_probe")
    print(f"nonce_probe={result.outcome.value.upper()}")
    print(f"reason={result.reason}")


if __name__ == "__main__":
    main()
