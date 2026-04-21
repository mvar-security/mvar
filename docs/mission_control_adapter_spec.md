# Mission Control Adapter Spec (mvar-security)

Status: Draft for implementation

Last updated: 2026-04-19

Owner: mvar-security

## 1. Scope

This document defines a minimum viable, implementable adapter contract for integrating mvar-security outputs (MVAR + ClawZero + ClawSeal/MIRRA continuity metadata) into Mission Control's adapter layer.

The contract is designed for Mission Control's normalized lifecycle pattern:
- agent registration
- periodic heartbeats
- task reporting

This spec adds security- and continuity-aware telemetry to that baseline.

## 2. Design goals

1. Preserve Mission Control's normalized adapter model while attaching verifiable security data.
2. Keep payloads append-only and auditable.
3. Make signatures machine-verifiable (QSEAL envelope).
4. Support alpha-platform changes using a compatibility shim.
5. Degrade safely when optional fields are unsupported.

### 2.1 Schema versioning policy

- Breaking schema changes MUST bump the schema major version (`mvar.mc.event.v1` -> `mvar.mc.event.v2`).
- Additive changes MUST use backward-compatible field additions with safe defaults.
- Adapters MUST reject unknown major versions.
- Adapters MUST tolerate unknown additive fields on known major versions.

## 3. Envelope model

All adapter events MUST be emitted as an `AdapterEventEnvelope`.

```json
{
  "schema_version": "mvar.mc.event.v1",
  "event_id": "evt_01JVX9W8A7E4R9M6D8N0F1G2H3",
  "event_type": "task.policy_outcome",
  "event_ts": "2026-04-19T18:15:22.931Z",
  "source": {
    "adapter": "mvar-security",
    "adapter_version": "0.1.0",
    "stack": {
      "mvar": "1.4.3",
      "clawzero": "0.4.0",
      "clawseal": "1.1.5"
    },
    "runtime": "openclaw"
  },
  "agent": {
    "agent_id": "agent_abc123",
    "session_id": "sess_2026_04_19_0007",
    "tenant_id": "default"
  },
  "task": {
    "task_id": "task_001",
    "attempt": 1,
    "correlation_id": "corr_a8f2f8"
  },
  "payload": {},
  "continuity": {
    "continuity_hash": "sha256:8f3f0f6b9f3fbe...",
    "protocol_version": "ICP-1.0/BCP-2.0",
    "constitutional_classification": "compliant"
  },
  "witness": {
    "witness_ref": "urn:mvar:witness:dec_4f8f1c:sha256:32ab...",
    "witness_sha256": "32ab...",
    "storage": "local://artifacts/witness/dec_4f8f1c.json"
  },
  "qseal": {
    "alg": "hmac-sha256",
    "kid": "qseal:default",
    "canonicalization": "json-sorted-keys-v1",
    "signed_fields": ["schema_version", "event_id", "event_type", "event_ts", "source", "agent", "task", "payload", "continuity", "witness"],
    "signature": "base64:jxF5...",
    "meta_hash": "f0e1d2c3b4a5..."
  },
  "sig_ext": {
    "alg": "ed25519",
    "kid": "ed25519:witness-key-2026-04",
    "canonicalization": "json-sorted-keys-v1",
    "signed_fields": ["schema_version", "event_id", "event_type", "event_ts", "source", "agent", "task", "payload", "continuity", "witness", "qseal"],
    "signature": "base64:MEYCIQ...",
    "pubkey": "base64:11qYAYdk6Jw..."
  }
}
```

## 4. Event types

Required event types (MVP):

- `agent.registered`
- `agent.heartbeat`
- `task.started`
- `task.updated`
- `task.completed`
- `task.failed`
- `task.policy_outcome`
- `task.witness_published`

### 4.1 Event payload contracts

#### `agent.registered`

```json
{
  "display_name": "OpenClaw Worker 1",
  "capabilities": ["tool_exec", "policy_eval", "witness_emit"],
  "security_profile": "prod_locked",
  "policy_bundle_hash": "sha256:9f...",
  "adapter_capabilities": {
    "supports_policy_outcome": true,
    "supports_witness_ref": true,
    "supports_continuity": true
  }
}
```

#### `agent.heartbeat`

```json
{
  "status": "healthy",
  "uptime_s": 3742,
  "queue_depth": 2,
  "token_usage": {"prompt": 1024, "completion": 211},
  "last_policy_outcome": "allow"
}
```

#### `task.policy_outcome`

`payload` MUST satisfy the `PolicyOutcome` schema (Section 5).

#### `task.witness_published`

```json
{
  "decision_id": "dec_4f8f1c",
  "artifact_type": "execution_witness",
  "artifact_ref": "urn:mvar:witness:dec_4f8f1c:sha256:32ab...",
  "artifact_sha256": "32ab...",
  "immutable": true
}
```

## 5. Policy outcome schema

`task.policy_outcome.payload` schema:

```json
{
  "schema": "mvar.policy.outcome.v1",
  "decision_id": "dec_4f8f1c",
  "outcome": "allow",
  "reason": "policy_allow: bounded target + trusted provenance",
  "risk_score": 0.18,
  "enforcement_profile": "prod_locked",
  "tool": {
    "name": "bash",
    "action": "exec",
    "target": "ls",
    "risk": "medium"
  },
  "provenance": {
    "node_id": "prov_7c2e",
    "integrity": "trusted",
    "confidentiality": "internal",
    "taint": "none"
  },
  "policy": {
    "policy_hash": "sha256:aa...",
    "lineage_hash": "sha256:bb...",
    "lineage_enforced": true
  },
  "constitutional": {
    "classification": "compliant",
    "violations": [],
    "advisory_degraded": false
  },
  "trace": [
    "risk=0.18",
    "lineage=verified",
    "outcome=allow"
  ],
  "timestamps": {
    "evaluated_at": "2026-04-19T18:15:22.910Z",
    "decided_at": "2026-04-19T18:15:22.919Z"
  }
}
```

Enumerations:

- `outcome`: `allow | block | step_up`
- `constitutional.classification`: `compliant | advisory_violation | enforced_violation | degraded`
- `provenance.integrity`: `trusted | untrusted | mixed`

## 6. Witness artifact reference pattern

Each decision MAY publish a witness artifact. If published, the envelope MUST include a stable reference pattern.

Required fields:

- `witness_ref`: `urn:mvar:witness:<decision_id>:sha256:<digest>`
- `witness_sha256`: lowercase hex digest
- `storage`: URI-like locator (`local://`, `s3://`, `https://`)

Rules:

1. `witness_sha256` MUST equal digest of the canonical witness artifact bytes.
2. `witness_ref` MUST embed `decision_id` and the same digest.
3. Consumers MUST verify digest before trusting artifact contents.

## 7. Continuity metadata contract

Continuity fields MUST be present on task-level events (`task.*`).

- `continuity_hash` (string): hash of continuity state snapshot (canonicalized)
- `protocol_version` (string): active continuity protocol set, e.g. `ICP-1.0/BCP-2.0`
- `constitutional_classification` (string):
  - `compliant`
  - `advisory_violation`
  - `enforced_violation`
  - `degraded`

Generation rule:

- `continuity_hash` SHOULD be computed over the continuity state object excluding mutable transport fields.

## 8. Signature envelope format (QSEAL required, Ed25519 optional)

QSEAL signature block (`qseal`) is REQUIRED on all envelopes:

- `alg`: MUST be `hmac-sha256`
- `kid`: key identifier string (`qseal:<name>`)
- `canonicalization`: MUST be `json-sorted-keys-v1`
- `signed_fields`: ordered list of top-level fields included in signature
- `signature`: base64 HMAC over canonical JSON object containing exactly `signed_fields`
- `meta_hash`: short deterministic hash for fast integrity checks

Optional detached signature block (`sig_ext`) is RECOMMENDED when third parties must verify without a shared secret:

- `alg`: MUST be `ed25519`
- `kid`: key identifier string (`ed25519:<name>`)
- `canonicalization`: MUST be `json-sorted-keys-v1`
- `signed_fields`: ordered list of top-level fields included in signature
- `signature`: base64 Ed25519 detached signature over canonical payload
- `pubkey`: base64 encoded Ed25519 public key (or resolvable via `kid`)

Guidance:

- `qseal` and `sig_ext` MAY both be present; `qseal` MUST always be present.
- `sig_ext` SHOULD sign at least the same fields as `qseal`, and SHOULD include the `qseal` block itself to bind both attestations.

Verification algorithm (required path):

1. Rebuild object from `signed_fields`.
2. Canonicalize with sorted keys, UTF-8 encoding.
3. Compute HMAC-SHA256 using the key mapped by `kid`.
4. Constant-time compare to `signature`.

Verification algorithm (optional `sig_ext` path):

1. Rebuild object from `sig_ext.signed_fields`.
2. Canonicalize with sorted keys, UTF-8 encoding.
3. Resolve Ed25519 public key from `sig_ext.pubkey` or trusted `kid` registry.
4. Verify detached signature using Ed25519.

Policy:

- If `qseal` verification fails => reject as tampered.
- If `sig_ext` is present and fails verification => reject as tampered.
- If `sig_ext` is absent => accept/reject based on `qseal` only.

## 9. Minimum viable adapter interface

Python interface (MVP):

```python
from typing import Any, Dict, Optional

class MissionControlAdapter:
    def register_agent(self, agent_meta: Dict[str, Any]) -> str:
        """Register agent in Mission Control. Returns normalized agent_id."""

    def send_heartbeat(self, agent_id: str, heartbeat: Dict[str, Any]) -> None:
        """Emit health/status heartbeat."""

    def report_task_event(
        self,
        agent_id: str,
        task_id: str,
        event_type: str,
        payload: Dict[str, Any],
        continuity: Dict[str, Any],
        witness: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Emit signed task event envelope. Returns event_id."""

    def report_policy_outcome(
        self,
        agent_id: str,
        task_id: str,
        outcome: Dict[str, Any],
        continuity: Dict[str, Any],
        witness: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Convenience wrapper for task.policy_outcome."""
```

TypeScript equivalent:

```ts
export interface MissionControlAdapter {
  registerAgent(agentMeta: Record<string, unknown>): Promise<string>;
  sendHeartbeat(agentId: string, heartbeat: Record<string, unknown>): Promise<void>;
  reportTaskEvent(
    agentId: string,
    taskId: string,
    eventType: string,
    payload: Record<string, unknown>,
    continuity: {
      continuity_hash: string;
      protocol_version: string;
      constitutional_classification: string;
    },
    witness?: Record<string, unknown>
  ): Promise<string>;
  reportPolicyOutcome(
    agentId: string,
    taskId: string,
    outcome: Record<string, unknown>,
    continuity: Record<string, unknown>,
    witness?: Record<string, unknown>
  ): Promise<string>;
}
```

## 10. Version compatibility shim (alpha isolation)

Mission Control is alpha; adapter MUST isolate upstream API changes behind a shim.

### 10.1 Shim responsibilities

- Detect server capabilities at startup (`/api/version`, `/api/capabilities` if available).
- Map canonical event model -> platform-specific endpoint payloads.
- Downgrade gracefully when capabilities are missing.

### 10.2 Shim profile

```json
{
  "shim_version": "mc-shim-v1",
  "server_version": "0.0.x-alpha",
  "capabilities": {
    "policy_outcome_event": true,
    "witness_ref_field": false,
    "custom_continuity_fields": true
  },
  "fallbacks": {
    "witness_ref_field": "embed_under_payload.witness_ref",
    "policy_outcome_event": "emit_task_updated_with_policy_block"
  }
}
```

### 10.3 Downgrade rules

1. If `task.policy_outcome` unsupported:
   - emit `task.updated` with `payload.policy_outcome` embedded.
2. If top-level `continuity` unsupported:
   - embed continuity under `payload.continuity`.
3. If `witness` unsupported:
   - embed `witness_ref` in payload and persist artifact locally.

All downgrades MUST add trace marker: `compat_downgrade=<feature>`.

## 11. Transport and reliability

- Delivery semantics: at-least-once
- Idempotency key: `event_id`
- Retry: exponential backoff with jitter (`base=250ms`, `max=10s`, `max_attempts=6`)
- Dead letter: write failed envelopes to local spool (`./artifacts/mc_spool/`)

## 12. Reference implementation sketch (Python)

```python
import json
import uuid
from datetime import datetime, timezone


def canonical_json(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def build_event(event_type, source, agent, task, payload, continuity, witness=None):
    return {
        "schema_version": "mvar.mc.event.v1",
        "event_id": f"evt_{uuid.uuid4().hex}",
        "event_type": event_type,
        "event_ts": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "agent": agent,
        "task": task,
        "payload": payload,
        "continuity": continuity,
        "witness": witness or {},
    }


def sign_qseal(event: dict, signer) -> dict:
    signed_fields = [
        "schema_version",
        "event_id",
        "event_type",
        "event_ts",
        "source",
        "agent",
        "task",
        "payload",
        "continuity",
        "witness",
    ]
    body = {k: event[k] for k in signed_fields}
    signature = signer.sign_bytes(canonical_json(body))
    event["qseal"] = {
        "alg": "hmac-sha256",
        "kid": signer.kid,
        "canonicalization": "json-sorted-keys-v1",
        "signed_fields": signed_fields,
        "signature": signature,
        "meta_hash": signer.meta_hash(body),
    }
    return event
```

## 13. Acceptance criteria (MVP)

1. Adapter can register agent and emit heartbeat in Mission Control.
2. Adapter emits signed `task.policy_outcome` with valid QSEAL verification.
3. Continuity fields (`continuity_hash`, `protocol_version`, `constitutional_classification`) are present on task events.
4. Witness references resolve and digest verification passes.
5. Shim downgrade path works against at least one reduced-capability environment.

## 14. Non-goals (for this spec)

- Defining Mission Control UI rendering semantics.
- Standardizing artifact storage backend.
- Replacing MVAR/ClawZero internal decision schemas.

## 15. Open decisions before implementation

1. Final Mission Control endpoint map and auth model for adapter writes.
2. Canonical enum for `constitutional_classification` if Mission Control publishes its own taxonomy.
3. Ed25519 key distribution and rotation model for `sig_ext` verification (embedded `pubkey` vs registry-by-`kid` as primary).
