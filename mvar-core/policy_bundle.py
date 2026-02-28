"""Signed policy bundle utilities for startup integrity verification."""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any, Dict, List


def canonicalize_sinks(sinks: List[Dict[str, Any]], fail_closed: bool) -> Dict[str, Any]:
    """Build canonical policy payload used for deterministic hashing/signing."""
    ordered = sorted(
        sinks,
        key=lambda item: (str(item.get("tool", "")), str(item.get("action", ""))),
    )
    return {
        "fail_closed": bool(fail_closed),
        "sinks": ordered,
    }


def compute_policy_hash(canonical_payload: Dict[str, Any]) -> str:
    serialized = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def build_signed_bundle(
    canonical_payload: Dict[str, Any],
    secret: bytes,
    issuer: str = "mvar_policy_bundle",
) -> Dict[str, Any]:
    """Create signed policy bundle using HMAC-SHA256."""
    policy_hash = compute_policy_hash(canonical_payload)
    signed_part = {
        "schema_version": "1.0",
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "issuer": issuer,
        "algorithm": "hmac-sha256",
        "policy_hash": policy_hash,
        "canonical_policy": canonical_payload,
    }
    payload = json.dumps(signed_part, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature = hmac.new(secret, payload, hashlib.sha256).hexdigest()
    signed_part["signature"] = signature
    return signed_part


def verify_signed_bundle(bundle: Dict[str, Any], secret: bytes) -> bool:
    """Verify signed policy bundle authenticity and internal consistency."""
    if not bundle or bundle.get("algorithm") != "hmac-sha256":
        return False
    if "signature" not in bundle or "canonical_policy" not in bundle:
        return False
    signed_portion = {k: v for k, v in bundle.items() if k != "signature"}
    payload = json.dumps(signed_portion, sort_keys=True, separators=(",", ":")).encode("utf-8")
    expected = hmac.new(secret, payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(str(bundle.get("signature", "")), expected):
        return False
    canonical = bundle.get("canonical_policy")
    if not isinstance(canonical, dict):
        return False
    return str(bundle.get("policy_hash", "")) == compute_policy_hash(canonical)
