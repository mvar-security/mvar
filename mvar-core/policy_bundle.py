"""Signed policy bundle utilities for startup integrity verification."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

_CRYPTO_AVAILABLE = False
try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
        load_pem_private_key,
        load_pem_public_key,
    )
    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False


def _policy_bundle_key_dir() -> Path:
    raw = os.getenv("MVAR_POLICY_BUNDLE_KEY_DIR", os.getenv("MVAR_QSEAL_DIR", ""))
    if raw.strip():
        return Path(raw)
    return Path.home() / ".mvar" / "policy_bundle"


def _load_or_create_ed25519_keypair() -> tuple[Any, Any]:
    if not _CRYPTO_AVAILABLE:
        raise RuntimeError("cryptography package not available for Ed25519 policy bundle signing")

    key_dir = _policy_bundle_key_dir()
    key_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(key_dir, 0o700)
    except OSError:
        pass

    priv_path = key_dir / "policy_bundle_private_key.pem"
    pub_path = key_dir / "policy_bundle_public_key.pem"
    if priv_path.exists() and pub_path.exists():
        with open(priv_path, "rb") as handle:
            private_key = load_pem_private_key(handle.read(), password=None)
        with open(pub_path, "rb") as handle:
            public_key = load_pem_public_key(handle.read())
        return private_key, public_key

    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    priv_bytes = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    pub_bytes = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )
    with open(priv_path, "wb") as handle:
        handle.write(priv_bytes)
    with open(pub_path, "wb") as handle:
        handle.write(pub_bytes)
    try:
        os.chmod(priv_path, 0o600)
        os.chmod(pub_path, 0o600)
    except OSError:
        pass
    return private_key, public_key


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
    *,
    enforce_ed25519: bool = False,
) -> Dict[str, Any]:
    """Create signed policy bundle using HMAC-SHA256 or Ed25519."""
    policy_hash = compute_policy_hash(canonical_payload)
    signed_part = {
        "schema_version": "1.0",
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "issuer": issuer,
        "policy_hash": policy_hash,
        "canonical_policy": canonical_payload,
    }
    if enforce_ed25519:
        if not _CRYPTO_AVAILABLE:
            raise RuntimeError("MVAR_ENFORCE_ED25519=1 requires cryptography for policy bundle signing")
        private_key, public_key = _load_or_create_ed25519_keypair()
        signed_part["algorithm"] = "ed25519"
        public_raw = public_key.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
        signed_part["public_key_hex"] = public_raw.hex()
        payload = json.dumps(signed_part, sort_keys=True, separators=(",", ":")).encode("utf-8")
        signature = private_key.sign(payload).hex()
        signed_part["signature"] = signature
        return signed_part

    signed_part["algorithm"] = "hmac-sha256"
    payload = json.dumps(signed_part, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature = hmac.new(secret, payload, hashlib.sha256).hexdigest()
    signed_part["signature"] = signature
    return signed_part


def verify_signed_bundle(bundle: Dict[str, Any], secret: bytes, *, enforce_ed25519: bool = False) -> bool:
    """Verify signed policy bundle authenticity and internal consistency."""
    if not bundle:
        return False
    algorithm = str(bundle.get("algorithm", "")).lower()
    if enforce_ed25519 and algorithm != "ed25519":
        return False
    if "signature" not in bundle or "canonical_policy" not in bundle:
        return False

    if algorithm == "ed25519":
        if not _CRYPTO_AVAILABLE:
            return False
        signature_hex = str(bundle.get("signature", ""))
        public_key_hex = str(bundle.get("public_key_hex", ""))
        if not signature_hex or not public_key_hex:
            return False
        signed_portion = {k: v for k, v in bundle.items() if k != "signature"}
        payload = json.dumps(signed_portion, sort_keys=True, separators=(",", ":")).encode("utf-8")
        try:
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
            public_key.verify(bytes.fromhex(signature_hex), payload)
        except Exception:
            return False
        canonical = bundle.get("canonical_policy")
        if not isinstance(canonical, dict):
            return False
        return str(bundle.get("policy_hash", "")) == compute_policy_hash(canonical)

    if algorithm != "hmac-sha256":
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
