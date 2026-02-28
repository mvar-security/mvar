"""
MVAR QSeal — Verification Sealing
=================================

Provides Ed25519 cryptographic signing for VerificationResult objects,
making every verification audit trail non-repudiable.

What this does:
    Each verification result can be sealed with
    an Ed25519 signature over its canonical JSON representation. The seal
    includes:
        - The proposal digest (SHA-256 of the proposal)
        - The confidence score
        - The trust level
        - The timestamp
        - The engine used
        - The verification trace (if present)

    This makes the audit trail externally verifiable: given the public key,
    anyone can confirm that a specific verification result was produced at a
    specific time with a specific confidence.

Key management:
    Keys are stored at: <project_root>/keys/qseal_signing/
        private_key.pem   — Ed25519 private key (keep secret)
        public_key.pem    — Ed25519 public key (distribute freely)

    Keys are generated automatically on first use if not present.

Usage:
    from mvar_core.qseal import QSealSigner

    signer = QSealSigner()
    seal = signer.seal_result(verification_result)
    # seal.signature_hex — the Ed25519 signature
    # seal.public_key_hex — the corresponding public key
    # seal.payload_digest — SHA-256 of the signed payload
    # seal.verified — True if signature was verified immediately after signing

    # Verify later:
    valid = signer.verify_seal(seal)
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger("mvar.qseal")

# ---------------------------------------------------------------------------
# Crypto imports (guarded — cryptography package may not be installed)
# ---------------------------------------------------------------------------

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
    logger.debug("QSeal: cryptography package available")
except ImportError:
    logger.warning(
        "QSeal: 'cryptography' package not installed. "
        "Install with: pip install cryptography. "
        "Sealing will use HMAC-SHA256 fallback."
    )

# ---------------------------------------------------------------------------
# Key directory
# ---------------------------------------------------------------------------

# Standard secure location for QSEAL keys
# Default: ~/.mvar/qseal
# Override: MVAR_QSEAL_DIR=/custom/path
_KEY_DIR = Path(os.getenv("MVAR_QSEAL_DIR", str(Path.home() / ".mvar" / "qseal")))


# ---------------------------------------------------------------------------
# QSeal dataclass
# ---------------------------------------------------------------------------


@dataclass
class QSeal:
    """
    Cryptographic seal over a VerificationResult.

    Fields:
        signature_hex     — Ed25519 signature (or HMAC-SHA256 fallback)
        public_key_hex    — Corresponding public key in hex
        payload_digest    — SHA-256 of the signed payload (for audit)
        algorithm         — "ed25519" | "hmac-sha256"
        timestamp         — ISO8601 when this seal was created
        verified          — True if immediately verified after signing
        payload_preview   — First 120 chars of signed payload (for debugging)
    """
    signature_hex: str
    public_key_hex: str
    payload_digest: str
    algorithm: str
    timestamp: str
    verified: bool
    payload_preview: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "signature_hex": self.signature_hex,
            "public_key_hex": self.public_key_hex,
            "payload_digest": self.payload_digest,
            "algorithm": self.algorithm,
            "timestamp": self.timestamp,
            "verified": self.verified,
            "payload_preview": self.payload_preview,
        }

    def __repr__(self) -> str:
        status = "VERIFIED" if self.verified else "UNVERIFIED"
        return (
            f"QSeal({self.algorithm} {status} "
            f"sig={self.signature_hex[:16]}... "
            f"digest={self.payload_digest[:16]}...)"
        )


# ---------------------------------------------------------------------------
# QSealSigner
# ---------------------------------------------------------------------------


class QSealSigner:
    """
    Produces and verifies Ed25519 seals over VerificationResult objects.

    Key lifecycle:
        - On first instantiation, generates an Ed25519 keypair and saves to
          _KEY_DIR/private_key.pem and _KEY_DIR/public_key.pem.
        - Subsequent instantiations load the existing keys.
        - Key dir is auto-created if it doesn't exist.

    Thread safety: signing is stateless after init. Safe for concurrent use.
    """

    def __init__(self, key_dir: Optional[Path] = None) -> None:
        self._key_dir = Path(key_dir) if key_dir else _KEY_DIR
        self._private_key: Optional[Any] = None
        self._public_key: Optional[Any] = None
        self._public_key_hex: str = ""
        self._algorithm = "ed25519" if _CRYPTO_AVAILABLE else "hmac-sha256"

        try:
            if _CRYPTO_AVAILABLE:
                self._init_ed25519_keys()
            else:
                self._init_hmac_fallback()
        except (PermissionError, OSError):
            # Sandbox-safe fallback when home directory is not writable.
            self._key_dir = Path("/tmp/mvar_qseal")
            if _CRYPTO_AVAILABLE:
                self._init_ed25519_keys()
            else:
                self._init_hmac_fallback()

        logger.info(
            "QSealSigner initialized | algorithm=%s | key_dir=%s",
            self._algorithm,
            self._key_dir,
        )

    # ------------------------------------------------------------------
    # Key initialization
    # ------------------------------------------------------------------

    def _init_ed25519_keys(self) -> None:
        """Load or generate Ed25519 keypair."""
        self._key_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self._key_dir, 0o700)
        except OSError:
            pass
        priv_path = self._key_dir / "private_key.pem"
        pub_path = self._key_dir / "public_key.pem"

        if priv_path.exists() and pub_path.exists():
            # Load existing keys
            with open(priv_path, "rb") as f:
                self._private_key = load_pem_private_key(f.read(), password=None)
            with open(pub_path, "rb") as f:
                self._public_key = load_pem_public_key(f.read())
            logger.debug("QSeal: loaded existing Ed25519 keypair from %s", self._key_dir)
        else:
            # Generate new keypair
            self._private_key = ed25519.Ed25519PrivateKey.generate()
            self._public_key = self._private_key.public_key()

            # Save private key
            priv_bytes = self._private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption(),
            )
            with open(priv_path, "wb") as f:
                f.write(priv_bytes)
            try:
                os.chmod(priv_path, 0o600)
            except OSError:
                pass

            # Save public key
            pub_bytes = self._public_key.public_bytes(
                encoding=Encoding.PEM,
                format=PublicFormat.SubjectPublicKeyInfo,
            )
            with open(pub_path, "wb") as f:
                f.write(pub_bytes)
            try:
                os.chmod(pub_path, 0o600)
            except OSError:
                pass

            logger.info("QSeal: generated new Ed25519 keypair at %s", self._key_dir)

        # Cache public key hex for embedding in QSeal objects
        pub_raw = self._public_key.public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw,
        )
        self._public_key_hex = pub_raw.hex()

    def _init_hmac_fallback(self) -> None:
        """Initialize HMAC-SHA256 fallback (no cryptography package)."""
        import hashlib
        import hmac as _hmac

        self._key_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self._key_dir, 0o700)
        except OSError:
            pass
        key_path = self._key_dir / "hmac_key.bin"

        if key_path.exists():
            with open(key_path, "rb") as f:
                self._hmac_key = f.read()
        else:
            self._hmac_key = os.urandom(32)
            with open(key_path, "wb") as f:
                f.write(self._hmac_key)
            try:
                os.chmod(key_path, 0o600)
            except OSError:
                pass
            logger.info("QSeal: generated HMAC-SHA256 key at %s", key_path)

        self._public_key_hex = self._hmac_key.hex()[:32] + "..."  # Partial (HMAC key is secret)
        logger.warning(
            "QSeal: using HMAC-SHA256 fallback. Install 'cryptography' for "
            "non-repudiable Ed25519 signatures."
        )

    # ------------------------------------------------------------------
    # Payload construction
    # ------------------------------------------------------------------

    @staticmethod
    def _build_payload(result_dict: Dict[str, Any]) -> bytes:
        """
        Build the canonical signing payload from a VerificationResult dict.

        Only includes the fields that are semantically meaningful for the seal:
        proposal_digest, confidence, trust_level, blocked, engine_used,
        timestamp, mode, and verification_trace.

        Stability: keys are sorted to ensure deterministic serialization.
        """
        payload = {
            "proposal_digest": result_dict.get("proposal_digest", ""),
            "confidence": result_dict.get("confidence", 0.0),
            "trust_level": result_dict.get("trust_level", ""),
            "blocked": result_dict.get("blocked", False),
            "engine_used": result_dict.get("engine_used", ""),
            "timestamp": result_dict.get("timestamp", ""),
            "mode": result_dict.get("mode", ""),
            "stub_mode": result_dict.get("stub_mode", False),
        }
        # Include trace if present (non-repudiable evidence of pipeline run)
        if result_dict.get("verification_trace") is not None:
            payload["verification_trace"] = result_dict["verification_trace"]

        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    # ------------------------------------------------------------------
    # Sealing
    # ------------------------------------------------------------------

    def seal_result(self, result_dict: Dict[str, Any]) -> QSeal:
        """
        Sign a VerificationResult dict and return a QSeal.

        Args:
            result_dict: VerificationResult.to_dict() output

        Returns:
            QSeal with signature, public key, and verification status.
        """
        payload = self._build_payload(result_dict)
        payload_digest = hashlib.sha256(payload).hexdigest()
        timestamp = datetime.now(timezone.utc).isoformat()

        if _CRYPTO_AVAILABLE and self._private_key is not None:
            # Ed25519 signing
            try:
                sig_bytes = self._private_key.sign(payload)
                sig_hex = sig_bytes.hex()
                algorithm = "ed25519"

                # Immediately verify
                verified = False
                try:
                    self._public_key.verify(sig_bytes, payload)
                    verified = True
                except Exception:
                    logger.error("QSeal: immediate verification failed — signing error")

            except Exception as exc:
                logger.error("QSeal: Ed25519 signing failed: %s", exc)
                sig_hex = "ERROR"
                algorithm = "ed25519_error"
                verified = False
        else:
            # HMAC-SHA256 fallback
            import hmac as _hmac
            mac = _hmac.new(self._hmac_key, payload, hashlib.sha256)
            sig_hex = mac.hexdigest()
            algorithm = "hmac-sha256"
            # HMAC is immediately verifiable
            mac2 = _hmac.new(self._hmac_key, payload, hashlib.sha256)
            verified = mac2.hexdigest() == sig_hex

        payload_preview = payload.decode("utf-8")[:120]

        seal = QSeal(
            signature_hex=sig_hex,
            public_key_hex=self._public_key_hex,
            payload_digest=payload_digest,
            algorithm=algorithm,
            timestamp=timestamp,
            verified=verified,
            payload_preview=payload_preview,
        )

        logger.debug(
            "QSeal.seal_result: algorithm=%s verified=%s digest=%s sig=%s...",
            algorithm,
            verified,
            payload_digest[:16],
            sig_hex[:16],
        )

        return seal

    def verify_seal(self, seal: QSeal, result_dict: Dict[str, Any]) -> bool:
        """
        Verify a QSeal against a VerificationResult dict.

        Args:
            seal: The QSeal to verify
            result_dict: The VerificationResult.to_dict() to verify against

        Returns:
            True if the seal is valid for the given result_dict.
        """
        payload = self._build_payload(result_dict)
        payload_digest = hashlib.sha256(payload).hexdigest()

        # Check digest first
        if payload_digest != seal.payload_digest:
            logger.warning("QSeal.verify_seal: payload digest mismatch — result was modified")
            return False

        if _CRYPTO_AVAILABLE and self._public_key is not None and seal.algorithm == "ed25519":
            try:
                sig_bytes = bytes.fromhex(seal.signature_hex)
                self._public_key.verify(sig_bytes, payload)
                return True
            except Exception:
                logger.warning("QSeal.verify_seal: Ed25519 signature invalid")
                return False
        elif seal.algorithm == "hmac-sha256":
            import hmac as _hmac
            mac = _hmac.new(self._hmac_key, payload, hashlib.sha256)
            return mac.hexdigest() == seal.signature_hex
        else:
            logger.warning("QSeal.verify_seal: unknown algorithm %s", seal.algorithm)
            return False

    @property
    def public_key_hex(self) -> str:
        """The public key in hex — distribute for external verification."""
        return self._public_key_hex

    @property
    def algorithm(self) -> str:
        return self._algorithm


# ---------------------------------------------------------------------------
# Module-level singleton (lazy)
# ---------------------------------------------------------------------------

_default_signer: Optional[QSealSigner] = None


def get_default_signer() -> QSealSigner:
    """Return the module-level default QSealSigner (singleton, lazy-init)."""
    global _default_signer
    if _default_signer is None:
        _default_signer = QSealSigner()
    return _default_signer
