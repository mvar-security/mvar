"""
Credential Vault Service

Provides isolated credential storage with:
- QSEAL-signed token generation (Ed25519)
- TTL-based expiration (default 5 minutes)
- Revocation API triggered by anomaly score detection
- Unix domain socket IPC for network namespace isolation

Architecture:
    Separate Python process, communicates via Unix socket only.
    Never exposes credentials to network. Tokens are time-bound and signed.
"""

import base64
import json
import hashlib
import hmac
import os
import time
import socket
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Optional, Any, Tuple
from enum import Enum

# Import QSEAL from local mvar-core package
from .qseal import QSealSigner

try:
    from cryptography.fernet import Fernet, InvalidToken
except ImportError as exc:  # pragma: no cover - enforced at runtime
    raise RuntimeError(
        "CredentialVault requires 'cryptography' for encrypted credential storage"
    ) from exc


class CredentialType(Enum):
    """Types of credentials the vault can manage"""
    API_KEY = "api_key"
    OAUTH_TOKEN = "oauth_token"
    PASSWORD = "password"
    SSH_KEY = "ssh_key"
    CERTIFICATE = "certificate"


class CredentialScope(Enum):
    """Scope restrictions for credential tokens"""
    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    ADMIN = "admin"


@dataclass
class CredentialToken:
    """
    Time-limited credential token with QSEAL signature.

    Tokens are:
    - Time-bound (default TTL 5 minutes)
    - Scope-restricted (read/write/execute/admin)
    - Cryptographically signed (QSEAL)
    - Single-use capable (optional)
    """
    token_id: str
    credential_id: str
    credential_version: int
    credential_type: CredentialType
    scope: CredentialScope
    issued_at: float  # Unix timestamp
    expires_at: float  # Unix timestamp
    revoked: bool
    single_use: bool
    verification_context: Dict[str, Any]
    qseal_signature: Dict[str, str]

    def is_valid(self) -> bool:
        """Check if token is still valid (not expired, not revoked)"""
        if self.revoked:
            return False
        if time.time() > self.expires_at:
            return False
        return True

    def time_remaining(self) -> float:
        """Seconds until expiration"""
        return max(0, self.expires_at - time.time())

    def to_reference_dict(self) -> Dict[str, Any]:
        """Serialize safe token reference (never includes raw credential material)."""
        return {
            "token_id": self.token_id,
            "credential_id": self.credential_id,
            "credential_version": self.credential_version,
            "credential_type": self.credential_type.value,
            "scope": self.scope.value,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "revoked": self.revoked,
            "single_use": self.single_use,
            "verification_context": self.verification_context,
            "qseal_signature": self.qseal_signature,
            "is_valid": self.is_valid(),
            "time_remaining": self.time_remaining()
        }

    def to_dict(self) -> Dict[str, Any]:
        """Backward-compatible alias for reference serialization."""
        return self.to_reference_dict()


@dataclass
class CredentialRecord:
    """Durable encrypted credential record metadata."""
    credential_id: str
    encrypted_payload: str
    credential_type: str
    created_at: float
    updated_at: float
    expires_at: Optional[float]
    revoked: bool
    version: int

    def is_expired(self) -> bool:
        return self.expires_at is not None and time.time() >= self.expires_at


class CredentialVault:
    """
    Isolated credential vault service.

    Runs as separate process, communicates via Unix domain socket only.
    Provides time-limited, scope-restricted, QSEAL-signed credential tokens.

    Security properties:
    - Credentials never leave vault process unencrypted
    - Tokens have short TTL (default 5 minutes)
    - Token revocation on anomaly score detection
    - Full audit trail with QSEAL chain
    - No network exposure (Unix socket only)
    """

    def __init__(
        self,
        socket_path: str = "/tmp/mvar_credential_vault.sock",
        default_ttl_seconds: int = 300,  # 5 minutes
        enable_audit_log: bool = True,
        vault_dir: Optional[str] = None,
        require_caller_auth: bool = True,
        allowed_uids: Optional[list[int]] = None,
    ):
        self.socket_path = socket_path
        self.default_ttl_seconds = default_ttl_seconds
        self.enable_audit_log = enable_audit_log
        self.profile_name = str(os.getenv("MVAR_RUNTIME_PROFILE", "dev_balanced")).strip().lower()
        if self.profile_name not in {"prod_locked", "dev_strict", "dev_balanced"}:
            self.profile_name = "dev_balanced"

        # Initialize QSEAL signer
        self.qseal = QSealSigner()
        self._require_ed25519 = self.profile_name == "prod_locked"
        if self._require_ed25519 and self.qseal.algorithm != "ed25519":
            raise RuntimeError("CredentialVault requires Ed25519 signing in prod_locked mode")

        # Runtime/auth configuration
        self.require_caller_auth = require_caller_auth
        default_uid = os.getuid() if hasattr(os, "getuid") else 0
        if allowed_uids is None:
            self.allowed_uids = {default_uid}
        else:
            self.allowed_uids = {int(uid) for uid in allowed_uids}

        # Durable encrypted credential storage
        root_dir = Path(vault_dir or os.getenv("MVAR_VAULT_DIR", str(Path.home() / ".mvar" / "vault")))
        root_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(root_dir, 0o700)
        except OSError:
            pass
        self._vault_dir = root_dir
        self._credentials_path = self._vault_dir / "credentials.enc"
        self._credentials_key_path = self._vault_dir / "credentials.key"
        self._audit_log_path = self._vault_dir / "audit.jsonl"
        self._fernet = self._initialize_fernet()

        # Token registry: {token_id: CredentialToken}
        self.tokens: Dict[str, CredentialToken] = {}

        # Durable credential metadata (encrypted payloads are stored encrypted-at-rest)
        self.credentials: Dict[str, CredentialRecord] = self._load_credentials()

        # In-memory cache for latest audit events.
        self.audit_log: list = []
        self._audit_prev_signature = self._load_last_audit_signature()

        # Revocation triggers (anomaly score thresholds, profile-aware).
        self.psi_anomaly_threshold = float(
            os.getenv(
                "MVAR_VAULT_PSI_THRESHOLD",
                {
                    "prod_locked": "3.0",
                    "dev_strict": "4.0",
                    "dev_balanced": "5.0",
                }[self.profile_name],
            )
        )

        # Server socket
        self.server_socket: Optional[socket.socket] = None
        self.running = False

    def _initialize_fernet(self) -> Fernet:
        """Initialize durable encryption key for credential storage."""
        if self._credentials_key_path.exists():
            key = self._credentials_key_path.read_bytes()
        else:
            key = Fernet.generate_key()
            self._credentials_key_path.write_bytes(key)
            try:
                os.chmod(self._credentials_key_path, 0o600)
            except OSError:
                pass
        return Fernet(key)

    def _persist_credentials(self) -> None:
        records = {
            credential_id: {
                "credential_id": rec.credential_id,
                "encrypted_payload": rec.encrypted_payload,
                "credential_type": rec.credential_type,
                "created_at": rec.created_at,
                "updated_at": rec.updated_at,
                "expires_at": rec.expires_at,
                "revoked": rec.revoked,
                "version": rec.version,
            }
            for credential_id, rec in self.credentials.items()
        }
        plaintext = json.dumps(records, sort_keys=True, separators=(",", ":")).encode("utf-8")
        encrypted = self._fernet.encrypt(plaintext)
        temp_path = self._credentials_path.with_suffix(".tmp")
        temp_path.write_bytes(encrypted)
        try:
            os.chmod(temp_path, 0o600)
        except OSError:
            pass
        temp_path.replace(self._credentials_path)
        try:
            os.chmod(self._credentials_path, 0o600)
        except OSError:
            pass

    def _load_credentials(self) -> Dict[str, CredentialRecord]:
        if not self._credentials_path.exists():
            return {}
        try:
            encrypted = self._credentials_path.read_bytes()
            plaintext = self._fernet.decrypt(encrypted)
            payload = json.loads(plaintext.decode("utf-8"))
        except (InvalidToken, ValueError, OSError, json.JSONDecodeError):
            return {}
        records: Dict[str, CredentialRecord] = {}
        for credential_id, raw in payload.items():
            records[str(credential_id)] = CredentialRecord(
                credential_id=str(raw.get("credential_id", credential_id)),
                encrypted_payload=str(raw.get("encrypted_payload", "")),
                credential_type=str(raw.get("credential_type", CredentialType.API_KEY.value)),
                created_at=float(raw.get("created_at", time.time())),
                updated_at=float(raw.get("updated_at", time.time())),
                expires_at=(
                    float(raw["expires_at"])
                    if raw.get("expires_at") is not None
                    else None
                ),
                revoked=bool(raw.get("revoked", False)),
                version=int(raw.get("version", 1)),
            )
        return records

    def _load_last_audit_signature(self) -> Optional[str]:
        if not self._audit_log_path.exists():
            return None
        try:
            with self._audit_log_path.open("r", encoding="utf-8") as handle:
                last_line = ""
                for line in handle:
                    if line.strip():
                        last_line = line
                if not last_line:
                    return None
                parsed = json.loads(last_line)
                return str(parsed.get("qseal_signature")) or None
        except Exception:
            return None

    def start(self):
        """Start the vault server (Unix domain socket)"""
        # Remove existing socket file if present
        socket_path = Path(self.socket_path)
        if socket_path.exists():
            socket_path.unlink()

        # Create Unix domain socket
        self.server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server_socket.bind(self.socket_path)
        try:
            os.chmod(self.socket_path, 0o600)
        except OSError:
            pass
        self.server_socket.listen(5)

        self.running = True

        print(f"[CredentialVault] Started on {self.socket_path}")
        print(f"[CredentialVault] Default TTL: {self.default_ttl_seconds}s")

        # Start server loop in background thread
        server_thread = threading.Thread(target=self._server_loop, daemon=True)
        server_thread.start()

    def stop(self):
        """Stop the vault server"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()

        # Revoke all active tokens on shutdown
        for token in self.tokens.values():
            if token.is_valid():
                self._revoke_token(token.token_id, reason="vault_shutdown")

        print("[CredentialVault] Stopped")

    def _caller_identity(self, client_socket: socket.socket) -> Tuple[Optional[int], Optional[int]]:
        """Resolve Unix peer credentials (uid, gid) for caller authentication."""
        try:
            if hasattr(client_socket, "getpeereid"):
                uid, gid = client_socket.getpeereid()
                return int(uid), int(gid)
        except Exception:
            pass
        try:
            import struct

            creds = client_socket.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            _pid, uid, gid = struct.unpack("3i", creds)
            return int(uid), int(gid)
        except Exception:
            return None, None

    def _authenticate_caller(self, client_socket: socket.socket) -> bool:
        if not self.require_caller_auth:
            return True
        uid, _gid = self._caller_identity(client_socket)
        if uid is None:
            return False
        return uid in self.allowed_uids

    def _server_loop(self):
        """Main server loop - accept connections and handle requests"""
        while self.running:
            try:
                client_socket, _ = self.server_socket.accept()
                # Handle request in separate thread
                handler_thread = threading.Thread(
                    target=self._handle_request,
                    args=(client_socket,),
                    daemon=True
                )
                handler_thread.start()
            except Exception as e:
                if self.running:
                    print(f"[CredentialVault] Error in server loop: {e}")

    def _handle_request(self, client_socket: socket.socket):
        """Handle a single client request"""
        try:
            if not self._authenticate_caller(client_socket):
                response = {"success": False, "error": "caller_authentication_failed"}
                client_socket.send(json.dumps(response).encode())
                return

            # Read request (JSON-encoded)
            request_data = client_socket.recv(4096).decode()
            request = json.loads(request_data)

            action = request.get("action")

            # Route to appropriate handler
            if action == "issue_token":
                response = self._handle_issue_token(request)
            elif action == "verify_token":
                response = self._handle_verify_token(request)
            elif action == "validate_token_use":
                response = self._handle_validate_token_use(request)
            elif action == "revoke_token":
                response = self._handle_revoke_token(request)
            elif action == "create_credential":
                response = self._handle_create_credential(request)
            elif action == "rotate_credential":
                response = self._handle_rotate_credential(request)
            elif action == "revoke_credential":
                response = self._handle_revoke_credential(request)
            elif action == "check_psi_anomaly":
                response = self._handle_psi_anomaly(request)
            else:
                response = {"success": False, "error": f"Unknown action: {action}"}

            # Send response
            client_socket.send(json.dumps(response).encode())

        except Exception as e:
            error_response = {"success": False, "error": str(e)}
            client_socket.send(json.dumps(error_response).encode())
        finally:
            client_socket.close()

    def _sign_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Cryptographically sign an arbitrary payload with truthful algorithm labeling."""
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        algorithm = str(self.qseal.algorithm).lower()
        payload_hash = hashlib.sha256(canonical).hexdigest()

        if algorithm == "ed25519":
            private_key = getattr(self.qseal, "_private_key", None)
            public_key = getattr(self.qseal, "_public_key", None)
            if private_key is None or public_key is None:
                raise RuntimeError("Ed25519 signer unavailable")
            signature_hex = private_key.sign(canonical).hex()
            verified = False
            try:
                public_key.verify(bytes.fromhex(signature_hex), canonical)
                verified = True
            except Exception:
                verified = False
            return {
                "algorithm": "ed25519",
                "signature": f"ed25519:{signature_hex}",
                "verified": verified,
                "payload_hash": payload_hash,
                "public_key_hex": self.qseal.public_key_hex,
            }

        if algorithm == "hmac-sha256":
            hmac_key = getattr(self.qseal, "_hmac_key", None)
            if hmac_key is None:
                raise RuntimeError("HMAC fallback key unavailable")
            signature_hex = hmac.new(hmac_key, canonical, hashlib.sha256).hexdigest()
            return {
                "algorithm": "hmac-sha256",
                "signature": f"hmac-sha256:{signature_hex}",
                "verified": True,
                "payload_hash": payload_hash,
                "public_key_hex": self.qseal.public_key_hex,
            }

        raise RuntimeError(f"Unsupported signing algorithm: {algorithm}")

    def _credential_record(self, credential_id: str) -> Optional[CredentialRecord]:
        record = self.credentials.get(str(credential_id))
        if record is None:
            return None
        if record.is_expired():
            record.revoked = True
            self._persist_credentials()
        if record.revoked:
            return None
        return record

    def _handle_create_credential(self, request: Dict[str, Any]) -> Dict[str, Any]:
        credential_id = str(request.get("credential_id", "")).strip()
        encrypted_credential = str(request.get("encrypted_credential", "")).strip()
        if not credential_id or not encrypted_credential:
            return {"success": False, "error": "credential_id and encrypted_credential are required"}
        created = self.add_credential(
            credential_id=credential_id,
            encrypted_credential=encrypted_credential,
            credential_type=str(request.get("credential_type", CredentialType.API_KEY.value)),
            ttl_seconds=request.get("ttl_seconds"),
        )
        return {"success": True, "credential": created}

    def _handle_rotate_credential(self, request: Dict[str, Any]) -> Dict[str, Any]:
        credential_id = str(request.get("credential_id", "")).strip()
        encrypted_credential = str(request.get("encrypted_credential", "")).strip()
        if not credential_id or not encrypted_credential:
            return {"success": False, "error": "credential_id and encrypted_credential are required"}
        rotated = self.rotate_credential(credential_id, encrypted_credential)
        if rotated is None:
            return {"success": False, "error": f"Credential {credential_id} not found"}
        return {"success": True, "credential": rotated}

    def _handle_revoke_credential(self, request: Dict[str, Any]) -> Dict[str, Any]:
        credential_id = str(request.get("credential_id", "")).strip()
        reason = str(request.get("reason", "manual_credential_revocation"))
        if not credential_id:
            return {"success": False, "error": "credential_id is required"}
        return {"success": self.revoke_credential(credential_id, reason=reason)}

    def _handle_issue_token(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Issue a new credential token reference (never raw credential material)."""
        credential_id = str(request.get("credential_id", "")).strip()
        credential_type = CredentialType(str(request.get("credential_type", "api_key")))
        scope = CredentialScope(str(request.get("scope", "read")))
        ttl_seconds = int(request.get("ttl_seconds", self.default_ttl_seconds))
        single_use = bool(request.get("single_use", False))
        verification_context = dict(request.get("verification_context", {}))

        if not credential_id:
            return {"success": False, "error": "credential_id is required"}

        record = self._credential_record(credential_id)
        if record is None:
            return {"success": False, "error": f"Credential {credential_id} unavailable"}

        token_id = self._generate_token_id(credential_id)
        now = time.time()
        token_payload = {
            "token_id": token_id,
            "credential_id": credential_id,
            "credential_version": record.version,
            "credential_type": credential_type.value,
            "scope": scope.value,
            "issued_at": now,
            "expires_at": now + ttl_seconds,
            "single_use": single_use,
            "verification_context": verification_context,
        }
        signature = self._sign_payload(token_payload)

        token = CredentialToken(
            token_id=token_id,
            credential_id=credential_id,
            credential_version=record.version,
            credential_type=credential_type,
            scope=scope,
            issued_at=now,
            expires_at=now + ttl_seconds,
            revoked=False,
            single_use=single_use,
            verification_context=verification_context,
            qseal_signature=signature,
        )
        self.tokens[token_id] = token

        self._audit_log(
            "token_issued",
            {
                "token_id": token_id,
                "credential_id": credential_id,
                "credential_version": record.version,
                "scope": scope.value,
                "ttl_seconds": ttl_seconds,
                "verification_context": verification_context,
            },
        )
        return {"success": True, "token": token.to_reference_dict()}

    def _handle_verify_token(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Verify a token's validity"""
        token_id = request.get("token_id")

        if token_id not in self.tokens:
            return {"success": False, "error": "Token not found"}

        token = self.tokens[token_id]

        record = self._credential_record(token.credential_id)
        if record is None:
            return {"success": False, "valid": False, "error": "credential_revoked_or_expired"}
        if int(record.version) != int(token.credential_version):
            return {"success": False, "valid": False, "error": "credential_rotated_token_stale"}

        if token.single_use and token.is_valid():
            token.revoked = True
            self._audit_log("single_use_token_consumed", {"token_id": token_id})

        return {
            "success": True,
            "valid": token.is_valid(),
            "token": token.to_dict()
        }

    def _handle_validate_token_use(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Validate token against sink/provenance policy at use-time."""
        token_id = str(request.get("token_id", "")).strip()
        sink_risk = str(request.get("sink_risk", "")).strip().lower()
        request_integrity = str(request.get("request_integrity", "unknown")).strip().lower()
        provenance_node_hash = str(request.get("provenance_node_hash", "")).strip()
        policy_hash = str(request.get("policy_hash", "")).strip()
        session_id = str(request.get("session_id", "")).strip()

        verify = self._handle_verify_token({"token_id": token_id})
        if not verify.get("success") or not verify.get("valid"):
            return {"success": False, "valid": False, "error": verify.get("error", "token_invalid")}

        token_data = verify.get("token", {})
        context = dict(token_data.get("verification_context", {}))
        issue_integrity = str(context.get("integrity_at_issue", "unknown")).strip().lower()
        issue_sink = str(context.get("sink_risk", "")).strip().lower()

        if sink_risk == "critical":
            if issue_integrity == "untrusted" or request_integrity == "untrusted":
                self._audit_log(
                    "token_use_blocked_untrusted_critical",
                    {"token_id": token_id, "issue_integrity": issue_integrity, "request_integrity": request_integrity},
                )
                return {"success": False, "valid": False, "error": "untrusted_to_critical_sink"}

        if session_id and context.get("session_id") and str(context.get("session_id")) != session_id:
            return {"success": False, "valid": False, "error": "session_binding_mismatch"}
        if provenance_node_hash and context.get("provenance_node_hash") and str(context.get("provenance_node_hash")) != provenance_node_hash:
            return {"success": False, "valid": False, "error": "provenance_binding_mismatch"}
        if policy_hash and context.get("policy_hash") and str(context.get("policy_hash")) != policy_hash:
            return {"success": False, "valid": False, "error": "policy_binding_mismatch"}
        if issue_sink and sink_risk and issue_sink != sink_risk:
            return {"success": False, "valid": False, "error": "sink_risk_mismatch"}

        self._audit_log(
            "token_use_validated",
            {
                "token_id": token_id,
                "sink_risk": sink_risk,
                "session_id": session_id,
            },
        )
        return {"success": True, "valid": True}

    def _handle_revoke_token(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Revoke a token"""
        token_id = request.get("token_id")
        reason = request.get("reason", "manual_revocation")

        return {"success": self._revoke_token(token_id, reason)}

    def _handle_psi_anomaly(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle anomaly score detection.

        If drift exceeds threshold, revoke all active tokens for that session.
        """
        psi_current = request.get("psi_current")
        psi_baseline = request.get("psi_baseline")
        psi_sigma = request.get("psi_sigma")
        session_id = request.get("session_id")

        # Calculate anomaly score
        try:
            if psi_sigma and float(psi_sigma) > 0:
                anomaly_score = abs(float(psi_current) - float(psi_baseline)) / float(psi_sigma)
            else:
                anomaly_score = 0.0
        except (TypeError, ValueError):
            anomaly_score = 0.0

        # Check threshold
        if anomaly_score >= self.psi_anomaly_threshold:
            revoked_count = self.revoke_all_credentials(
                reason=f"psi_anomaly_detected (score={anomaly_score:.2f}σ)",
                session_id=str(session_id or ""),
            )

            self._audit_log("psi_anomaly_mass_revocation", {
                "session_id": session_id,
                "psi_current": psi_current,
                "psi_baseline": psi_baseline,
                "anomaly_score": anomaly_score,
                "tokens_revoked": revoked_count
            })

            return {
                "success": True,
                "anomaly_detected": True,
                "anomaly_score": anomaly_score,
                "tokens_revoked": revoked_count
            }
        else:
            return {
                "success": True,
                "anomaly_detected": False,
                "anomaly_score": anomaly_score
            }

    def _revoke_token(self, token_id: str, reason: str) -> bool:
        """Internal token revocation"""
        if token_id not in self.tokens:
            return False

        token = self.tokens[token_id]
        if not token.revoked:
            token.revoked = True
            self._audit_log("token_revoked", {
                "token_id": token_id,
                "reason": reason,
                "time_remaining": token.time_remaining()
            })

        return True

    def _revoke_tokens_for_credential(self, credential_id: str, reason: str) -> int:
        revoked_count = 0
        for token in self.tokens.values():
            if token.credential_id == credential_id and token.is_valid():
                if self._revoke_token(token.token_id, reason=reason):
                    revoked_count += 1
        return revoked_count

    def _generate_token_id(self, credential_id: str) -> str:
        """Generate unique token ID"""
        timestamp = str(time.time())
        nonce = hashlib.sha256(f"{credential_id}{timestamp}".encode()).hexdigest()[:16]
        return f"mvar_token_{nonce}"

    def _audit_log(self, event_type: str, details: Dict[str, Any]):
        """Write to audit log"""
        if not self.enable_audit_log:
            return

        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "details": details,
            "prev_signature": self._audit_prev_signature or "",
        }
        signature = self._sign_payload(payload)
        log_entry = {
            **payload,
            "qseal_algorithm": signature["algorithm"],
            "qseal_signature": signature["signature"],
            "qseal_verified": bool(signature["verified"]),
            "payload_hash": signature["payload_hash"],
        }

        self.audit_log.append(log_entry)
        self._audit_prev_signature = str(log_entry.get("qseal_signature") or self._audit_prev_signature or "")
        with self._audit_log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(log_entry, sort_keys=True) + "\n")
        try:
            os.chmod(self._audit_log_path, 0o600)
        except OSError:
            pass

    def add_credential(
        self,
        credential_id: str,
        encrypted_credential: str,
        credential_type: str = CredentialType.API_KEY.value,
        ttl_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Add a credential to the vault.

        Args:
            credential_id: Unique identifier for the credential
            encrypted_credential: Base64-encoded encrypted credential

        In production: credentials should be encrypted with proper key management.
        For MVP: we accept pre-encrypted credentials.
        """
        now = time.time()
        expires_at = (now + int(ttl_seconds)) if ttl_seconds is not None else None
        record = CredentialRecord(
            credential_id=credential_id,
            encrypted_payload=encrypted_credential,
            credential_type=credential_type,
            created_at=now,
            updated_at=now,
            expires_at=expires_at,
            revoked=False,
            version=1,
        )
        self.credentials[credential_id] = record
        self._persist_credentials()
        self._audit_log(
            "credential_added",
            {
                "credential_id": credential_id,
                "credential_type": credential_type,
                "expires_at": expires_at,
                "version": 1,
            },
        )
        return {
            "credential_id": credential_id,
            "credential_type": credential_type,
            "expires_at": expires_at,
            "version": 1,
        }

    def rotate_credential(self, credential_id: str, encrypted_credential: str) -> Optional[Dict[str, Any]]:
        record = self.credentials.get(credential_id)
        if record is None:
            return None
        record.encrypted_payload = encrypted_credential
        record.updated_at = time.time()
        record.version = int(record.version) + 1
        record.revoked = False
        self._persist_credentials()
        revoked_tokens = self._revoke_tokens_for_credential(
            credential_id,
            reason=f"credential_rotated_v{record.version}",
        )
        self._audit_log(
            "credential_rotated",
            {
                "credential_id": credential_id,
                "new_version": record.version,
                "revoked_tokens": revoked_tokens,
            },
        )
        return {"credential_id": credential_id, "version": record.version}

    def revoke_credential(self, credential_id: str, reason: str = "manual_credential_revocation") -> bool:
        record = self.credentials.get(credential_id)
        if record is None:
            return False
        if not record.revoked:
            record.revoked = True
            record.updated_at = time.time()
            self._persist_credentials()
        revoked_tokens = self._revoke_tokens_for_credential(credential_id, reason=reason)
        self._audit_log(
            "credential_revoked",
            {
                "credential_id": credential_id,
                "reason": reason,
                "revoked_tokens": revoked_tokens,
            },
        )
        return True

    def revoke_all_credentials(self, reason: str, session_id: str = "") -> int:
        revoked_credentials = 0
        revoked_tokens = 0
        for record in self.credentials.values():
            if not record.revoked:
                record.revoked = True
                record.updated_at = time.time()
                revoked_credentials += 1
            revoked_tokens += self._revoke_tokens_for_credential(record.credential_id, reason=reason)
        self._persist_credentials()
        self._audit_log(
            "credential_mass_revocation",
            {
                "reason": reason,
                "session_id": session_id,
                "credentials_revoked": revoked_credentials,
                "tokens_revoked": revoked_tokens,
            },
        )
        return revoked_tokens

    def get_audit_log(self) -> list:
        """Retrieve audit log"""
        if not self._audit_log_path.exists():
            return self.audit_log.copy()
        events = []
        with self._audit_log_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return events


# Client for communicating with CredentialVault
class CredentialVaultClient:
    """
    Client for communicating with CredentialVault service.

    Used by agents/adapters to request credential tokens.
    """

    def __init__(self, socket_path: str = "/tmp/mvar_credential_vault.sock"):
        self.socket_path = socket_path

    def _send_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Send request to vault and receive response"""
        client_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            client_socket.connect(self.socket_path)
            client_socket.send(json.dumps(request).encode())
            response_data = client_socket.recv(4096).decode()
            return json.loads(response_data)
        finally:
            client_socket.close()

    def issue_token(
        self,
        credential_id: str,
        credential_type: str = "api_key",
        scope: str = "read",
        ttl_seconds: int = 300,
        single_use: bool = False,
        verification_context: Optional[Dict[str, Any]] = None
    ) -> Optional[CredentialToken]:
        """Request a credential token from the vault"""
        request = {
            "action": "issue_token",
            "credential_id": credential_id,
            "credential_type": credential_type,
            "scope": scope,
            "ttl_seconds": ttl_seconds,
            "single_use": single_use,
            "verification_context": verification_context or {}
        }

        response = self._send_request(request)

        if response.get("success"):
            token_data = response["token"]
            return CredentialToken(
                token_id=token_data["token_id"],
                credential_id=token_data["credential_id"],
                credential_version=int(token_data.get("credential_version", 1)),
                credential_type=CredentialType(token_data["credential_type"]),
                scope=CredentialScope(token_data["scope"]),
                issued_at=token_data["issued_at"],
                expires_at=token_data["expires_at"],
                revoked=token_data["revoked"],
                single_use=token_data["single_use"],
                verification_context=dict(token_data.get("verification_context", {})),
                qseal_signature=token_data["qseal_signature"],
            )
        else:
            print(f"[CredentialVaultClient] Error: {response.get('error')}")
            return None

    def verify_token(self, token_id: str) -> Dict[str, Any]:
        """Verify a token's validity"""
        request = {"action": "verify_token", "token_id": token_id}
        return self._send_request(request)

    def validate_token_use(
        self,
        token_id: str,
        *,
        sink_risk: str,
        request_integrity: str,
        provenance_node_hash: str,
        policy_hash: str,
        session_id: str,
    ) -> Dict[str, Any]:
        request = {
            "action": "validate_token_use",
            "token_id": token_id,
            "sink_risk": sink_risk,
            "request_integrity": request_integrity,
            "provenance_node_hash": provenance_node_hash,
            "policy_hash": policy_hash,
            "session_id": session_id,
        }
        return self._send_request(request)

    def revoke_token(self, token_id: str, reason: str = "manual") -> bool:
        """Revoke a token"""
        request = {"action": "revoke_token", "token_id": token_id, "reason": reason}
        response = self._send_request(request)
        return response.get("success", False)

    def create_credential(
        self,
        credential_id: str,
        encrypted_credential: str,
        *,
        credential_type: str = "api_key",
        ttl_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        request: Dict[str, Any] = {
            "action": "create_credential",
            "credential_id": credential_id,
            "encrypted_credential": encrypted_credential,
            "credential_type": credential_type,
        }
        if ttl_seconds is not None:
            request["ttl_seconds"] = int(ttl_seconds)
        return self._send_request(request)

    def rotate_credential(self, credential_id: str, encrypted_credential: str) -> Dict[str, Any]:
        request = {
            "action": "rotate_credential",
            "credential_id": credential_id,
            "encrypted_credential": encrypted_credential,
        }
        return self._send_request(request)

    def revoke_credential(self, credential_id: str, reason: str = "manual_credential_revocation") -> Dict[str, Any]:
        request = {
            "action": "revoke_credential",
            "credential_id": credential_id,
            "reason": reason,
        }
        return self._send_request(request)

    def report_psi_anomaly(
        self,
        psi_current: float,
        psi_baseline: float,
        psi_sigma: float,
        session_id: str
    ) -> Dict[str, Any]:
        """Report anomaly score to vault (may trigger mass revocation)"""
        request = {
            "action": "check_psi_anomaly",
            "psi_current": psi_current,
            "psi_baseline": psi_baseline,
            "psi_sigma": psi_sigma,
            "session_id": session_id
        }
        return self._send_request(request)


if __name__ == "__main__":
    # Example usage
    print("=== MVAR Credential Vault - Example ===\n")

    # Start vault
    vault = CredentialVault()
    vault.start()

    # Add a test credential (in production: properly encrypted)
    vault.add_credential("test_api_key", "encrypted_base64_payload_here")

    # Wait for vault to be ready
    time.sleep(0.5)

    # Create client
    client = CredentialVaultClient()

    # Issue a token
    print("1. Issuing token with 10-second TTL...")
    token = client.issue_token(
        credential_id="test_api_key",
        scope="read",
        ttl_seconds=10,
        verification_context={"confidence": 0.75, "action": "read_email"}
    )

    if token:
        print(f"   Token ID: {token.token_id}")
        print(f"   Valid: {token.is_valid()}")
        print(f"   Time remaining: {token.time_remaining():.1f}s")
        print(f"   QSEAL signature: {list(token.qseal_signature.keys())}\n")

        # Verify token
        print("2. Verifying token...")
        verification = client.verify_token(token.token_id)
        print(f"   Valid: {verification.get('valid')}\n")

        # Simulate anomaly score spike
        print("3. Simulating anomaly score event (6σ deviation)...")
        anomaly_response = client.report_psi_anomaly(
            psi_current=0.95,
            psi_baseline=0.45,
            psi_sigma=0.08,  # (0.95-0.45)/0.08 = 6.25σ
            session_id="test_session"
        )
        print(f"   Anomaly detected: {anomaly_response.get('anomaly_detected')}")
        print(f"   Anomaly score: {anomaly_response.get('anomaly_score'):.2f}σ")
        print(f"   Tokens revoked: {anomaly_response.get('tokens_revoked')}\n")

        # Verify token again (should be revoked)
        print("4. Verifying token after revocation...")
        verification = client.verify_token(token.token_id)
        print(f"   Valid: {verification.get('valid')}")

    # Show audit log
    print("\n5. Audit log:")
    for entry in vault.get_audit_log():
        print(f"   [{entry['timestamp']}] {entry['event_type']}")

    # Clean up
    vault.stop()

    print("\n=== Done ===")
