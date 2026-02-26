"""
Credential Vault Service

Provides isolated credential storage with:
- QSEAL-signed token generation (Ed25519)
- TTL-based expiration (default 5 minutes)
- Revocation API triggered by Ψ(t) anomaly detection
- Unix domain socket IPC for network namespace isolation

Architecture:
    Separate Python process, communicates via Unix socket only.
    Never exposes credentials to network. Tokens are time-bound and signed.
"""

import json
import hashlib
import time
import socket
import threading
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Optional, Any
from enum import Enum

# Import QSEAL from local mvar-core package
from .qseal import QSealSigner


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
    credential_type: CredentialType
    scope: CredentialScope
    issued_at: float  # Unix timestamp
    expires_at: float  # Unix timestamp
    revoked: bool
    single_use: bool
    qseal_signature: Dict[str, str]

    # Encrypted credential payload (base64-encoded)
    encrypted_payload: str

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

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary"""
        return {
            "token_id": self.token_id,
            "credential_type": self.credential_type.value,
            "scope": self.scope.value,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "revoked": self.revoked,
            "single_use": self.single_use,
            "qseal_signature": self.qseal_signature,
            "encrypted_payload": self.encrypted_payload,
            "is_valid": self.is_valid(),
            "time_remaining": self.time_remaining()
        }


class CredentialVault:
    """
    Isolated credential vault service.

    Runs as separate process, communicates via Unix domain socket only.
    Provides time-limited, scope-restricted, QSEAL-signed credential tokens.

    Security properties:
    - Credentials never leave vault process unencrypted
    - Tokens have short TTL (default 5 minutes)
    - Token revocation on Ψ(t) anomaly detection
    - Full audit trail with QSEAL chain
    - No network exposure (Unix socket only)
    """

    def __init__(
        self,
        socket_path: str = "/tmp/mvar_credential_vault.sock",
        default_ttl_seconds: int = 300,  # 5 minutes
        enable_audit_log: bool = True
    ):
        self.socket_path = socket_path
        self.default_ttl_seconds = default_ttl_seconds
        self.enable_audit_log = enable_audit_log

        # Initialize QSEAL signer (Entry 500 SDK)
        self.qseal = QSealSigner()

        # Token registry: {token_id: CredentialToken}
        self.tokens: Dict[str, CredentialToken] = {}

        # Credential store: {credential_id: encrypted_credential}
        # In production: use proper key management (HSM, Vault, etc.)
        self.credentials: Dict[str, str] = {}

        # Audit log
        self.audit_log: list = []

        # Revocation triggers (Ψ anomaly thresholds)
        self.psi_anomaly_threshold = 5.0  # 5-sigma deviation

        # Server socket
        self.server_socket: Optional[socket.socket] = None
        self.running = False

    def start(self):
        """Start the vault server (Unix domain socket)"""
        # Remove existing socket file if present
        socket_path = Path(self.socket_path)
        if socket_path.exists():
            socket_path.unlink()

        # Create Unix domain socket
        self.server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server_socket.bind(self.socket_path)
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
            # Read request (JSON-encoded)
            request_data = client_socket.recv(4096).decode()
            request = json.loads(request_data)

            action = request.get("action")

            # Route to appropriate handler
            if action == "issue_token":
                response = self._handle_issue_token(request)
            elif action == "verify_token":
                response = self._handle_verify_token(request)
            elif action == "revoke_token":
                response = self._handle_revoke_token(request)
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

    def _handle_issue_token(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Issue a new credential token"""
        credential_id = request.get("credential_id")
        credential_type = CredentialType(request.get("credential_type", "api_key"))
        scope = CredentialScope(request.get("scope", "read"))
        ttl_seconds = request.get("ttl_seconds", self.default_ttl_seconds)
        single_use = request.get("single_use", False)
        entry500_context = request.get("entry500_context", {})

        # Verify credential exists
        if credential_id not in self.credentials:
            return {"success": False, "error": f"Credential {credential_id} not found"}

        # Generate token ID
        token_id = self._generate_token_id(credential_id)

        # Get encrypted credential payload
        encrypted_payload = self.credentials[credential_id]

        # Create token metadata for QSEAL
        now = time.time()
        token_metadata = {
            "token_id": token_id,
            "credential_id": credential_id,
            "credential_type": credential_type.value,
            "scope": scope.value,
            "issued_at": now,
            "expires_at": now + ttl_seconds,
            "single_use": single_use,
            "entry500_context": entry500_context
        }

        # QSEAL signature
        sealed_metadata = self.qseal.seal_result(token_metadata)

        # Create token
        token = CredentialToken(
            token_id=token_id,
            credential_type=credential_type,
            scope=scope,
            issued_at=now,
            expires_at=now + ttl_seconds,
            revoked=False,
            single_use=single_use,
            qseal_signature=sealed_metadata.to_dict(),
            encrypted_payload=encrypted_payload
        )

        # Store token
        self.tokens[token_id] = token

        # Audit log
        self._audit_log("token_issued", {
            "token_id": token_id,
            "credential_id": credential_id,
            "scope": scope.value,
            "ttl_seconds": ttl_seconds,
            "entry500_context": entry500_context
        })

        return {
            "success": True,
            "token": token.to_dict()
        }

    def _handle_verify_token(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Verify a token's validity"""
        token_id = request.get("token_id")

        if token_id not in self.tokens:
            return {"success": False, "error": "Token not found"}

        token = self.tokens[token_id]

        # Check if single-use token has already been consumed
        if token.single_use and not token.is_valid():
            return {"success": False, "error": "Single-use token already consumed"}

        # Mark single-use token as consumed
        if token.single_use and token.is_valid():
            token.revoked = True
            self._audit_log("single_use_token_consumed", {"token_id": token_id})

        return {
            "success": True,
            "valid": token.is_valid(),
            "token": token.to_dict()
        }

    def _handle_revoke_token(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Revoke a token"""
        token_id = request.get("token_id")
        reason = request.get("reason", "manual_revocation")

        return {"success": self._revoke_token(token_id, reason)}

    def _handle_psi_anomaly(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle Ψ(t) anomaly detection.

        If drift exceeds threshold, revoke all active tokens for that session.
        """
        psi_current = request.get("psi_current")
        psi_baseline = request.get("psi_baseline")
        psi_sigma = request.get("psi_sigma")
        session_id = request.get("session_id")

        # Calculate anomaly score
        if psi_sigma > 0:
            anomaly_score = abs(psi_current - psi_baseline) / psi_sigma
        else:
            anomaly_score = 0.0

        # Check threshold
        if anomaly_score >= self.psi_anomaly_threshold:
            # REVOKE ALL TOKENS for this session
            revoked_count = 0
            for token in self.tokens.values():
                if token.is_valid():
                    # In production: check token session_id from entry500_context
                    self._revoke_token(
                        token.token_id,
                        reason=f"psi_anomaly_detected (score={anomaly_score:.2f}σ)"
                    )
                    revoked_count += 1

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

    def _generate_token_id(self, credential_id: str) -> str:
        """Generate unique token ID"""
        timestamp = str(time.time())
        nonce = hashlib.sha256(f"{credential_id}{timestamp}".encode()).hexdigest()[:16]
        return f"mvar_token_{nonce}"

    def _audit_log(self, event_type: str, details: Dict[str, Any]):
        """Write to audit log"""
        if not self.enable_audit_log:
            return

        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "event_type": event_type,
            "details": details
        }

        self.audit_log.append(log_entry)

        # Optional: write to disk for persistence
        # In production: send to SIEM, append to QSEAL chain, etc.

    def add_credential(self, credential_id: str, encrypted_credential: str):
        """
        Add a credential to the vault.

        Args:
            credential_id: Unique identifier for the credential
            encrypted_credential: Base64-encoded encrypted credential

        In production: credentials should be encrypted with proper key management.
        For MVP: we accept pre-encrypted credentials.
        """
        self.credentials[credential_id] = encrypted_credential
        self._audit_log("credential_added", {"credential_id": credential_id})

    def get_audit_log(self) -> list:
        """Retrieve audit log"""
        return self.audit_log.copy()


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
        entry500_context: Optional[Dict[str, Any]] = None
    ) -> Optional[CredentialToken]:
        """Request a credential token from the vault"""
        request = {
            "action": "issue_token",
            "credential_id": credential_id,
            "credential_type": credential_type,
            "scope": scope,
            "ttl_seconds": ttl_seconds,
            "single_use": single_use,
            "entry500_context": entry500_context or {}
        }

        response = self._send_request(request)

        if response.get("success"):
            token_data = response["token"]
            return CredentialToken(
                token_id=token_data["token_id"],
                credential_type=CredentialType(token_data["credential_type"]),
                scope=CredentialScope(token_data["scope"]),
                issued_at=token_data["issued_at"],
                expires_at=token_data["expires_at"],
                revoked=token_data["revoked"],
                single_use=token_data["single_use"],
                qseal_signature=token_data["qseal_signature"],
                encrypted_payload=token_data["encrypted_payload"]
            )
        else:
            print(f"[CredentialVaultClient] Error: {response.get('error')}")
            return None

    def verify_token(self, token_id: str) -> Dict[str, Any]:
        """Verify a token's validity"""
        request = {"action": "verify_token", "token_id": token_id}
        return self._send_request(request)

    def revoke_token(self, token_id: str, reason: str = "manual") -> bool:
        """Revoke a token"""
        request = {"action": "revoke_token", "token_id": token_id, "reason": reason}
        response = self._send_request(request)
        return response.get("success", False)

    def report_psi_anomaly(
        self,
        psi_current: float,
        psi_baseline: float,
        psi_sigma: float,
        session_id: str
    ) -> Dict[str, Any]:
        """Report Ψ(t) anomaly to vault (may trigger mass revocation)"""
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
        entry500_context={"confidence": 0.75, "action": "read_email"}
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

        # Simulate Ψ anomaly
        print("3. Simulating Ψ(t) anomaly (6σ deviation)...")
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
