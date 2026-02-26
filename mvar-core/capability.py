"""
MVAR Capability Runtime

Implements deny-by-default capability-based access control.
Research foundation: Capsicum (USENIX Security), principle of least privilege

Core principle: No ambient authority. Every tool must explicitly declare
required capabilities. Actions denied by default unless manifest permits.

Key properties:
- Deny-by-default (no implicit permissions)
- Per-tool granularity (gmail_api ≠ slack_api)
- Per-target granularity (api.gmail.com ≠ attacker.com)
- Per-action granularity (read ≠ write ≠ exec)
- Composable capabilities (tool can declare multiple required caps)

This is the first hard boundary in the control plane.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Set, Optional, Pattern
import fnmatch
import shlex
from urllib.parse import urlparse


class CapabilityType(Enum):
    """
    Capability types for different resource classes.

    Each type represents a distinct security boundary:
    - FILESYSTEM_READ: Read files/directories
    - FILESYSTEM_WRITE: Write/modify files/directories
    - NETWORK_EGRESS: Outbound network connections
    - PROCESS_EXEC: Execute processes/commands
    - CREDENTIAL_ACCESS: Access credential vault
    - IPC: Inter-process communication
    """
    FILESYSTEM_READ = "filesystem_read"
    FILESYSTEM_WRITE = "filesystem_write"
    NETWORK_EGRESS = "network_egress"
    PROCESS_EXEC = "process_exec"
    CREDENTIAL_ACCESS = "credential_access"
    IPC = "ipc"


@dataclass
class CapabilityGrant:
    """
    Single capability grant with scope restrictions.

    Example:
        CapabilityGrant(
            cap_type=CapabilityType.NETWORK_EGRESS,
            allowed_targets=["api.gmail.com", "*.google.com"],
            metadata={"protocol": "https", "port": 443}
        )

    Targets support:
    - Exact match: "api.gmail.com"
    - Wildcard: "*.google.com"
    - Glob patterns: "/home/user/docs/**/*.txt"
    """
    cap_type: CapabilityType
    allowed_targets: List[str] = field(default_factory=list)
    denied_targets: List[str] = field(default_factory=list)  # Explicit denials (take precedence)
    metadata: Dict[str, any] = field(default_factory=dict)

    def matches_target(self, target: str) -> bool:
        """
        Check if target is permitted by this capability grant.

        Rules:
        1. Explicit denials take precedence
        2. If no allowed_targets, deny all (deny-by-default)
        3. Target must match at least one allowed pattern
        """
        # Check explicit denials first
        for deny_pattern in self.denied_targets:
            if self._pattern_matches(deny_pattern, target):
                return False

        # If no allowed targets specified, deny by default
        if not self.allowed_targets:
            return False

        # Check if target matches any allowed pattern
        for allow_pattern in self.allowed_targets:
            if self._pattern_matches(allow_pattern, target):
                return True

        return False

    @staticmethod
    def _pattern_matches(pattern: str, target: str) -> bool:
        """
        Pattern matching with support for:
        - Exact match: "api.gmail.com" matches "api.gmail.com"
        - Wildcard: "*.google.com" matches "api.google.com", "mail.google.com"
        - Glob: "/docs/**/*.txt" matches "/docs/2024/notes.txt"

        SECURITY: For filesystem paths, normalizes target to prevent path
        traversal attacks (e.g., "/tmp/safe/../etc/passwd" → "/etc/passwd").
        """
        # For filesystem paths, normalize target to prevent path traversal
        if "/" in target or "\\" in target:
            try:
                # Resolve path traversal: /tmp/safe/../etc/passwd → /etc/passwd
                target = str(Path(target).resolve())
            except:
                pass  # If resolution fails, use original target

        # Exact match
        if pattern == target:
            return True

        # Wildcard/glob match
        if fnmatch.fnmatch(target, pattern):
            return True

        # For filesystem patterns, also try Path glob
        if "/" in pattern or "\\" in pattern:
            try:
                pattern_path = Path(pattern)
                target_path = Path(target)
                # Simplified glob matching
                return fnmatch.fnmatch(str(target_path), str(pattern_path))
            except:
                pass

        return False


@dataclass
class ToolCapabilityManifest:
    """
    Capability manifest for a single tool.

    Example:
        manifest = ToolCapabilityManifest(
            tool_name="gmail_api",
            capabilities=[
                CapabilityGrant(
                    cap_type=CapabilityType.NETWORK_EGRESS,
                    allowed_targets=["api.gmail.com", "*.googleapis.com"]
                ),
                CapabilityGrant(
                    cap_type=CapabilityType.CREDENTIAL_ACCESS,
                    allowed_targets=["gmail_oauth_token"]
                )
            ]
        )
    """
    tool_name: str
    capabilities: List[CapabilityGrant] = field(default_factory=list)
    metadata: Dict[str, any] = field(default_factory=dict)

    def has_capability(self, cap_type: CapabilityType, target: Optional[str] = None) -> bool:
        """
        Check if tool has capability for given type and target.

        Args:
            cap_type: Capability type to check
            target: Optional target to verify (e.g., domain, path)

        Returns:
            True if tool has capability AND target is allowed
        """
        for grant in self.capabilities:
            if grant.cap_type == cap_type:
                if target is None:
                    # No target specified - just check if capability type exists
                    return True
                elif grant.matches_target(target):
                    return True

        return False

    def get_capability(self, cap_type: CapabilityType) -> Optional[CapabilityGrant]:
        """Get first capability grant of given type"""
        for grant in self.capabilities:
            if grant.cap_type == cap_type:
                return grant
        return None


class CapabilityRuntime:
    """
    Deny-by-default capability enforcement runtime.

    Security properties:
    - No ambient authority (all permissions explicit)
    - Fail-closed (unknown tool = deny)
    - Per-tool isolation (gmail_api permissions ≠ slack_api permissions)
    - Target-specific grants (api.gmail.com ≠ attacker.com)

    Usage:
        runtime = CapabilityRuntime()

        # Register tool capabilities
        runtime.register_tool(
            tool_name="gmail_api",
            capabilities=[
                CapabilityGrant(
                    cap_type=CapabilityType.NETWORK_EGRESS,
                    allowed_targets=["api.gmail.com"]
                )
            ]
        )

        # Check capability at runtime
        allowed = runtime.check_capability(
            tool="gmail_api",
            cap_type=CapabilityType.NETWORK_EGRESS,
            target="api.gmail.com"
        )
        # Result: True

        allowed = runtime.check_capability(
            tool="gmail_api",
            cap_type=CapabilityType.NETWORK_EGRESS,
            target="attacker.com"
        )
        # Result: False (not in allowed_targets)
    """

    def __init__(self):
        self.manifests: Dict[str, ToolCapabilityManifest] = {}

    def register_tool(
        self,
        tool_name: str,
        capabilities: List[CapabilityGrant],
        metadata: Optional[Dict[str, any]] = None
    ) -> ToolCapabilityManifest:
        """
        Register capability manifest for a tool.

        Args:
            tool_name: Unique tool identifier
            capabilities: List of capability grants
            metadata: Optional tool metadata

        Returns:
            Registered ToolCapabilityManifest
        """
        manifest = ToolCapabilityManifest(
            tool_name=tool_name,
            capabilities=capabilities,
            metadata=metadata or {}
        )
        self.manifests[tool_name] = manifest
        return manifest

    def check_capability(
        self,
        tool: str,
        cap_type: CapabilityType,
        target: Optional[str] = None
    ) -> bool:
        """
        Check if tool has capability for given type and target.

        Deny-by-default: Returns False if:
        - Tool not registered
        - Tool doesn't have capability type
        - Target not in allowed list

        Args:
            tool: Tool name
            cap_type: Capability type
            target: Optional target to verify

        Returns:
            True only if explicitly permitted
        """
        # Deny if tool not registered
        if tool not in self.manifests:
            return False

        manifest = self.manifests[tool]
        return manifest.has_capability(cap_type, target)

    def get_manifest(self, tool: str) -> Optional[ToolCapabilityManifest]:
        """Get capability manifest for tool"""
        return self.manifests.get(tool)

    def list_tools(self) -> List[str]:
        """List all registered tools"""
        return list(self.manifests.keys())

    def validate_process_exec(
        self,
        tool: str,
        command: str,
        allowed_commands: Optional[List[str]] = None,
        max_args: int = 16
    ) -> tuple[bool, str]:
        """
        Validate process execution against strict command boundaries.
        """
        if not self.check_capability(tool, CapabilityType.PROCESS_EXEC, target=tool):
            return False, "process_exec capability denied"
        if not command:
            return False, "empty command"
        if re.search(r"[;&|`<>]|(\$\()", command):
            return False, "shell metacharacters denied"
        try:
            tokens = shlex.split(command)
        except ValueError:
            return False, "command parsing failed"
        if not tokens:
            return False, "empty command tokens"
        if len(tokens) > max_args:
            return False, "too many command args"
        if allowed_commands and tokens[0] not in allowed_commands:
            return False, f"command '{tokens[0]}' not allowlisted"
        return True, "ok"

    def validate_network_egress(
        self,
        tool: str,
        target: str,
        allowed_domains: Optional[List[str]] = None
    ) -> tuple[bool, str]:
        """
        Validate network egress target against capability and hostname policy.
        """
        parsed = urlparse(target if "://" in target else f"https://{target}")
        hostname = (parsed.hostname or "").lower()
        if not hostname:
            return False, "missing hostname"
        if not self.check_capability(tool, CapabilityType.NETWORK_EGRESS, target=hostname):
            return False, "network_egress capability denied"
        if hostname in {"localhost", "127.0.0.1"} or hostname.startswith("10.") or hostname.startswith("192.168."):
            return False, "private network egress denied"
        if allowed_domains:
            allowed = any(
                hostname == domain or (domain.startswith("*.") and hostname.endswith(domain[1:]))
                for domain in allowed_domains
            )
            if not allowed:
                return False, f"hostname '{hostname}' not in allowlist"
        return True, "ok"


# Convenience builders for common tool patterns

def build_read_only_tool(
    tool_name: str,
    allowed_paths: List[str],
    network_domains: Optional[List[str]] = None
) -> ToolCapabilityManifest:
    """
    Build manifest for read-only tool (no write, no exec).

    Example:
        manifest = build_read_only_tool(
            tool_name="document_reader",
            allowed_paths=["/home/user/documents/**"],
            network_domains=["docs.google.com"]
        )
    """
    capabilities = [
        CapabilityGrant(
            cap_type=CapabilityType.FILESYSTEM_READ,
            allowed_targets=allowed_paths
        )
    ]

    if network_domains:
        capabilities.append(
            CapabilityGrant(
                cap_type=CapabilityType.NETWORK_EGRESS,
                allowed_targets=network_domains
            )
        )

    return ToolCapabilityManifest(
        tool_name=tool_name,
        capabilities=capabilities,
        metadata={"permission_class": "read_only"}
    )


def build_api_client_tool(
    tool_name: str,
    api_domains: List[str],
    credential_ids: List[str]
) -> ToolCapabilityManifest:
    """
    Build manifest for API client tool.

    Example:
        manifest = build_api_client_tool(
            tool_name="gmail_api",
            api_domains=["api.gmail.com", "*.googleapis.com"],
            credential_ids=["gmail_oauth_token"]
        )
    """
    return ToolCapabilityManifest(
        tool_name=tool_name,
        capabilities=[
            CapabilityGrant(
                cap_type=CapabilityType.NETWORK_EGRESS,
                allowed_targets=api_domains
            ),
            CapabilityGrant(
                cap_type=CapabilityType.CREDENTIAL_ACCESS,
                allowed_targets=credential_ids
            )
        ],
        metadata={"permission_class": "api_client"}
    )


def build_shell_tool(
    tool_name: str,
    allowed_commands: List[str],
    allowed_paths: Optional[List[str]] = None
) -> ToolCapabilityManifest:
    """
    Build manifest for shell execution tool.

    CRITICAL: Shell tools are ALWAYS high-risk.
    Use narrowest possible capability grants.

    Example:
        manifest = build_shell_tool(
            tool_name="git_wrapper",
            allowed_commands=["git"],  # Whitelist specific commands only
            allowed_paths=["/home/user/repos/**"]
        )
    """
    capabilities = [
        CapabilityGrant(
            cap_type=CapabilityType.PROCESS_EXEC,
            allowed_targets=allowed_commands,
            metadata={"warning": "CRITICAL_RISK"}
        )
    ]

    if allowed_paths:
        capabilities.extend([
            CapabilityGrant(
                cap_type=CapabilityType.FILESYSTEM_READ,
                allowed_targets=allowed_paths
            ),
            CapabilityGrant(
                cap_type=CapabilityType.FILESYSTEM_WRITE,
                allowed_targets=allowed_paths
            )
        ])

    return ToolCapabilityManifest(
        tool_name=tool_name,
        capabilities=capabilities,
        metadata={"permission_class": "shell_exec", "risk_level": "CRITICAL"}
    )


if __name__ == "__main__":
    # Example: Capability runtime with common tools
    print("=== MVAR Capability Runtime - Example ===\n")

    runtime = CapabilityRuntime()

    # 1. Register gmail_api tool
    print("1. Registering gmail_api tool")
    gmail_manifest = runtime.register_tool(
        tool_name="gmail_api",
        capabilities=[
            CapabilityGrant(
                cap_type=CapabilityType.NETWORK_EGRESS,
                allowed_targets=["api.gmail.com", "*.googleapis.com"]
            ),
            CapabilityGrant(
                cap_type=CapabilityType.CREDENTIAL_ACCESS,
                allowed_targets=["gmail_oauth_token"]
            )
        ]
    )
    print(f"   Capabilities: {[cap.cap_type.value for cap in gmail_manifest.capabilities]}\n")

    # 2. Register document_reader tool (read-only)
    print("2. Registering document_reader tool (read-only)")
    doc_manifest = build_read_only_tool(
        tool_name="document_reader",
        allowed_paths=["/home/user/documents/**", "/tmp/safe_docs/**"],
        network_domains=["docs.google.com"]
    )
    runtime.manifests["document_reader"] = doc_manifest
    print(f"   Allowed paths: {doc_manifest.get_capability(CapabilityType.FILESYSTEM_READ).allowed_targets}\n")

    # 3. Register bash tool (CRITICAL risk)
    print("3. Registering bash tool (CRITICAL risk - whitelisted commands only)")
    bash_manifest = build_shell_tool(
        tool_name="bash",
        allowed_commands=["ls", "cat", "grep"],  # Whitelist only
        allowed_paths=["/home/user/safe_scripts/**"]
    )
    runtime.manifests["bash"] = bash_manifest
    print(f"   Risk level: {bash_manifest.metadata['risk_level']}")
    print(f"   Allowed commands: {bash_manifest.get_capability(CapabilityType.PROCESS_EXEC).allowed_targets}\n")

    # 4. Capability checks (permitted)
    print("4. Capability check: gmail_api → api.gmail.com")
    allowed = runtime.check_capability(
        tool="gmail_api",
        cap_type=CapabilityType.NETWORK_EGRESS,
        target="api.gmail.com"
    )
    print(f"   Result: {allowed} ✅\n")

    # 5. Capability checks (denied - wrong target)
    print("5. Capability check: gmail_api → attacker.com")
    allowed = runtime.check_capability(
        tool="gmail_api",
        cap_type=CapabilityType.NETWORK_EGRESS,
        target="attacker.com"
    )
    print(f"   Result: {allowed} ❌ (not in allowed_targets)\n")

    # 6. Capability checks (denied - wrong capability type)
    print("6. Capability check: document_reader → FILESYSTEM_WRITE")
    allowed = runtime.check_capability(
        tool="document_reader",
        cap_type=CapabilityType.FILESYSTEM_WRITE,
        target="/home/user/documents/test.txt"
    )
    print(f"   Result: {allowed} ❌ (read-only tool)\n")

    # 7. Capability checks (denied - unregistered tool)
    print("7. Capability check: unknown_tool → NETWORK_EGRESS")
    allowed = runtime.check_capability(
        tool="unknown_tool",
        cap_type=CapabilityType.NETWORK_EGRESS,
        target="anywhere.com"
    )
    print(f"   Result: {allowed} ❌ (tool not registered)\n")

    # 8. Wildcard pattern matching
    print("8. Wildcard pattern matching: gmail_api → mail.googleapis.com")
    allowed = runtime.check_capability(
        tool="gmail_api",
        cap_type=CapabilityType.NETWORK_EGRESS,
        target="mail.googleapis.com"
    )
    print(f"   Result: {allowed} ✅ (matches *.googleapis.com)\n")

    # 9. Command whitelist enforcement
    print("9. Command whitelist: bash → 'curl' (NOT in whitelist)")
    allowed = runtime.check_capability(
        tool="bash",
        cap_type=CapabilityType.PROCESS_EXEC,
        target="curl"
    )
    print(f"   Result: {allowed} ❌ (only ls/cat/grep permitted)\n")

    print("10. Registered tools:")
    for tool in runtime.list_tools():
        manifest = runtime.get_manifest(tool)
        print(f"   - {tool}: {len(manifest.capabilities)} capabilities")

    print("\n=== Done ===")
    print("\nKey properties demonstrated:")
    print("✅ Deny-by-default (unknown tool/target → False)")
    print("✅ Per-tool isolation (gmail_api ≠ document_reader)")
    print("✅ Target-specific grants (api.gmail.com ≠ attacker.com)")
    print("✅ Capability type enforcement (read ≠ write)")
    print("✅ Wildcard pattern support (*.googleapis.com)")
    print("✅ Command whitelisting (bash limited to ls/cat/grep)")
