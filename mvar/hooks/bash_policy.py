"""
Bash Command Policy Rules for MVAR Claude Code Hook Demo
==========================================================

Starter policy set with pattern-matching rules for common bash security risks.
This is a demonstration policy, not production-complete.

Author: MVAR Security
Date: 2026-04-20
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class BashPolicyViolation:
    """Represents a policy violation detected in a bash command."""

    rule_id: str
    severity: str  # "critical" | "high" | "medium" | "low"
    category: str  # "credential_access" | "destructive_operation" | "network_exfiltration" | "privilege_escalation"
    message: str
    matched_pattern: str


class BashPolicyEngine:
    """
    Pattern-based bash command policy engine.

    Evaluates bash commands against security rules and returns violations.
    Designed for Claude Code PreToolUse hook integration.
    """

    # Policy rules: (pattern, rule_id, severity, category, message_template)
    POLICY_RULES = [
        # === OBFUSCATION / ENCODED EXECUTION (CRITICAL) ===
        (
            r'base64\s+-d(?:ecode)?\s*\|\s*(bash|sh)\b',
            "bash_000",
            "critical",
            "obfuscated_execution",
            "Decoded base64 payload piped to shell execution"
        ),
        (
            r'xxd\s+-r\s+-p\s*\|\s*(bash|sh)\b',
            "bash_000a",
            "critical",
            "obfuscated_execution",
            "Decoded hex payload piped to shell execution"
        ),
        (
            r'eval\s*\$\(',
            "bash_000b",
            "critical",
            "obfuscated_execution",
            "Command substitution with eval indicates obfuscated execution"
        ),

        # === CREDENTIAL ACCESS (CRITICAL) ===
        (
            r'/etc/passwd',
            "bash_001",
            "critical",
            "credential_access",
            "Reading /etc/passwd exposes system user information"
        ),
        (
            r'/etc/shadow',
            "bash_002",
            "critical",
            "credential_access",
            "Reading /etc/shadow exposes password hashes (requires sudo)"
        ),
        (
            r'(~|/home/[^/\s]+)/\.ssh/id_[a-z0-9_]+\b',
            "bash_003",
            "critical",
            "credential_access",
            "Reading SSH private key material"
        ),
        (
            r'(~|/home/[^/\s]+|\$HOME)/\.ssh/authorized_keys\b',
            "bash_004",
            "critical",
            "credential_access",
            "Modifying SSH authorized_keys can grant persistent access"
        ),
        (
            r'(~|/home/[^/\s]+|\$HOME)/\.aws/credentials\b',
            "bash_005",
            "critical",
            "credential_access",
            "Reading AWS credentials file"
        ),
        (
            r'(~|/home/[^/\s]+|\$HOME)/\.aws/config\b',
            "bash_006",
            "high",
            "credential_access",
            "Reading AWS configuration file (may contain sensitive settings)"
        ),
        (
            r'env\s*\|\s*grep\s+.*SECRET',
            "bash_007",
            "critical",
            "credential_access",
            "Searching environment variables for secrets"
        ),
        (
            r'env\s*\|\s*grep\s+.*TOKEN',
            "bash_008",
            "critical",
            "credential_access",
            "Searching environment variables for tokens"
        ),
        (
            r'env\s*\|\s*grep\s+.*PASSWORD',
            "bash_009",
            "critical",
            "credential_access",
            "Searching environment variables for passwords"
        ),
        (
            r'printenv\s+.*SECRET',
            "bash_010",
            "critical",
            "credential_access",
            "Printing secret environment variables"
        ),
        (
            r'(^|\s)env($|\s)',
            "bash_010a",
            "high",
            "credential_access",
            "Dumping environment variables may expose secrets"
        ),
        (
            r'(~|/home/[^/\s]+|\$HOME)/\.netrc\b',
            "bash_011",
            "critical",
            "credential_access",
            "Reading .netrc file (contains FTP/HTTP credentials)"
        ),
        (
            r'(~|/home/[^/\s]+|\$HOME)/\.docker/config\.json\b',
            "bash_012",
            "critical",
            "credential_access",
            "Reading Docker registry credentials"
        ),
        (
            r'(^|\s|/)\.env($|\s)',
            "bash_013",
            "high",
            "credential_access",
            "Reading .env file (commonly contains API keys and secrets)"
        ),
        (
            r'(~|/home/[^/\s]+|\$HOME)/\.kube/config\b',
            "bash_013a",
            "critical",
            "credential_access",
            "Reading Kubernetes kubeconfig can expose cluster credentials"
        ),
        (
            r'terraform\.tfstate',
            "bash_013b",
            "critical",
            "credential_access",
            "Terraform state files often contain plaintext secrets"
        ),
        (
            r'aws\s+ssm\s+get-parameters?.*--with-decryption',
            "bash_013c",
            "critical",
            "credential_access",
            "Retrieving decrypted AWS SSM parameters exposes secrets"
        ),
        (
            r'vault\s+kv\s+get\b',
            "bash_013d",
            "critical",
            "credential_access",
            "Reading Vault secrets from CLI"
        ),
        (
            r'kubectl\s+get\s+secrets?\b',
            "bash_013e",
            "critical",
            "credential_access",
            "Accessing Kubernetes secrets directly"
        ),
        (
            r'git\s+config\s+--list.*(credential|token)',
            "bash_013f",
            "high",
            "credential_access",
            "Git config enumeration of credential or token values"
        ),
        (
            r'(~|/home/[^/\s]+|\$HOME)/\.config/gcloud/application_default_credentials\.json\b',
            "bash_013g",
            "critical",
            "credential_access",
            "Reading GCP application default credentials file"
        ),
        (
            r'(~|/home/[^/\s]+|\$HOME)/Library/Application\\?\s+Support/Google/Chrome/Default/(Login\\?\s+Data|Cookies)\b',
            "bash_013h",
            "critical",
            "credential_access",
            "Reading browser credential or cookie databases"
        ),

        # === DESTRUCTIVE OPERATIONS (CRITICAL) ===
        (
            r'rm\s+-[rRfF]+(\s+--)?\s+(/|~|\$HOME|\./|\.git|/usr|/var|/etc|/opt)',
            "bash_020",
            "critical",
            "destructive_operation",
            "Destructive recursive rm targeting critical paths"
        ),
        (
            r'rm\s+-[rRfF]+.*\*',
            "bash_021",
            "critical",
            "destructive_operation",
            "Destructive wildcard deletion detected"
        ),
        (
            r':\(\)\{\s*:\|:\&\s*\}',
            "bash_022",
            "critical",
            "destructive_operation",
            "Fork bomb detected (malicious resource exhaustion)"
        ),
        (
            r'dd\s+if=/dev/(zero|urandom)\s+of=/dev/',
            "bash_023",
            "critical",
            "destructive_operation",
            "Disk wipe operation detected"
        ),
        (
            r'killall\s+-9\b',
            "bash_024",
            "high",
            "destructive_operation",
            "Force-killing process groups is a destructive operation"
        ),
        (
            r'kubectl\s+delete\s+all\s+--all',
            "bash_025",
            "critical",
            "destructive_operation",
            "Deleting all Kubernetes resources across namespaces"
        ),
        (
            r'psql\b.*drop\s+schema\s+public\s+cascade',
            "bash_026",
            "critical",
            "destructive_operation",
            "Dropping database schema is destructive"
        ),
        (
            r'docker\s+rmi\s+-f\b',
            "bash_027",
            "high",
            "destructive_operation",
            "Forced deletion of Docker images"
        ),

        # === NETWORK CREDENTIAL EXFILTRATION (HIGH) ===
        (
            r'curl\s+.*api\..*\.(token|auth|login)',
            "bash_030",
            "high",
            "network_exfiltration",
            "curl to authentication endpoint (potential credential exfiltration)"
        ),
        (
            r'curl\s+.*oauth',
            "bash_031",
            "high",
            "network_exfiltration",
            "curl to OAuth endpoint (potential token exfiltration)"
        ),
        (
            r'wget\s+.*password',
            "bash_032",
            "high",
            "network_exfiltration",
            "wget with 'password' in URL (credential exposure risk)"
        ),
        (
            r'curl\s+.*--data.*password',
            "bash_033",
            "high",
            "network_exfiltration",
            "curl POST with password in request body"
        ),
        (
            r'curl\b.*(-t|-x\s+post|-d\s+@?-)',
            "bash_034",
            "high",
            "network_exfiltration",
            "curl upload or POST payload can exfiltrate data"
        ),
        (
            r'curl\s+https?://',
            "bash_034a",
            "high",
            "network_exfiltration",
            "curl to external HTTP endpoint can exfiltrate data"
        ),
        (
            r'(scp|rsync)\b.*@',
            "bash_035",
            "critical",
            "network_exfiltration",
            "File transfer to remote host detected"
        ),
        (
            r'ssh\s+(\$[A-Za-z_][A-Za-z0-9_]*|\S+)',
            "bash_036",
            "high",
            "network_exfiltration",
            "Remote SSH operation detected"
        ),
        (
            r'nc\s+-e\s+',
            "bash_037",
            "critical",
            "network_exfiltration",
            "Netcat reverse shell pattern detected"
        ),
        (
            r'dig\s+.*\.[a-z0-9-]+\.[a-z]{2,}',
            "bash_038",
            "high",
            "network_exfiltration",
            "DNS query with encoded payload domain indicates exfiltration"
        ),

        # === PRIVILEGE ESCALATION (HIGH) ===
        (
            r'sudo\s+su\s+-',
            "bash_040",
            "high",
            "privilege_escalation",
            "Escalating to root shell via sudo su"
        ),
        (
            r'sudo\s+bash',
            "bash_041",
            "high",
            "privilege_escalation",
            "Escalating to root bash shell"
        ),
        (
            r'chmod\s+[0-7]*[67][0-9]{2}',
            "bash_042",
            "medium",
            "privilege_escalation",
            "Setting world-writable or executable permissions"
        ),
        (
            r'sudo\s+chmod\s+777\s+/var/run/docker\.sock',
            "bash_043",
            "critical",
            "privilege_escalation",
            "World-writable Docker socket enables container escape"
        ),
        (
            r'sudo\s+(useradd|usermod|chpasswd)\b',
            "bash_044",
            "critical",
            "privilege_escalation",
            "User account privilege modification detected"
        ),
        (
            r'NOPASSWD:ALL',
            "bash_045",
            "critical",
            "privilege_escalation",
            "Passwordless sudo grants unrestricted escalation"
        ),
        (
            r'/etc/sudoers',
            "bash_046",
            "critical",
            "privilege_escalation",
            "Modification of sudoers configuration detected"
        ),
        (
            r'chmod\s+u\+s\b',
            "bash_047",
            "critical",
            "privilege_escalation",
            "Setting SUID bit can grant privilege escalation"
        ),
        (
            r'(^|\s)sudo($|\s)',
            "bash_048",
            "high",
            "privilege_escalation",
            "Privileged command execution via sudo"
        ),
        (
            r'docker\s+exec\s+-it\b',
            "bash_049",
            "high",
            "privilege_escalation",
            "Interactive shell access into running container"
        ),
        (
            r'kubectl\s+exec\s+-it\b',
            "bash_050",
            "high",
            "privilege_escalation",
            "Interactive shell access into Kubernetes workload"
        ),
    ]

    def __init__(self):
        """Initialize the policy engine with compiled regex patterns."""
        self._compiled_rules = [
            (re.compile(pattern, re.IGNORECASE), rule_id, severity, category, message)
            for pattern, rule_id, severity, category, message in self.POLICY_RULES
        ]

    def evaluate_command(self, command: str) -> list[BashPolicyViolation]:
        """
        Evaluate a bash command against policy rules.

        Args:
            command: The bash command string to evaluate

        Returns:
            List of BashPolicyViolation objects (empty if no violations)
        """
        violations_by_rule: dict[str, BashPolicyViolation] = {}

        for candidate in self._expand_inspection_candidates(command):
            for regex, rule_id, severity, category, message in self._compiled_rules:
                match = regex.search(candidate)
                if match and rule_id not in violations_by_rule:
                    violations_by_rule[rule_id] = BashPolicyViolation(
                        rule_id=rule_id,
                        severity=severity,
                        category=category,
                        message=message,
                        matched_pattern=match.group(0),
                    )

        return list(violations_by_rule.values())

    def _expand_inspection_candidates(self, command: str) -> list[str]:
        """Expand command into decoded/normalized candidates for inspection."""
        candidates: set[str] = set()
        queue = [command]

        while queue and len(candidates) < 16:
            current = queue.pop(0).strip()
            if not current or current in candidates:
                continue
            candidates.add(current)

            normalized = self._normalize_command(current)
            if normalized and normalized not in candidates:
                queue.append(normalized)

            decoded_b64 = self._decode_base64_payload(current)
            if decoded_b64 and decoded_b64 not in candidates:
                queue.append(decoded_b64)

            decoded_hex = self._decode_hex_payload(current)
            if decoded_hex and decoded_hex not in candidates:
                queue.append(decoded_hex)

            eval_echo = self._extract_eval_echo(current)
            if eval_echo and eval_echo not in candidates:
                queue.append(eval_echo)

        return list(candidates)

    def _normalize_command(self, command: str) -> str:
        """Normalize whitespace and common indirections used for evasion."""
        normalized = re.sub(r'\s+', ' ', command).strip()
        normalized = normalized.replace(r'\ ', ' ')
        normalized = re.sub(r'\$\{RM:-rm\}', 'rm', normalized, flags=re.IGNORECASE)
        normalized = re.sub(r'\$\{SUDO:-sudo\}', 'sudo', normalized, flags=re.IGNORECASE)
        if len(normalized) >= 2 and normalized[0] == normalized[-1] and normalized[0] in {"'", '"'}:
            normalized = normalized[1:-1].strip()
        return normalized

    def _decode_base64_payload(self, command: str) -> Optional[str]:
        """Decode simple echo <base64> | base64 -d pipelines."""
        match = re.search(
            r'echo\s+["\']?([A-Za-z0-9+/=]{16,})["\']?\s*\|\s*base64\s+-d(?:ecode)?',
            command,
            re.IGNORECASE,
        )
        if not match:
            return None
        payload = match.group(1)
        try:
            decoded = base64.b64decode(payload, validate=True).decode("utf-8", errors="ignore").strip()
        except (binascii.Error, ValueError):
            return None
        return decoded or None

    def _decode_hex_payload(self, command: str) -> Optional[str]:
        """Decode simple echo <hex> | xxd -r -p pipelines."""
        match = re.search(
            r'echo\s+["\']?([0-9a-fA-F]{16,})["\']?\s*\|\s*xxd\s+-r\s+-p',
            command,
            re.IGNORECASE,
        )
        if not match:
            return None
        payload = match.group(1)
        if len(payload) % 2 != 0:
            return None
        try:
            decoded = bytes.fromhex(payload).decode("utf-8", errors="ignore").strip()
        except ValueError:
            return None
        return decoded or None

    def _extract_eval_echo(self, command: str) -> Optional[str]:
        """Extract payload from eval $(echo <payload>) wrappers."""
        match = re.search(r'eval\s*\$\(\s*echo\s+(.+?)\s*\)\s*$', command, re.IGNORECASE)
        if not match:
            return None
        payload = match.group(1).strip()
        if len(payload) >= 2 and payload[0] == payload[-1] and payload[0] in {"'", '"'}:
            payload = payload[1:-1].strip()
        return payload or None

    def get_decision(self, violations: list[BashPolicyViolation]) -> str:
        """
        Determine execution decision based on violations.

        Args:
            violations: List of policy violations

        Returns:
            "allow" | "block" | "step_up"
        """
        if not violations:
            return "allow"

        # Strict security posture: any critical/high violation blocks execution.
        if any(v.severity in {"critical", "high"} for v in violations):
            return "block"

        # Medium-only signals are still suspicious: require step-up review.
        if any(v.severity == "medium" for v in violations):
            return "step_up"

        # Low-only = allow with annotation.
        return "allow"


def evaluate_bash_command(command: str) -> tuple[str, list[dict], str]:
    """
    Convenience function to evaluate a bash command.

    Args:
        command: The bash command string to evaluate

    Returns:
        Tuple of (decision, violations_list, primary_violation_message)

    Example:
        >>> decision, violations, message = evaluate_bash_command("cat /etc/passwd")
        >>> assert decision == "block"
        >>> assert violations[0]["category"] == "credential_access"
    """
    engine = BashPolicyEngine()
    violations = engine.evaluate_command(command)
    decision = engine.get_decision(violations)

    violations_list = [
        {
            "rule_id": v.rule_id,
            "severity": v.severity,
            "category": v.category,
            "message": v.message,
            "matched_pattern": v.matched_pattern
        }
        for v in violations
    ]

    primary_message = violations[0].message if violations else "No violations"

    return decision, violations_list, primary_message
