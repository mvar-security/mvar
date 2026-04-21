"""
Bash Command Policy Rules for MVAR Claude Code Hook Demo
==========================================================

Starter policy set with pattern-matching rules for common bash security risks.
This is a demonstration policy, not production-complete.

Author: MVAR Security
Date: 2026-04-20
"""

from __future__ import annotations

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
            r'~/\.ssh/id_[rd]sa\b',
            "bash_003",
            "critical",
            "credential_access",
            "Reading SSH private keys (~/.ssh/id_rsa or id_dsa)"
        ),
        (
            r'~/\.ssh/[^/]*_rsa\b',
            "bash_004",
            "critical",
            "credential_access",
            "Reading SSH private keys from ~/.ssh/"
        ),
        (
            r'~/\.aws/credentials',
            "bash_005",
            "critical",
            "credential_access",
            "Reading AWS credentials file"
        ),
        (
            r'~/\.aws/config',
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
            r'~/\.netrc',
            "bash_011",
            "critical",
            "credential_access",
            "Reading .netrc file (contains FTP/HTTP credentials)"
        ),
        (
            r'~/\.docker/config\.json',
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

        # === DESTRUCTIVE OPERATIONS (CRITICAL) ===
        (
            r'rm\s+(-[rRfF]+\s+)?/',
            "bash_020",
            "critical",
            "destructive_operation",
            "Destructive rm command targeting root directory"
        ),
        (
            r'rm\s+-rf\s+~',
            "bash_021",
            "critical",
            "destructive_operation",
            "Destructive rm -rf targeting home directory"
        ),
        (
            r':\(\)\{\s*:\|:\&\s*\}',
            "bash_022",
            "critical",
            "destructive_operation",
            "Fork bomb detected (malicious resource exhaustion)"
        ),
        (
            r'dd\s+if=/dev/zero\s+of=/',
            "bash_023",
            "critical",
            "destructive_operation",
            "Disk wipe operation detected"
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
        violations = []

        for regex, rule_id, severity, category, message in self._compiled_rules:
            match = regex.search(command)
            if match:
                violation = BashPolicyViolation(
                    rule_id=rule_id,
                    severity=severity,
                    category=category,
                    message=message,
                    matched_pattern=match.group(0)
                )
                violations.append(violation)

        return violations

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

        # Any critical violation = block
        if any(v.severity == "critical" for v in violations):
            return "block"

        # Multiple high violations = block
        high_count = sum(1 for v in violations if v.severity == "high")
        if high_count >= 2:
            return "block"

        # Single high violation = step_up (could be made configurable)
        if high_count == 1:
            return "step_up"

        # Medium/low only = allow with annotation
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
