"""Network exposure guardrails for local-model and gateway deployments.

Context:
- Public reports on March 2, 2026 highlighted widespread exposed local-model
  deployments caused by binding to 0.0.0.0 without authentication.
- Public reporting cited roughly 175,000 exposed instances in this class.
- These checks provide deterministic fail-closed diagnostics for that class.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Mapping, Optional, Tuple
from urllib.parse import urlparse


PUBLIC_BIND_HOSTS = {"0.0.0.0", "::", "[::]"}
LOCALHOST_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]"}

# Environment variables commonly used to control bind targets in local-model stacks.
BIND_ENV_KEYS = (
    "OLLAMA_HOST",
    "OPENCLAW_HOST",
    "OPENCLAW_BIND_HOST",
    "MVAR_BIND_HOST",
    "HOST",
)

# Environment variables that indicate caller intentionally accepts public bind.
ALLOW_PUBLIC_BIND_KEYS = (
    "MVAR_ALLOW_PUBLIC_BIND",
    "OPENCLAW_ALLOW_PUBLIC_BIND",
    "OLLAMA_ALLOW_PUBLIC_BIND",
)

# Environment variables that indicate authentication is configured.
AUTH_ENV_KEYS = (
    "MVAR_GATEWAY_AUTH_TOKEN",
    "MVAR_GATEWAY_API_KEY",
    "OPENCLAW_API_KEY",
    "OLLAMA_API_KEY",
    "MVAR_AUTH_REQUIRED",  # treated as boolean marker when set to "1"
)


@dataclass
class ExposureCheckResult:
    ok: bool
    issues: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    observed_public_binds: List[Tuple[str, str]] = field(default_factory=list)


def _extract_host(value: str) -> str:
    text = (value or "").strip()
    if not text:
        return ""

    # Accept raw host:port, raw host, or URL values.
    if "://" in text:
        parsed = urlparse(text)
        return (parsed.hostname or "").strip().lower()

    # Trim scheme-like accidental values and path fragments.
    host = text.split("/", 1)[0]
    if host.startswith("[") and host.endswith("]"):
        return host.lower()
    if ":" in host:
        host = host.split(":", 1)[0]
    return host.strip().lower()


def _is_truthy(value: Optional[str]) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def _public_bind_entries(env: Mapping[str, str]) -> List[Tuple[str, str]]:
    entries: List[Tuple[str, str]] = []
    for key in BIND_ENV_KEYS:
        raw = env.get(key, "")
        host = _extract_host(raw)
        if host in PUBLIC_BIND_HOSTS:
            entries.append((key, raw))
    return entries


def _allow_public_bind(env: Mapping[str, str]) -> bool:
    return any(_is_truthy(env.get(k)) for k in ALLOW_PUBLIC_BIND_KEYS)


def _auth_configured(env: Mapping[str, str]) -> bool:
    for key in AUTH_ENV_KEYS:
        value = env.get(key, "")
        if key == "MVAR_AUTH_REQUIRED":
            if _is_truthy(value):
                return True
        elif value.strip():
            return True
    return False


def check_network_exposure_guardrails(env: Mapping[str, str]) -> ExposureCheckResult:
    """Evaluate deterministic network exposure guardrails from environment vars."""

    binds = _public_bind_entries(env)
    if not binds:
        return ExposureCheckResult(ok=True)

    allow_public = _allow_public_bind(env)
    auth_configured = _auth_configured(env)

    result = ExposureCheckResult(ok=False, observed_public_binds=binds)
    for key, raw in binds:
        result.issues.append(
            f"Public bind detected: {key}={raw} (non-loopback exposure risk)."
        )

    if not allow_public:
        result.issues.append(
            "Public bind is blocked unless an explicit allow flag is set "
            "(MVAR_ALLOW_PUBLIC_BIND=1)."
        )

    if not auth_configured:
        result.issues.append(
            "Public bind requires authentication. Set an auth token/key "
            "(for example MVAR_GATEWAY_AUTH_TOKEN or OPENCLAW_API_KEY)."
        )

    if allow_public and auth_configured:
        result.ok = True
        result.issues = []
        result.warnings.append(
            "Public bind is explicitly allowed with authentication configured. "
            "Ensure firewall rules and TLS are also enabled."
        )

    return result


def enforce_network_exposure_guardrails(env: Mapping[str, str]) -> None:
    """Raise RuntimeError when guardrails fail."""

    result = check_network_exposure_guardrails(env)
    if not result.ok:
        raise RuntimeError(" ; ".join(result.issues))


def render_network_exposure_report(env: Mapping[str, str]) -> str:
    """Human-readable report used by diagnostics/doctor commands."""

    result = check_network_exposure_guardrails(env)
    lines: List[str] = []
    lines.append("Network exposure guardrails:")
    if result.observed_public_binds:
        for key, raw in result.observed_public_binds:
            lines.append(f"  - observed public bind: {key}={raw}")
    if result.ok:
        lines.append("  - status: OK")
    else:
        lines.append("  - status: BLOCK")
        for issue in result.issues:
            lines.append(f"  - issue: {issue}")
    for warning in result.warnings:
        lines.append(f"  - warning: {warning}")
    return "\n".join(lines)
