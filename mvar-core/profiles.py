"""Security profile bootstrap helpers for MVAR runtime initialization."""

from __future__ import annotations

import os
from enum import Enum
from typing import Dict, Tuple

try:
    from .capability import CapabilityRuntime
    from .provenance import ProvenanceGraph
    from .sink_policy import SinkPolicy, register_common_sinks
except ImportError:
    from capability import CapabilityRuntime
    from provenance import ProvenanceGraph
    from sink_policy import SinkPolicy, register_common_sinks


class SecurityProfile(str, Enum):
    """Supported runtime security presets."""

    STRICT = "strict"
    BALANCED = "balanced"
    MONITOR = "monitor"


PROFILE_ENV: Dict[SecurityProfile, Dict[str, str]] = {
    SecurityProfile.STRICT: {
        "MVAR_FAIL_CLOSED": "1",
        "MVAR_ENFORCE_ED25519": "1",
        "MVAR_POLICY_BUNDLE_ENFORCE_ED25519": "1",
        "MVAR_REQUIRE_EXECUTION_CONTRACT": "1",
        "MVAR_HTTP_DEFAULT_DENY": "1",
        "MVAR_REQUIRE_EXECUTION_TOKEN": "1",
        "MVAR_EXECUTION_TOKEN_ONE_TIME": "1",
        "MVAR_EXECUTION_TOKEN_NONCE_PERSIST": "1",
        "MVAR_ENABLE_COMPOSITION_RISK": "1",
        "MVAR_REQUIRE_DECLASSIFY_TOKEN": "1",
        "MVAR_DECLASSIFY_TOKEN_ONE_TIME": "1",
        "MVAR_REQUIRE_SIGNED_POLICY_BUNDLE": "1",
    },
    SecurityProfile.BALANCED: {
        "MVAR_FAIL_CLOSED": "1",
        "MVAR_ENFORCE_ED25519": "0",
        "MVAR_POLICY_BUNDLE_ENFORCE_ED25519": "1",
        "MVAR_REQUIRE_EXECUTION_CONTRACT": "0",
        "MVAR_HTTP_DEFAULT_DENY": "0",
        "MVAR_REQUIRE_EXECUTION_TOKEN": "1",
        "MVAR_EXECUTION_TOKEN_ONE_TIME": "1",
        "MVAR_EXECUTION_TOKEN_NONCE_PERSIST": "0",
        "MVAR_ENABLE_COMPOSITION_RISK": "1",
        "MVAR_REQUIRE_DECLASSIFY_TOKEN": "1",
        "MVAR_DECLASSIFY_TOKEN_ONE_TIME": "1",
        "MVAR_REQUIRE_SIGNED_POLICY_BUNDLE": "1",
    },
    SecurityProfile.MONITOR: {
        "MVAR_FAIL_CLOSED": "1",
        "MVAR_ENFORCE_ED25519": "0",
        "MVAR_POLICY_BUNDLE_ENFORCE_ED25519": "1",
        "MVAR_REQUIRE_EXECUTION_CONTRACT": "0",
        "MVAR_HTTP_DEFAULT_DENY": "0",
        "MVAR_REQUIRE_EXECUTION_TOKEN": "0",
        "MVAR_EXECUTION_TOKEN_ONE_TIME": "0",
        "MVAR_EXECUTION_TOKEN_NONCE_PERSIST": "0",
        "MVAR_ENABLE_COMPOSITION_RISK": "1",
        "MVAR_REQUIRE_DECLASSIFY_TOKEN": "0",
        "MVAR_DECLASSIFY_TOKEN_ONE_TIME": "0",
        "MVAR_REQUIRE_SIGNED_POLICY_BUNDLE": "1",
    },
}


def apply_profile(profile: SecurityProfile, *, overwrite: bool = True) -> Dict[str, str]:
    """Apply environment values for a profile.

    Returns the key/value pairs applied.
    """

    config = PROFILE_ENV[profile]
    for key, value in config.items():
        if overwrite or key not in os.environ:
            os.environ[key] = value
    return dict(config)


def create_default_runtime(
    profile: SecurityProfile = SecurityProfile.BALANCED,
    *,
    enable_qseal: bool = True,
    exec_token_secret: str = "",
    qseal_secret: str = "",
) -> Tuple[ProvenanceGraph, SinkPolicy, CapabilityRuntime]:
    """Create a configured MVAR control-plane runtime.

    This helper intentionally uses the existing stable APIs:
    - ProvenanceGraph
    - CapabilityRuntime
    - SinkPolicy
    - register_common_sinks
    """

    apply_profile(profile)

    if exec_token_secret:
        os.environ["MVAR_EXEC_TOKEN_SECRET"] = exec_token_secret
    if qseal_secret:
        os.environ["QSEAL_SECRET"] = qseal_secret

    graph = ProvenanceGraph(enable_qseal=enable_qseal)
    capability_runtime = CapabilityRuntime()
    policy = SinkPolicy(capability_runtime, graph, enable_qseal=enable_qseal)
    register_common_sinks(policy)
    return graph, policy, capability_runtime


def profile_summary(profile: SecurityProfile) -> Dict[str, str]:
    """Return a copy of profile env settings for diagnostics/docs."""

    return dict(PROFILE_ENV[profile])
