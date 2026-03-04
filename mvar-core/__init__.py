# MVAR Core - Information Flow Control for AI Agents
__version__ = "1.2.1"

try:
    from .profiles import SecurityProfile, apply_profile, create_default_runtime, profile_summary
except Exception:  # pragma: no cover
    # Keep import failures non-fatal for minimal environments.
    pass
