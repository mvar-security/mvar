# MVAR Core - Information Flow Control for AI Agents
__version__ = "1.4.3"

__all__ = [
    "SecurityProfile",
    "apply_profile",
    "create_default_runtime",
    "profile_summary",
]


def __getattr__(name):  # pragma: no cover - simple lazy-export shim
    if name in __all__:
        from .profiles import SecurityProfile, apply_profile, create_default_runtime, profile_summary

        exports = {
            "SecurityProfile": SecurityProfile,
            "apply_profile": apply_profile,
            "create_default_runtime": create_default_runtime,
            "profile_summary": profile_summary,
        }
        return exports[name]
    raise AttributeError(f"module 'mvar_core' has no attribute {name!r}")
