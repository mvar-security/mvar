"""
MVAR QSEAL — Cryptographic Signing
===================================

Convenience wrapper around mvar_core.qseal for signing policy decisions.
"""

# Re-export QSEAL functionality from mvar_core
from mvar_core.qseal import (
    QSEALEngine,
    sign_decision,
    verify_signature,
)

__all__ = [
    "QSEALEngine",
    "sign_decision",
    "verify_signature",
]
