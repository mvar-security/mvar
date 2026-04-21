"""
MVAR QSEAL convenience exports.
"""

from mvar_core.qseal import QSeal, QSealSigner

# Backward-compatible alias
QSEALEngine = QSealSigner

def sign_decision(result_dict):
    signer = QSealSigner()
    return signer.seal_result(result_dict)

def verify_signature(result_dict, seal):
    signer = QSealSigner()
    if isinstance(seal, dict):
        seal = QSeal(**seal)
    return signer.verify_seal(seal, result_dict)

__all__ = [
    "QSeal",
    "QSealSigner",
    "QSEALEngine",
    "sign_decision",
    "verify_signature",
]
