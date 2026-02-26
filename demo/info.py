"""
MVAR CLI information and environment diagnostics.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


def _safe_import_qseal():
    try:
        from mvar_core.qseal import QSealSigner  # type: ignore
        return QSealSigner
    except Exception:
        return None


def _doctor() -> int:
    print("=" * 70)
    print("  MVAR Doctor")
    print("=" * 70)
    print(f"Python executable: {sys.executable}")
    print(f"MVAR_ENABLE_LEDGER: {os.getenv('MVAR_ENABLE_LEDGER', '0')}")
    print(f"MVAR_ENABLE_TRUST_ORACLE: {os.getenv('MVAR_ENABLE_TRUST_ORACLE', '0')}")

    qseal_dir = Path(os.getenv("MVAR_QSEAL_DIR", str(Path.home() / ".mvar" / "qseal")))
    print(f"QSEAL dir: {qseal_dir}")

    QSealSigner = _safe_import_qseal()
    if QSealSigner is None:
        print("QSEAL signer import: FAIL")
        return 1

    try:
        signer = QSealSigner()
        print(f"QSEAL algorithm: {signer.algorithm}")
    except Exception as exc:
        print(f"QSEAL signer init: FAIL ({exc})")
        return 1

    if "site-packages" not in str(Path(__file__).resolve()):
        print("Install source: running from source tree")
    else:
        print("Install source: site-packages")

    print("Status: OK")
    return 0


def main() -> None:
    """Display MVAR system information."""
    print("=" * 70)
    print("  MVAR — MIRRA Verified Agent Runtime")
    print("  System Information")
    print("=" * 70)
    print()
    print("Version: 1.0.0")
    print("Author: Shawn Cohen")
    print("License: Apache 2.0")
    print()
    print("Dependencies:")
    print("  - numpy>=1.24.0,<3.0.0")
    print("  - cryptography>=41.0.0,<47.0.0")
    print()
    print("Python: >=3.10")
    print()
    QSealSigner = _safe_import_qseal()
    if QSealSigner is not None:
        try:
            signer = QSealSigner()
            print("Cryptographic Signing:")
            print(f"  Algorithm: {signer.algorithm}")
            print("  Hash: sha256")
            print()
        except Exception as exc:
            print(f"Cryptographic Signing: unavailable ({exc})")
            print()
    print("Architecture:")
    print("  - Provenance taint tracking (IFC)")
    print("  - Capability runtime (deny-by-default)")
    print("  - Sink policy engine (deterministic)")
    print("  - QSEAL audit trail")
    print()
    print("Use `mvar-doctor` for strict runtime diagnostics.")


def doctor_main() -> None:
    raise SystemExit(_doctor())


if __name__ == "__main__":
    main()
