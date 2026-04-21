"""
Test S1501-03: Fix broken mvar.qseal exports.

Verifies that convenience exports work correctly.
"""


def test_qseal_convenience_exports_work():
    """Verify QSEAL convenience exports work."""
    from mvar.qseal import QSEALEngine, sign_decision, verify_signature

    payload = {"x": 1, "y": "ok"}
    seal = sign_decision(payload)
    assert verify_signature(payload, seal) is True
    assert QSEALEngine is not None
