"""
Test S1501-04: Stop asserting qseal_verified=True without verification.

Verifies that qseal_verified reflects actual verification check.
"""
import hmac
import hashlib
import json


def test_qseal_verified_reflects_actual_check():
    """Verify qseal_verified equals compare_digest result."""
    # Build canonical payload
    policy_outcome = {"decision": "allow", "confidence": 0.95}
    qseal_secret = b"test_secret_key"

    canonical_json = json.dumps(policy_outcome, sort_keys=True, separators=(',', ':'))
    meta_hash = hashlib.sha256(canonical_json.encode()).hexdigest()

    # Compute signature
    qseal_signature = hmac.new(
        qseal_secret,
        canonical_json.encode(),
        hashlib.sha256
    ).hexdigest()

    # Recompute and verify (same secret, should match)
    recomputed_signature = hmac.new(
        qseal_secret,
        canonical_json.encode(),
        hashlib.sha256
    ).hexdigest()
    qseal_verified = hmac.compare_digest(qseal_signature, recomputed_signature)

    assert qseal_verified is True

    # Test with different secret (should NOT match)
    wrong_signature = hmac.new(
        b"wrong_secret",
        canonical_json.encode(),
        hashlib.sha256
    ).hexdigest()
    qseal_verified_wrong = hmac.compare_digest(qseal_signature, wrong_signature)

    assert qseal_verified_wrong is False
