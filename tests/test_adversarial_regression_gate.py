"""Regression gate for adversarial corpus performance."""

from __future__ import annotations

import sys
from pathlib import Path


def test_adversarial_corpus_gate_strict_profile() -> None:
    """Fail CI when bypass/FPR regress beyond acceptable thresholds."""
    adv_dir = Path(__file__).resolve().parent / "adversarial"
    if str(adv_dir) not in sys.path:
        sys.path.insert(0, str(adv_dir))

    from evaluation_harness import EvaluationHarness, EvaluationMetrics  # noqa: PLC0415

    harness = EvaluationHarness(
        attack_corpus_path=adv_dir / "corpus_attacks.json",
        benign_corpus_path=adv_dir / "corpus_benign.json",
        policy_profile="strict",
        variants_per_attack=10,
        seed=42,
    )
    results = harness.run_evaluation()
    metrics = EvaluationMetrics(**results["metrics"])

    assert metrics.bypass_rate <= 0.05, (
        f"Bypass rate regression: {metrics.bypass_rate:.2%} exceeds 5.00% threshold"
    )
    assert metrics.false_positive_rate <= 0.05, (
        f"False-positive regression: {metrics.false_positive_rate:.2%} exceeds 5.00% threshold"
    )

