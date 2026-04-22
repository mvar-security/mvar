"""Regression gate for adversarial corpus performance."""

from __future__ import annotations

import sys
from pathlib import Path
import pytest


def _run_harness(seed: int):
    adv_dir = Path(__file__).resolve().parent / "adversarial"
    if str(adv_dir) not in sys.path:
        sys.path.insert(0, str(adv_dir))

    from evaluation_harness import EvaluationHarness, EvaluationMetrics  # noqa: PLC0415

    harness = EvaluationHarness(
        attack_corpus_path=adv_dir / "corpus_attacks.json",
        benign_corpus_path=adv_dir / "corpus_benign.json",
        policy_profile="strict",
        variants_per_attack=10,
        seed=seed,
    )
    results = harness.run_evaluation()
    return EvaluationMetrics(**results["metrics"])


def test_adversarial_corpus_gate_fixed_seed_strict_profile() -> None:
    """Primary gate for reproducible baseline seed."""
    metrics = _run_harness(seed=42)

    assert metrics.raw_bypass_rate <= 0.10, (
        f"Raw bypass regression: {metrics.raw_bypass_rate:.2%} exceeds 10.00% threshold"
    )
    assert metrics.semantic_preserving_bypass_rate <= 0.05, (
        "Semantic-preserving bypass regression: "
        f"{metrics.semantic_preserving_bypass_rate:.2%} exceeds 5.00% threshold"
    )
    assert metrics.false_positive_rate <= 0.05, (
        f"False-positive regression: {metrics.false_positive_rate:.2%} exceeds 5.00% threshold"
    )


@pytest.mark.parametrize("seed", [1337, 271828])
def test_adversarial_corpus_gate_rotating_seeds(seed: int) -> None:
    """Secondary gate with additional deterministic seeds to catch brittle overfitting."""
    metrics = _run_harness(seed=seed)

    assert metrics.semantic_preserving_bypass_rate <= 0.05, (
        f"[seed={seed}] Semantic-preserving bypass regression: "
        f"{metrics.semantic_preserving_bypass_rate:.2%} exceeds 5.00% threshold"
    )
    assert metrics.false_positive_rate <= 0.05, (
        f"[seed={seed}] False-positive regression: "
        f"{metrics.false_positive_rate:.2%} exceeds 5.00% threshold"
    )
