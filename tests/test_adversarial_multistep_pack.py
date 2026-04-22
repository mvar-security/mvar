"""Regression checks for staged multi-step adversarial scenarios."""

from __future__ import annotations

import json
from pathlib import Path

from mvar.hooks import evaluate_bash_command


def test_multistep_attack_pack() -> None:
    """Ensure staged attacks are caught when they cross into high-risk steps."""
    corpus_path = Path(__file__).resolve().parent / "adversarial" / "corpus_multistep.json"
    scenarios = json.loads(corpus_path.read_text())

    blocked_steps = 0
    total_steps = 0

    for scenario in scenarios:
        scenario_has_block = False
        for step in scenario["steps"]:
            total_steps += 1
            decision, violations, _message = evaluate_bash_command(step["command"])
            blocked = decision == "block"
            if blocked:
                blocked_steps += 1
                scenario_has_block = True

            assert blocked == step["expected_block"], (
                f"{scenario['scenario_id']}:{step['step_id']} expected_block={step['expected_block']} "
                f"got decision={decision} violations={violations}"
            )

        assert scenario_has_block, (
            f"{scenario['scenario_id']} produced no block events; expected at least one high-risk step"
        )

    assert total_steps > 0
    assert blocked_steps > 0
