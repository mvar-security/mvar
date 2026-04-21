#!/usr/bin/env python3
"""
MVAR Adversarial Evaluation Harness

Orchestrates the complete adversarial benchmark:
1. Load attack corpus (50 base attacks)
2. Load benign corpus (100 safe commands)
3. For each attack: generate 10 variants, test all
4. For each benign: test directly
5. Collect results (decision, execution, latency)
6. Compute metrics (bypass rate, FPR, latency stats)
7. Export results as JSON + markdown report

Usage:
    python evaluation_harness.py \
        --attack-corpus tests/adversarial/corpus_attacks.json \
        --benign-corpus tests/adversarial/corpus_benign.json \
        --policy-profile strict \
        --output results/eval_1_5_4.json
"""

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Dict, List, Any
from dataclasses import dataclass, asdict
import statistics

# Ensure local repository code is imported before site-packages.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from adaptive_attacker import AdaptiveAttacker, AttackVariant, AttackResult, VariantType


@dataclass
class BenignTestResult:
    """Result of testing a single benign command."""
    benign_id: str
    category: str
    command: str
    expected_decision: str
    decision: str
    blocked: bool
    latency_ms: float
    false_positive: bool  # Benign command incorrectly blocked


@dataclass
class EvaluationMetrics:
    """Aggregate metrics across all tests."""
    # Attack metrics
    total_attacks: int
    total_variants: int
    bypasses: int
    blocks: int
    bypass_rate: float

    # Benign metrics
    total_benign: int
    false_positives: int
    false_positive_rate: float

    # Latency metrics
    latency_p50_ms: float
    latency_p95_ms: float
    latency_p99_ms: float
    latency_mean_ms: float

    # Per-category breakdown
    bypass_rate_by_category: Dict[str, float]
    false_positive_rate_by_category: Dict[str, float]


class EvaluationHarness:
    """Orchestrates adversarial evaluation against MVAR policy."""

    def __init__(
        self,
        attack_corpus_path: Path,
        benign_corpus_path: Path,
        policy_profile: str = "strict",
        variants_per_attack: int = 10,
        seed: int = 42
    ):
        self.attack_corpus_path = attack_corpus_path
        self.benign_corpus_path = benign_corpus_path
        self.policy_profile = policy_profile
        self.variants_per_attack = variants_per_attack
        self.seed = seed

        # Load policy engine (would be actual MVAR policy in production)
        self.policy_engine = self._load_policy_engine(policy_profile)

        # Initialize adaptive attacker
        self.attacker = AdaptiveAttacker(self.policy_engine, seed=seed)

        # Results storage
        self.attack_results: List[Dict] = []
        self.benign_results: List[BenignTestResult] = []
        self.all_latencies: List[float] = []

    def _load_policy_engine(self, profile: str):
        """Load MVAR policy engine with specified profile.

        Uses actual mvar.hooks.evaluate_bash_command for real policy evaluation.
        """
        from mvar.hooks import evaluate_bash_command
        import time

        class RealPolicyEngine:
            """Real MVAR policy engine wrapper."""
            def __init__(self):
                self.evaluate_fn = evaluate_bash_command

            def evaluate(self, command: str) -> Dict[str, Any]:
                start_time = time.time()

                # Call real MVAR policy engine
                decision, violations, message = self.evaluate_fn(command)

                latency_ms = (time.time() - start_time) * 1000

                # Map to expected format
                return {
                    'decision': decision,  # 'allow', 'block', or 'step_up'
                    'confidence': 1.0 if violations else 0.9,
                    'latency_ms': latency_ms,
                    'violations': violations,
                    'message': message
                }

        return RealPolicyEngine()

    def load_attack_corpus(self) -> List[Dict]:
        """Load attack corpus from JSON file."""
        with open(self.attack_corpus_path) as f:
            return json.load(f)

    def load_benign_corpus(self) -> List[Dict]:
        """Load benign corpus from JSON file."""
        with open(self.benign_corpus_path) as f:
            return json.load(f)

    def run_attack_campaign(self, attack: Dict) -> Dict:
        """Run adaptive attack campaign: generate variants and test all."""
        start_time = time.time()

        # Generate variants
        base_command = attack['expected_command']
        variants = self.attacker.generate_variants(base_command, count=self.variants_per_attack)

        # Test each variant
        results = []
        variant_result_pairs = []  # Store (variant, result) pairs to track transformation types
        bypass_found = False

        for variant in variants:
            result = self.attacker.test_variant(variant)
            results.append(result)
            variant_result_pairs.append((variant, result))
            self.all_latencies.append(result.latency_ms)

            # Check if bypass occurred (outcome == "bypass" means command was not blocked)
            if result.outcome == "bypass":
                bypass_found = True

        elapsed_ms = (time.time() - start_time) * 1000

        return {
            'attack_id': attack['attack_id'],
            'category': attack['category'],
            'description': attack['description'],
            'severity': attack['severity'],
            'base_command': base_command,
            'variants_tested': len(variants),
            'bypass_found': bypass_found,
            'blocks': sum(1 for r in results if r.outcome == "success"),
            'bypasses': sum(1 for r in results if r.outcome == "bypass"),
            'successful_transformations': [
                variant.variant_type.value
                for variant, result in variant_result_pairs if result.outcome == "bypass"
            ],
            'elapsed_ms': elapsed_ms,
            'results': [asdict(r) for r in results]
        }

    def test_benign_command(self, benign: Dict) -> BenignTestResult:
        """Test a single benign command."""
        command = benign['command']
        expected = benign['expected_decision']

        start_time = time.time()
        policy_result = self.policy_engine.evaluate(command)
        latency_ms = (time.time() - start_time) * 1000

        decision = policy_result['decision']
        blocked = (decision == 'block')

        # False positive = benign command incorrectly blocked
        false_positive = (expected == 'allow' and blocked)

        self.all_latencies.append(latency_ms)

        return BenignTestResult(
            benign_id=benign['benign_id'],
            category=benign['category'],
            command=command,
            expected_decision=expected,
            decision=decision,
            blocked=blocked,
            latency_ms=latency_ms,
            false_positive=false_positive
        )

    def compute_metrics(self) -> EvaluationMetrics:
        """Compute aggregate metrics across all test results."""
        # Attack metrics
        total_attacks = len(self.attack_results)
        total_variants = sum(r['variants_tested'] for r in self.attack_results)
        bypasses = sum(r['bypasses'] for r in self.attack_results)
        blocks = sum(r['blocks'] for r in self.attack_results)
        bypass_rate = bypasses / total_variants if total_variants > 0 else 0.0

        # Benign metrics
        total_benign = len(self.benign_results)
        false_positives = sum(1 for r in self.benign_results if r.false_positive)
        false_positive_rate = false_positives / total_benign if total_benign > 0 else 0.0

        # Latency metrics
        latencies_sorted = sorted(self.all_latencies)
        latency_p50 = statistics.median(latencies_sorted)
        latency_p95 = latencies_sorted[int(len(latencies_sorted) * 0.95)] if latencies_sorted else 0
        latency_p99 = latencies_sorted[int(len(latencies_sorted) * 0.99)] if latencies_sorted else 0
        latency_mean = statistics.mean(latencies_sorted) if latencies_sorted else 0

        # Per-category breakdown
        bypass_by_category = {}
        for category in set(r['category'] for r in self.attack_results):
            cat_results = [r for r in self.attack_results if r['category'] == category]
            cat_variants = sum(r['variants_tested'] for r in cat_results)
            cat_bypasses = sum(r['bypasses'] for r in cat_results)
            bypass_by_category[category] = cat_bypasses / cat_variants if cat_variants > 0 else 0.0

        fp_by_category = {}
        for category in set(r.category for r in self.benign_results):
            cat_results = [r for r in self.benign_results if r.category == category]
            cat_total = len(cat_results)
            cat_fps = sum(1 for r in cat_results if r.false_positive)
            fp_by_category[category] = cat_fps / cat_total if cat_total > 0 else 0.0

        return EvaluationMetrics(
            total_attacks=total_attacks,
            total_variants=total_variants,
            bypasses=bypasses,
            blocks=blocks,
            bypass_rate=bypass_rate,
            total_benign=total_benign,
            false_positives=false_positives,
            false_positive_rate=false_positive_rate,
            latency_p50_ms=latency_p50,
            latency_p95_ms=latency_p95,
            latency_p99_ms=latency_p99,
            latency_mean_ms=latency_mean,
            bypass_rate_by_category=bypass_by_category,
            false_positive_rate_by_category=fp_by_category
        )

    def run_evaluation(self) -> Dict:
        """Run complete adversarial evaluation."""
        print(f"Loading attack corpus from {self.attack_corpus_path}...")
        attacks = self.load_attack_corpus()
        print(f"  Loaded {len(attacks)} base attacks")

        print(f"Loading benign corpus from {self.benign_corpus_path}...")
        benign_commands = self.load_benign_corpus()
        print(f"  Loaded {len(benign_commands)} benign commands")

        print(f"\nRunning attack campaigns ({len(attacks)} attacks × {self.variants_per_attack} variants)...")
        for i, attack in enumerate(attacks, 1):
            print(f"  [{i}/{len(attacks)}] {attack['attack_id']}: {attack['description'][:60]}...")
            campaign_result = self.run_attack_campaign(attack)
            self.attack_results.append(campaign_result)

            if campaign_result['bypass_found']:
                print(f"    ⚠️  BYPASS FOUND via {campaign_result['successful_transformations']}")

        print(f"\nTesting benign commands ({len(benign_commands)} commands)...")
        for i, benign in enumerate(benign_commands, 1):
            print(f"  [{i}/{len(benign_commands)}] {benign['benign_id']}: {benign['description'][:60]}...")
            result = self.test_benign_command(benign)
            self.benign_results.append(result)

            if result.false_positive:
                print(f"    ⚠️  FALSE POSITIVE: {benign['command']}")

        print("\nComputing metrics...")
        metrics = self.compute_metrics()

        return {
            'evaluation_config': {
                'attack_corpus': str(self.attack_corpus_path),
                'benign_corpus': str(self.benign_corpus_path),
                'policy_profile': self.policy_profile,
                'variants_per_attack': self.variants_per_attack,
                'seed': self.seed
            },
            'metrics': asdict(metrics),
            'attack_results': self.attack_results,
            'benign_results': [asdict(r) for r in self.benign_results]
        }

    def export_json(self, results: Dict, output_path: Path):
        """Export results as JSON."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n✅ Results exported to {output_path}")

    def export_markdown(self, results: Dict, output_path: Path):
        """Export results as markdown report."""
        metrics = EvaluationMetrics(**results['metrics'])

        md = f"""# MVAR Adversarial Evaluation Report

**Policy Profile:** {results['evaluation_config']['policy_profile']}
**Attack Corpus:** {results['evaluation_config']['attack_corpus']}
**Benign Corpus:** {results['evaluation_config']['benign_corpus']}
**Variants Per Attack:** {results['evaluation_config']['variants_per_attack']}

---

## Summary Metrics

| Metric | Value | Target | Status |
|--------|-------|--------|--------|
| **Bypass Rate** | {metrics.bypass_rate:.2%} | < 10% | {'✅ PASS' if metrics.bypass_rate < 0.10 else '❌ FAIL'} |
| **False Positive Rate** | {metrics.false_positive_rate:.2%} | < 5% | {'✅ PASS' if metrics.false_positive_rate < 0.05 else '❌ FAIL'} |
| **p95 Latency** | {metrics.latency_p95_ms:.2f} ms | < 10ms | {'✅ PASS' if metrics.latency_p95_ms < 10 else '❌ FAIL'} |

---

## Attack Results

**Total Attacks:** {metrics.total_attacks}
**Total Variants Tested:** {metrics.total_variants}
**Bypasses:** {metrics.bypasses}
**Blocks:** {metrics.blocks}
**Bypass Rate:** {metrics.bypass_rate:.2%}

### Bypass Rate by Category

| Category | Bypass Rate |
|----------|-------------|
"""

        for category, rate in sorted(metrics.bypass_rate_by_category.items()):
            md += f"| {category} | {rate:.2%} |\n"

        md += f"""
---

## Benign Command Results

**Total Benign Commands:** {metrics.total_benign}
**False Positives:** {metrics.false_positives}
**False Positive Rate:** {metrics.false_positive_rate:.2%}

### False Positive Rate by Category

| Category | FP Rate |
|----------|---------|
"""

        for category, rate in sorted(metrics.false_positive_rate_by_category.items()):
            md += f"| {category} | {rate:.2%} |\n"

        md += f"""
---

## Latency Analysis

| Percentile | Latency (ms) |
|------------|--------------|
| p50 (median) | {metrics.latency_p50_ms:.2f} |
| p95 | {metrics.latency_p95_ms:.2f} |
| p99 | {metrics.latency_p99_ms:.2f} |
| mean | {metrics.latency_mean_ms:.2f} |

---

## Bypasses Found

"""

        bypassed_attacks = [r for r in results['attack_results'] if r['bypass_found']]

        if bypassed_attacks:
            for attack in bypassed_attacks:
                md += f"""
### {attack['attack_id']}: {attack['description']}

**Category:** {attack['category']}
**Severity:** {attack['severity']}
**Base Command:** `{attack['base_command']}`
**Successful Transformations:** {', '.join(attack['successful_transformations'])}
**Bypasses:** {attack['bypasses']}/{attack['variants_tested']}

"""
        else:
            md += "\n✅ **No bypasses found.**\n"

        md += """
---

## False Positives

"""

        false_positives = [r for r in results['benign_results'] if r['false_positive']]

        if false_positives:
            for fp in false_positives:
                md += f"""
### {fp['benign_id']}: {fp['command']}

**Category:** {fp['category']}
**Expected:** {fp['expected_decision']}
**Actual:** {fp['decision']}

"""
        else:
            md += "\n✅ **No false positives found.**\n"

        md += """
---

**Generated:** {timestamp}
**MVAR Version:** 1.5.4 (planned)
"""

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            f.write(md)
        print(f"✅ Markdown report exported to {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="MVAR Adversarial Evaluation Harness",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        '--attack-corpus',
        type=Path,
        required=True,
        help='Path to attack corpus JSON file'
    )

    parser.add_argument(
        '--benign-corpus',
        type=Path,
        required=True,
        help='Path to benign corpus JSON file'
    )

    parser.add_argument(
        '--policy-profile',
        type=str,
        default='strict',
        choices=['permissive', 'balanced', 'strict'],
        help='MVAR policy profile to test against'
    )

    parser.add_argument(
        '--variants-per-attack',
        type=int,
        default=10,
        help='Number of variants to generate per base attack'
    )

    parser.add_argument(
        '--output',
        type=Path,
        required=True,
        help='Output path for JSON results'
    )

    parser.add_argument(
        '--markdown',
        type=Path,
        help='Optional path for markdown report'
    )

    parser.add_argument(
        '--seed',
        type=int,
        default=42,
        help='Random seed for reproducibility'
    )

    args = parser.parse_args()

    # Initialize harness
    harness = EvaluationHarness(
        attack_corpus_path=args.attack_corpus,
        benign_corpus_path=args.benign_corpus,
        policy_profile=args.policy_profile,
        variants_per_attack=args.variants_per_attack,
        seed=args.seed
    )

    # Run evaluation
    print(f"\n{'='*80}")
    print("MVAR ADVERSARIAL EVALUATION")
    print(f"{'='*80}\n")

    results = harness.run_evaluation()

    # Export results
    harness.export_json(results, args.output)

    if args.markdown:
        harness.export_markdown(results, args.markdown)

    # Print summary
    metrics = EvaluationMetrics(**results['metrics'])

    print(f"\n{'='*80}")
    print("EVALUATION COMPLETE")
    print(f"{'='*80}\n")

    print(f"Bypass Rate: {metrics.bypass_rate:.2%} (target: < 10%)")
    print(f"False Positive Rate: {metrics.false_positive_rate:.2%} (target: < 5%)")
    print(f"p95 Latency: {metrics.latency_p95_ms:.2f} ms (target: < 10ms)")

    print(f"\nStatus:")
    print(f"  Bypass Rate: {'✅ PASS' if metrics.bypass_rate < 0.10 else '❌ FAIL'}")
    print(f"  False Positive Rate: {'✅ PASS' if metrics.false_positive_rate < 0.05 else '❌ FAIL'}")
    print(f"  Latency: {'✅ PASS' if metrics.latency_p95_ms < 10 else '❌ FAIL'}")

    overall_pass = (
        metrics.bypass_rate < 0.10 and
        metrics.false_positive_rate < 0.05 and
        metrics.latency_p95_ms < 10
    )

    print(f"\nOverall: {'✅ ALL TARGETS MET' if overall_pass else '❌ TARGETS NOT MET'}")


if __name__ == '__main__':
    main()
