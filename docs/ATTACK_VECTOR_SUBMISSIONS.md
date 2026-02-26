# Community Attack Vector Submissions

MVAR accepts adversarial vector submissions to expand the public validation corpus.

## Submission format

Use the JSON schema in:

- `conformance/community_attack_vector_schema.json`

Minimum fields per vector:

- `id`
- `description`
- `payload`
- `sink.tool`
- `sink.action`
- `expected_outcome` (`ALLOW` | `BLOCK` | `STEP_UP`)

## Local verification

Run your submission through the community harness before opening a PR:

```bash
python conformance/community_attack_harness.py path/to/submission.json
```

## PR requirements

1. Include your submission JSON in `tests/community_vectors/`.
2. Include harness output in the PR description.
3. Explain why the vector class is novel or not already represented in `demo/extreme_attack_suite_50.py`.
4. Confirm expected outcome rationale under current sink configuration.

## Scope note

Vector acceptance does not imply universal coverage. Contributions are evaluated against the current threat model and policy assumptions in `THREAT_MODEL.md`.
