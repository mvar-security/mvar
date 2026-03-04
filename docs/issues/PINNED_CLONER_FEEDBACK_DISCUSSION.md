# Pinned Discussion Draft: If You Cloned MVAR, What Blocked Adoption?

Use this as the body for a pinned GitHub Discussion.

## Suggested title
`If you cloned MVAR, what blocked adoption in your stack?`

## Suggested body
If you cloned MVAR recently, we want direct feedback on adoption friction.

Please share:
1. Your stack (LangChain/OpenAI/Claude/MCP/custom).
2. Where integration slowed down (API shape, docs, deployment, CI, policy tuning).
3. What would make this a same-day production trial.

Helpful details:
- commit/tag used
- exact command you ran
- expected vs actual behavior
- logs/traces (if available)

Quick baseline commands:
```bash
pytest -q
./scripts/launch-gate.sh
python3 scripts/generate_security_scorecard.py
python3 scripts/update_status_md.py
```

Current reproducible baseline:
- 267 tests passing
- 50/50 adversarial vectors blocked
- 200/200 benign corpus passing (0 false blocks)

If you found a bypass or policy gap, please also open a dedicated break-attempt issue using:
- `.github/ISSUE_TEMPLATE/break_mvar.md`

We prioritize:
- reproducible reports
- failing regression tests
- adapter-specific integration blockers
