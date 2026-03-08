# Demos and Testbeds

This page collects reproducible demos that show MVAR behavior under benign and adversarial inputs.

## 10-Second Attack Demo

Run the same agent behavior with and without execution-boundary enforcement.

![MVAR One-Line Integration](../../assets/mvar-one-line-integration.png)
![MVAR Attack Demo](../../assets/demo.gif)

```bash
bash scripts/run-agent-testbed.sh --scenario rag_injection
```

```powershell
pwsh -File .\scripts\run-agent-testbed.ps1 --scenario rag_injection
```

Expected output shape:

```text
Baseline: ALLOW -> executing bash command
MVAR:    BLOCK -> UNTRUSTED input reaching CRITICAL sink
```

## Agent Testbed Trilogy

Run all three canonical scenarios:

```bash
bash scripts/run-agent-testbed.sh --scenario rag_injection
bash scripts/run-agent-testbed.sh --scenario taint_laundering
bash scripts/run-agent-testbed.sh --scenario benign
```

Expected outcomes:

| Scenario | Baseline | MVAR |
|---|---|---|
| `rag_injection` | ALLOW + simulated execution | BLOCK + no execution |
| `taint_laundering` | ALLOW + simulated execution | BLOCK + no execution |
| `benign` | ALLOW + simulated execution | ALLOW + simulated execution |

## Governed MCP Runtime Proof

For governed runtime proof artifacts (envelope + policy + evidence chain), see:

- [../outreach/GOVERNED_MCP_RUNTIME_PROOF.md](../outreach/GOVERNED_MCP_RUNTIME_PROOF.md)

## Related Validation Docs

- [../AGENT_TESTBED.md](../AGENT_TESTBED.md)
- [../ATTACK_VALIDATION_SHOWCASE.md](../ATTACK_VALIDATION_SHOWCASE.md)
