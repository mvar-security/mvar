# GitHub Pinned Post: 30-Second Proof

Use this in a pinned issue/discussion or repo announcement.

---

**Start here in 30 seconds**

MVAR is deterministic security for AI agents.

Invariant: `UNTRUSTED input + CRITICAL sink -> BLOCK`

```bash
git clone https://github.com/mvar-security/mvar.git
cd mvar
bash scripts/install.sh
bash scripts/run-agent-testbed.sh --scenario rag_injection
```

Expected output:

```text
Baseline: ALLOW -> executing bash command
MVAR:    BLOCK -> UNTRUSTED input reaching CRITICAL sink
```

What this proves:

- benign tool use still works
- adversarial prompt-injection paths are blocked before execution
- deterministic policy decisions are emitted with auditable metadata

Full governed MCP proof:
[docs/outreach/GOVERNED_MCP_RUNTIME_PROOF.md](./GOVERNED_MCP_RUNTIME_PROOF.md)

If you can reproduce a bypass, open an issue with a minimal vector:
[docs/ATTACK_VECTOR_SUBMISSIONS.md](../ATTACK_VECTOR_SUBMISSIONS.md)
