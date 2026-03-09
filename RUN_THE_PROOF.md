# Run The Proof

Canonical operator runbook to verify MVAR in under 2 minutes.

## Quick Proof (2 minutes)

### Step 1 — Clone
```bash
git clone https://github.com/mvar-security/mvar
cd mvar
```

### Step 2 — Run proof pack
```bash
scripts/repro-validation-pack.sh
```

### Step 3 — Verify witness chain
```bash
mvar-verify-witness data/mvar_decisions.jsonl --require-chain
```

### Step 4 — Inspect artifacts
Expected artifact locations:

```text
artifacts/
artifacts/latest/
artifacts/<timestamp>/
```

### Step 5 — Confirm PASS signals
Expected output signals:

```text
launch gate PASS
attack corpus blocked
witness verification PASS
```

## What the proof pack validates

- Launch gate executes and reports PASS.
- Attack corpus execution is blocked under enforced policy.
- Validation summary is emitted in deterministic machine-readable form.
- Witness output is present for chain verification.

## Artifact structure

- `artifacts/latest/`: pointer to the most recent proof output.
- `artifacts/<timestamp>/`: immutable run-specific proof artifacts.
- `artifacts/`: parent directory holding current and historical proof outputs.

## Witness verification explanation

`mvar-verify-witness` validates signed witness records and, with `--require-chain`, verifies previous-signature linkage.

Pass means the witness file is structurally valid, signatures verify, and the chain integrity check succeeds.
