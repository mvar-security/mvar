# MVAR Installation Guide

**Get started in 3 minutes.**

---

## Prerequisites

- Python 3.10+ (3.11 or 3.12 recommended)
- pip package manager

Check your Python version:
```bash
python3 --version
```

---

## Installation

### Option 1: Install from Source (Current Recommended)

```bash
git clone https://github.com/mvar-security/mvar.git
cd mvar
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip setuptools wheel
python -m pip install .
```

### Option 2: Install from PyPI (After Publication)

```bash
pip install mvar
```

---

## Verify Installation

Run the quickstart example:

```bash
python -c "from mvar_core.provenance import ProvenanceGraph; print('✅ MVAR installed successfully')"
```

Or run the full demo:

```bash
python quickstart.py
```

You should see:
```
=== MVAR Quickstart Example ===

✓ Control plane initialized

Step 1: Provenance tracking
  User input: trusted / public
  External doc: untrusted / public
  Taint tags: {'prompt_injection_risk', 'external_content'}

Step 2: LLM processing (conservative propagation)
  LLM output integrity: untrusted
  → Inherited UNTRUSTED from external doc

Step 3: Sink policy decision
  Outcome: block
  Reason: Strict boundary denied target: shell metacharacters detected (strict execution boundary)
  QSEAL verified: True

✅ ATTACK BLOCKED
   Zero credentials exposed
   Zero code execution
   Full forensic trace available
```

---

## Run Full Demo

The OpenClaw CVE defense demo shows MVAR blocking a real prompt injection attack:

```bash
python demo/openclaw_cve_defense.py
```

---

## Next Steps

1. **Read the architecture:** [DESIGN_LINEAGE.md](DESIGN_LINEAGE.md)
2. **Explore the code:** Start with [quickstart.py](quickstart.py)
3. **Integration guide:** Coming in Phase 2 (post-launch)

---

## Troubleshooting

### ModuleNotFoundError: mvar_core

Ensure the package is installed:

```bash
pip install -e .
```

### Installation Issues

Upgrade packaging tools:

```bash
pip install --upgrade pip setuptools wheel
```

### Offline / Restricted Environments

If isolated build dependency resolution fails in your environment:

```bash
python -m pip install --no-build-isolation .
```

If needed, provision `pip`, `setuptools`, and `wheel` from your internal package mirror first.

### Ledger CLI says "Unable to initialize decision ledger"

If you enable ledger mode, set a signing secret in environments without MIRRA Ed25519 engine:

```bash
export MVAR_ENABLE_LEDGER=1
export QSEAL_SECRET=$(openssl rand -hex 32)
mvar-report
```

---

## System Requirements

- **Python:** 3.10+
- **Platforms:** macOS, Linux, Windows
- **Dependencies:** Installed automatically via pip

---

## Getting Help

- **Issues:** https://github.com/mvar-security/mvar/issues
- **Docs:** [README.md](README.md)
- **Architecture:** [DESIGN_LINEAGE.md](DESIGN_LINEAGE.md)

---

**License:** Apache 2.0
**Patent:** US Provisional #63/989,269 (Feb 24, 2026)
