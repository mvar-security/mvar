# Troubleshooting

Use this guide when copy/pasting quickstart and verification commands.

## Fast Recovery (Recommended)

```bash
bash scripts/doctor-environment.sh
bash scripts/quick-verify.sh
```

These scripts validate path, venv, installability, tests, launch-gate, and scorecard output.

## Common Errors and Fixes

### 1) `No such file or directory: ./scripts/launch-gate.sh`

Cause: Running commands from a parent repo instead of the `mvar` repo root.

Fix:
```bash
cd /path/to/mvar
```

### 2) `can't open file scripts/generate_security_scorecard.py`

Cause: Same as above (wrong working directory).

Fix:
```bash
cd /path/to/mvar
python scripts/generate_security_scorecard.py
```

### 3) `pytest` loads unrelated tests (e.g., Transformers / Mistral failures)

Cause: Running `pytest` in a different project root (for example a mono-repo root) where other tests exist.

Fix:
```bash
cd /path/to/mvar
python -m pytest -q
```

### 4) `fatal: destination path 'mvar' already exists and is not an empty directory`

Cause: Clone target already exists.

Fix:
```bash
rm -rf /tmp/mvar-quickcheck
git clone https://github.com/mvar-security/mvar.git /tmp/mvar-quickcheck
```

### 5) `No module named pip.__main__` or pip bootstrap errors

Cause: Broken venv or invalid current directory state.

Fix:
```bash
cd ~
rm -rf /tmp/mvar-quickcheck
git clone https://github.com/mvar-security/mvar.git /tmp/mvar-quickcheck
cd /tmp/mvar-quickcheck
python3 -m venv .venv
source .venv/bin/activate
python -m ensurepip --upgrade
python -m pip install -U pip setuptools wheel
```

### 6) `FileNotFoundError: os.getcwd()` from pip/ensurepip

Cause: Current working directory was deleted while shell stayed open.

Fix:
```bash
cd ~
```
Then rerun setup commands.

### 7) Offline/restricted network install failures (`setuptools>=68` not found)

Cause: Build isolation needs packages not available from public index.

Fix options:
- Use internal mirror for `pip/setuptools/wheel` and dependencies.
- Retry with no build isolation:

```bash
python -m pip install --no-build-isolation .
```

## Canonical Validation Commands

From the `mvar` repo root:

```bash
python -m pytest -q
./scripts/launch-gate.sh
python scripts/generate_security_scorecard.py
python scripts/update_status_md.py
```

Expected for `v1.2.0` baseline:
- `261 passed`
- launch gate: PASS
- attack corpus: `50/50 blocked`
- benign corpus: `200/200 passed`, `0 false blocks`
