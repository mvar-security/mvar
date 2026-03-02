#!/usr/bin/env python3
"""Check release metadata consistency inside the repo."""

from __future__ import annotations

import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SETUP_FILE = REPO_ROOT / "setup.py"
INIT_FILE = REPO_ROOT / "mvar-core" / "__init__.py"


def _extract(pattern: str, text: str, label: str) -> str:
    match = re.search(pattern, text, re.MULTILINE)
    if not match:
        raise RuntimeError(f"could not find {label}")
    return match.group(1)


def main() -> int:
    setup_text = SETUP_FILE.read_text(encoding="utf-8")
    init_text = INIT_FILE.read_text(encoding="utf-8")

    setup_version = _extract(r'version\s*=\s*"([^"]+)"', setup_text, "setup version")
    core_version = _extract(r'__version__\s*=\s*"([^"]+)"', init_text, "core version")

    if setup_version != core_version:
        raise RuntimeError(
            f"release integrity mismatch: setup.py={setup_version} mvar-core/__init__.py={core_version}"
        )

    print(f"release integrity check: PASS (version {setup_version})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
