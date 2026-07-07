#!/usr/bin/env python3
"""Public/private boundary gate (EVAL/04_TARGET_ARCHITECTURE.md §6, hard rule 3).

Fails (exit 1) if any PUBLIC package's source or docs reference MIRRA EOS private-brain
internals. Public packages (MVAR, ClawZero, ClawSeal) must depend only on the generic
core contract — never on private identity/emotion/cognition concepts. The private brain
implements the CapabilityProvider interface and is injected at runtime.

Usage:
    python check_public_private_boundary.py <public_pkg_dir> [<public_pkg_dir> ...]

Intended to run in each public repo's CI. Exit 0 = clean, 1 = leak found.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# Private-brain concepts that must NOT appear in public package source/docs. Word-boundary
# matched to avoid false hits (e.g. "pad" inside "keypad"). Kept deliberately specific.
FORBIDDEN_PATTERNS = [
    r"\bMIRRA[_ ]?EOS\b",
    r"\bentry[_ ]?500\b",
    r"\bentry_5\d\d\b",
    r"\bsoulprint\b",
    r"\bPAD\s+(?:state|substrate|emotional)\b",
    r"\barchetype\b",
    r"\brebirth\b",
    r"\bconsciousness[_ ]?(?:loop|substrate|equation|intensity)\b",
    r"\bbecoming[_ ]?continuity\b",
    r"\bmirra_core\.consciousness\b",
]

# Files/dirs to skip: build artifacts, deps, VCS, and this gate's own allowlist docs.
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "build", "dist", "__pycache__",
             ".pytest_cache", "site", "_archive"}
SCAN_EXT = {".py", ".md", ".txt", ".toml", ".cfg", ".json", ".yaml", ".yml", ".rst"}
# Neutral capability-provider references are allowed (the contract interface is generic).
# A line may also opt out explicitly with a "boundary-policy-ok" marker — used ONLY where a
# doc/comment must NAME the forbidden concepts in order to STATE the boundary rule itself.
ALLOW_SUBSTR = (
    "CapabilityProvider", "capability provider", "capability_provider",
    "boundary-policy-ok",
)


def scan(root: Path) -> list[tuple[str, int, str]]:
    hits: list[tuple[str, int, str]] = []
    regexes = [re.compile(p, re.IGNORECASE) for p in FORBIDDEN_PATTERNS]
    for path in root.rglob("*"):
        if path.is_dir() or path.suffix.lower() not in SCAN_EXT:
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception:
            continue
        for i, line in enumerate(lines, 1):
            if any(a in line for a in ALLOW_SUBSTR):
                continue
            for rx in regexes:
                if rx.search(line):
                    hits.append((str(path), i, line.strip()[:120]))
                    break
    return hits


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: check_public_private_boundary.py <public_pkg_dir> [...]", file=sys.stderr)
        return 2
    total = 0
    for target in argv[1:]:
        root = Path(target)
        if not root.exists():
            print(f"skip (missing): {target}")
            continue
        hits = scan(root)
        if hits:
            print(f"LEAK in {target}: {len(hits)} reference(s) to private-brain concepts")
            for f, ln, txt in hits[:40]:
                print(f"  {f}:{ln}: {txt}")
            total += len(hits)
        else:
            print(f"clean: {target}")
    if total:
        print(f"\nFAIL: {total} public/private boundary leak(s) found.")
        return 1
    print("\nPASS: no private-brain concepts leaked into public packages.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
