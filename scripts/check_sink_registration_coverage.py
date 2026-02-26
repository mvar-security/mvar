#!/usr/bin/env python3
"""Fail if literal policy.evaluate(tool, action, ...) calls reference unregistered sinks."""

from __future__ import annotations

import ast
import sys
from pathlib import Path
from typing import Iterable, Optional

REPO_ROOT = Path(__file__).resolve().parents[1]
SINK_POLICY_FILE = REPO_ROOT / "mvar-core" / "sink_policy.py"
INTENTIONAL_UNREGISTERED = {
    # Intentional fail-closed demo case in demo/live_exploit_attempts.py
    ("custom_evil_tool", "pwn"),
}


def _const_str(node: Optional[ast.AST]) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _extract_registered_pairs(tree: ast.AST) -> set[tuple[str, str]]:
    pairs: set[tuple[str, str]] = set()

    class Visitor(ast.NodeVisitor):
        def visit_Call(self, node: ast.Call) -> None:
            if isinstance(node.func, ast.Name) and node.func.id == "SinkClassification":
                tool = None
                action = None
                for kw in node.keywords:
                    if kw.arg == "tool":
                        tool = _const_str(kw.value)
                    elif kw.arg == "action":
                        action = _const_str(kw.value)
                if tool and action:
                    pairs.add((tool, action))
            self.generic_visit(node)

    Visitor().visit(tree)
    return pairs


def _extract_evaluate_pairs(tree: ast.AST) -> set[tuple[str, str]]:
    pairs: set[tuple[str, str]] = set()

    class Visitor(ast.NodeVisitor):
        def visit_Call(self, node: ast.Call) -> None:
            if isinstance(node.func, ast.Attribute) and node.func.attr == "evaluate":
                tool = None
                action = None

                kw = {k.arg: k.value for k in node.keywords if k.arg}
                if "tool" in kw:
                    tool = _const_str(kw["tool"])
                if "action" in kw:
                    action = _const_str(kw["action"])

                if tool is None and len(node.args) >= 1:
                    tool = _const_str(node.args[0])
                if action is None and len(node.args) >= 2:
                    action = _const_str(node.args[1])

                if tool and action:
                    pairs.add((tool, action))
            self.generic_visit(node)

    Visitor().visit(tree)
    return pairs


def _iter_python_files(root: Path) -> Iterable[Path]:
    # Focus on user-facing execution surfaces, not test-only synthetic tools.
    scan_paths = [
        root / "demo",
        root / "examples",
        root / "mvar_adapters",
        root / "quickstart.py",
    ]
    for item in scan_paths:
        if item.is_file() and item.suffix == ".py":
            yield item
            continue
        if item.is_dir():
            for path in item.rglob("*.py"):
                parts = set(path.parts)
                if {"__pycache__"} & parts:
                    continue
                yield path


def main() -> int:
    sink_tree = ast.parse(SINK_POLICY_FILE.read_text(encoding="utf-8"), filename=str(SINK_POLICY_FILE))
    registered = _extract_registered_pairs(sink_tree)

    used: set[tuple[str, str]] = set()
    for py in _iter_python_files(REPO_ROOT):
        tree = ast.parse(py.read_text(encoding="utf-8"), filename=str(py))
        used.update(_extract_evaluate_pairs(tree))

    missing = sorted((used - registered) - INTENTIONAL_UNREGISTERED)

    print(f"registered sink pairs: {len(registered)}")
    print(f"literal evaluate sink pairs observed: {len(used)}")

    if missing:
        print("\nERROR: evaluate(...) pairs missing from register_common_sinks:")
        for tool, action in missing:
            print(f"  - {tool}:{action}")
        return 1

    print("sink registration coverage check: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
