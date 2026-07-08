"""Static reachable-sink analysis over a tool callable's own module.

LOCAL-ONLY by hard constraint: pure ``ast`` parsing of source already on disk,
bounded breadth-first reachability over the module-internal call graph. No
external API, no semantic extraction, no network — the analyzed source never
leaves the process. Zero non-stdlib dependencies (bounded BFS over a dict
adjacency needs no graph library).

Scope (v0.1, stated plainly): *reachability*, not data-flow. Sound for
statically-resolvable, same-module call chains; best-effort past dynamic
boundaries — getattr-computed calls and dynamic imports are surfaced as a
``dynamic_dispatch`` flag rather than a false all-clear. Cross-module
first-party helpers (``from mymodule import helper``) are out of v0.1 scope.
"""

from __future__ import annotations

import ast
import inspect
from typing import Any, Optional

from mvar.structural import sinks as _sinks

_WRITE_MODE_CHARS = set("wax+")


def _import_aliases(tree: ast.AST) -> dict[str, str]:
    """Map local alias -> dotted origin for every import in the module."""
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                local = a.asname or a.name.split(".")[0]
                aliases[local] = a.name if a.asname else a.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            for a in node.names:
                aliases[a.asname or a.name] = f"{node.module}.{a.name}"
    return aliases


def _function_index(tree: ast.AST) -> dict[str, list[ast.AST]]:
    index: dict[str, list[ast.AST]] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            index.setdefault(node.name, []).append(node)
    return index


def _dotted_name(node: ast.AST) -> Optional[str]:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _resolve(dotted: str, aliases: dict[str, str]) -> str:
    root, _, rest = dotted.partition(".")
    origin = aliases.get(root)
    if origin is None:
        return dotted
    return f"{origin}.{rest}" if rest else origin


def _open_is_write(call: ast.Call) -> bool:
    mode: Optional[ast.expr] = None
    if len(call.args) >= 2:
        mode = call.args[1]
    for kw in call.keywords:
        if kw.arg == "mode":
            mode = kw.value
    if mode is None:
        return False  # default mode "r"
    if isinstance(mode, ast.Constant) and isinstance(mode.value, str):
        return bool(set(mode.value) & _WRITE_MODE_CHARS)
    return True  # non-literal mode: over-approximate toward write


def analyze_callable(tool_fn: Any, *, hop_limit: int = 6, node_budget: int = 500) -> Optional[dict[str, Any]]:
    """Derive the reachable-sink set for a callable. Returns None when the
    source cannot be analyzed (derivation absence -> callers fall back to
    flat enforcement; this function raising is treated the same way)."""
    fn = inspect.unwrap(tool_fn)
    code = getattr(fn, "__code__", None)
    source_file = inspect.getsourcefile(fn)
    if code is None or source_file is None:
        return None
    with open(source_file, "r", encoding="utf-8", errors="replace") as fh:
        tree = ast.parse(fh.read())

    aliases = _import_aliases(tree)
    functions = _function_index(tree)
    candidates = functions.get(fn.__name__, [])
    if not candidates:
        return None
    entry = min(candidates, key=lambda n: abs(n.lineno - code.co_firstlineno))

    reachable: dict[str, dict[str, Any]] = {}
    dynamic_dispatch = False
    visited: set[int] = set()
    queue: list[tuple[ast.AST, list[str]]] = [(entry, [fn.__name__])]

    while queue:
        func_node, path = queue.pop(0)
        if id(func_node) in visited or len(visited) >= node_budget:
            continue
        visited.add(id(func_node))

        for node in ast.walk(func_node):
            if isinstance(node, ast.Call):
                # getattr(...)(...) / __import__ / importlib.import_module
                inner = node.func
                if isinstance(inner, ast.Call) and isinstance(inner.func, ast.Name) and inner.func.id == "getattr":
                    dynamic_dispatch = True
                    continue
                dotted = _dotted_name(inner)
                if dotted is None:
                    continue
                if dotted in ("__import__", "importlib.import_module"):
                    dynamic_dispatch = True
                    continue
                if "." not in dotted:
                    name = dotted
                    if name in _sinks.NAME_SINKS:
                        reachable.setdefault(_sinks.NAME_SINKS[name], {"sink": name, "path": path + [name]})
                        continue
                    if name == "open":
                        if _open_is_write(node):
                            reachable.setdefault(_sinks.FS_WRITE, {"sink": "open", "path": path + ["open"]})
                        continue
                    if name == "getattr" and len(node.args) >= 2 and not isinstance(node.args[1], ast.Constant):
                        dynamic_dispatch = True
                        continue
                resolved = _resolve(dotted, aliases)
                cls = _sinks.classify_dotted(resolved)
                if cls is not None:
                    reachable.setdefault(cls, {"sink": resolved, "path": path + [resolved]})
                    continue
                # same-module helper call -> follow the edge (bounded)
                if "." not in dotted and dotted in functions and len(path) < hop_limit:
                    for callee in functions[dotted]:
                        queue.append((callee, path + [dotted]))
            elif isinstance(node, ast.Attribute):
                dotted = _dotted_name(node)
                if dotted is not None:
                    resolved = _resolve(dotted, aliases)
                    for read_name, cls in _sinks.ATTRIBUTE_READ_SINKS.items():
                        if resolved == read_name or resolved.startswith(read_name + "."):
                            reachable.setdefault(cls, {"sink": read_name, "path": path + [read_name]})

    return {
        "version": 1,
        "analyzer": "ast/0.1",
        "tool": f"{getattr(fn, '__module__', '?')}.{getattr(fn, '__qualname__', fn.__name__)}",
        "reachable_sinks": reachable,
        "dynamic_dispatch": dynamic_dispatch,
        "hop_limit": hop_limit,
    }
