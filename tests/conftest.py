from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _bootstrap_mvar_core_from_source() -> None:
    if importlib.util.find_spec("mvar_core.capability") is not None:
        return

    repo_root = Path(__file__).resolve().parents[1]
    source_pkg = repo_root / "mvar-core"
    init_py = source_pkg / "__init__.py"
    if not init_py.exists():
        return

    spec = importlib.util.spec_from_file_location(
        "mvar_core",
        init_py,
        submodule_search_locations=[str(source_pkg)],
    )
    if spec is None or spec.loader is None:
        return

    sys.modules.pop("mvar_core", None)
    module = importlib.util.module_from_spec(spec)
    sys.modules["mvar_core"] = module
    spec.loader.exec_module(module)


_bootstrap_mvar_core_from_source()
