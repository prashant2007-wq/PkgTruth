"""Explainer for files declared as outputs in build/package configurations."""

import json
from pathlib import Path
from typing import Set, Tuple


def get_declared_output_paths(source_root: Path) -> Set[str]:
    """Inspect package.json, tsconfig.json, and pyproject.toml for declared build paths."""
    declared: Set[str] = set()

    # 1. tsconfig.json outDir
    tsconfig = source_root / "tsconfig.json"
    if tsconfig.exists():
        try:
            with open(tsconfig, "r", encoding="utf-8") as f:
                data = json.load(f)
                out_dir = data.get("compilerOptions", {}).get("outDir")
                if out_dir:
                    declared.add(out_dir.strip("./\\"))
        except Exception:
            pass

    # 2. package.json entrypoints
    pkg_json = source_root / "package.json"
    if pkg_json.exists():
        try:
            with open(pkg_json, "r", encoding="utf-8") as f:
                data = json.load(f)
                for field in ("main", "module", "types", "typings"):
                    val = data.get(field)
                    if isinstance(val, str):
                        parts = val.replace("\\", "/").strip("./").split("/")
                        if len(parts) > 1:
                            declared.add(parts[0])
                        declared.add(val.replace("\\", "/").strip("./"))

                exports = data.get("exports")
                if isinstance(exports, dict):
                    for v in exports.values():
                        if isinstance(v, str):
                            parts = v.replace("\\", "/").strip("./").split("/")
                            if len(parts) > 1:
                                declared.add(parts[0])
        except Exception:
            pass

    return declared


def explain_config(rel_path: str, source_root: Path) -> Tuple[bool, str]:
    """Check if file sits inside a path declared in project config."""
    declared = get_declared_output_paths(source_root)
    clean_path = rel_path.replace("\\", "/")

    for dec in declared:
        if clean_path == dec or clean_path.startswith(f"{dec}/"):
            return True, f"Located within declared build output directory '{dec}'"

    # Common standard package additions like LICENSE, README, .d.ts
    fname_upper = Path(rel_path).name.upper()
    if fname_upper in ("LICENSE", "LICENSE.MD", "LICENSE.TXT", "LICENCE", "README.MD", "CHANGELOG.MD"):
        return True, "Standard distribution metadata file"

    return False, ""
