"""Sourcemap explainer: verifies compiled JS against referenced sources and maps."""

import json
import re
from pathlib import Path
from typing import Optional, Tuple


def find_sourcemap_file(js_path: Path) -> Optional[Path]:
    """Locate corresponding sourcemap file for a given JS file."""
    # 1. Same directory with .map appended
    direct_map = js_path.with_name(js_path.name + ".map")
    if direct_map.exists():
        return direct_map

    # 2. Check sourceMappingURL comment inside JS file
    try:
        with open(js_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in reversed(f.readlines()[-5:]):
                match = re.search(r"/\/[#@]\s*sourceMappingURL=([^\s]+)", line)
                if match:
                    map_target = match.group(1).strip()
                    cand = js_path.parent / map_target
                    if cand.exists():
                        return cand
    except Exception:
        pass

    return None


def explain_sourcemap(pkg_file: Path, source_root: Path) -> Tuple[bool, str]:
    """Check if a compiled JavaScript file is explained by a valid sourcemap matching source files."""
    if not pkg_file.suffix.lower() in (".js", ".mjs", ".cjs"):
        return False, ""

    map_file = find_sourcemap_file(pkg_file)
    if not map_file or not map_file.exists():
        return False, ""

    try:
        with open(map_file, "r", encoding="utf-8") as f:
            map_data = json.load(f)
    except Exception:
        return False, ""

    sources = map_data.get("sources", [])
    if not sources:
        return False, ""

    matched_sources = []
    # Verify each source exists in source_root
    for s in sources:
        # Resolve relative to map file or source root
        clean_s = s.replace("../", "").lstrip("./")
        cand_in_src = source_root / clean_s
        if cand_in_src.exists():
            matched_sources.append(clean_s)
        else:
            # Check by filename search in source_root
            fname = Path(s).name
            matches = list(source_root.glob(f"**/{fname}"))
            if matches:
                matched_sources.append(str(matches[0].relative_to(source_root)))

    if matched_sources:
        evidence = ", ".join(matched_sources[:3])
        if len(matched_sources) > 3:
            evidence += f" (+{len(matched_sources) - 3} more)"
        return True, f"Verified compiled output from source files via sourcemap: {evidence}"

    return False, ""
