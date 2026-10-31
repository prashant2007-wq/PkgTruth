"""Explainer for metadata-only differences in package.json or setup metadata."""

import json
from pathlib import Path
from typing import Tuple

PUBLISH_TIME_FIELDS = {
    "_id",
    "_from",
    "_nodeVersion",
    "_npmVersion",
    "_npmUser",
    "_hasShrinkwrap",
    "_shasum",
    "_integrity",
    "_resolved",
    "dist",
    "gitHead",
    "deprecated",
    "readme",
    "readmeFilename",
}


def explain_metadata_only(pkg_file: Path, src_file: Path) -> Tuple[bool, str]:
    """Check if differences between package.json files are solely publish-time metadata."""
    if pkg_file.name != "package.json":
        return False, ""

    if not src_file.exists():
        return False, ""

    try:
        with open(pkg_file, "r", encoding="utf-8") as f:
            pkg_data = json.load(f)
        with open(src_file, "r", encoding="utf-8") as f:
            src_data = json.load(f)
    except Exception:
        return False, ""

    # Check non-publish-time fields
    all_keys = set(pkg_data.keys()) | set(src_data.keys())
    for k in all_keys:
        if k in PUBLISH_TIME_FIELDS:
            continue
        # If fields like scripts or dependencies differ, it's not metadata-only
        if pkg_data.get(k) != src_data.get(k):
            return False, ""

    return True, "Differences strictly confined to standard npm publish-time metadata fields"
