"""Detector for unauthorized, URL, or typosquatted dependency additions."""

import json
from pathlib import Path
from typing import Dict, List

from pkgtruth.models import Finding


def levenshtein_distance(s1: str, s2: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def check_dependencies(pkg_root: Path, src_root: Path) -> List[Finding]:
    """Flag new dependencies, git/URL specs, or potential typosquats."""
    findings: List[Finding] = []

    pkg_json = pkg_root / "package.json"
    src_json = src_root / "package.json"

    if not pkg_json.exists():
        return findings

    try:
        with open(pkg_json, "r", encoding="utf-8") as f:
            pkg_data = json.load(f)
        src_data = {}
        if src_json.exists():
            with open(src_json, "r", encoding="utf-8") as f:
                src_data = json.load(f)

        dep_sections = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]
        for section in dep_sections:
            pkg_deps = pkg_data.get(section, {})
            src_deps = src_data.get(section, {})
            if not isinstance(pkg_deps, dict):
                continue

            for dep_name, version_spec in pkg_deps.items():
                if dep_name not in src_deps:
                    # New dependency
                    findings.append(Finding(
                        id="new_dependency",
                        severity="medium",
                        rule="deps",
                        line=1,
                        snippet=f'"{dep_name}": "{version_spec}"',
                        reason=f"New dependency '{dep_name}' added to {section} not present in source repository",
                        weight=15,
                    ))
                    findings.append(Finding(
                        id="string_not_in_source",
                        severity="medium",
                        rule="deps",
                        line=1,
                        snippet=f'"{dep_name}"',
                        reason=f"Novel dependency name '{dep_name}' not present in source configuration",
                        weight=20,
                    ))

                # Check for git/http/tarball URLs in dependency versions
                if isinstance(version_spec, str):
                    if any(prefix in version_spec for prefix in ("git://", "git+ssh://", "git+http", "http://", "https://", ".tar.gz", ".tgz")):
                        findings.append(Finding(
                            id="url_dependency",
                            severity="high",
                            rule="deps",
                            line=1,
                            snippet=f'"{dep_name}": "{version_spec}"',
                            reason=f"Dependency '{dep_name}' points directly to external URL/git target '{version_spec}'",
                            weight=20,
                        ))

            # Check typosquatting against other existing dependencies
            all_known = list(src_deps.keys())
            for dep_name in pkg_deps.keys():
                if dep_name not in src_deps:
                    for known in all_known:
                        dist = levenshtein_distance(dep_name, known)
                        if 1 <= dist <= 2 and len(dep_name) > 4:
                            findings.append(Finding(
                                id="typosquat_dependency",
                                severity="high",
                                rule="deps",
                                line=1,
                                snippet=f'"{dep_name}" (similar to "{known}")',
                                reason=f"Newly added dependency '{dep_name}' closely resembles existing dependency '{known}' (edit distance {dist})",
                                weight=25,
                            ))
                            break

    except Exception:
        pass

    return findings
