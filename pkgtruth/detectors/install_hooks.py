"""Detector for dangerous install hooks and lifecycle script modifications."""

import json
from pathlib import Path
from typing import List

from pkgtruth.models import Finding

DANGEROUS_HOOKS = {"preinstall", "install", "postinstall", "prepublish", "prepare"}


def check_install_hooks(pkg_root: Path, src_root: Path) -> List[Finding]:
    """Flag newly added or modified install lifecycle scripts or Python .pth files."""
    findings: List[Finding] = []

    # 1. npm package.json scripts
    pkg_json_path = pkg_root / "package.json"
    src_json_path = src_root / "package.json"

    if pkg_json_path.exists():
        try:
            with open(pkg_json_path, "r", encoding="utf-8") as f:
                pkg_data = json.load(f)
            pkg_scripts = pkg_data.get("scripts", {})

            src_scripts = {}
            if src_json_path.exists():
                with open(src_json_path, "r", encoding="utf-8") as f:
                    src_data = json.load(f)
                src_scripts = src_data.get("scripts", {})

            for hook in DANGEROUS_HOOKS:
                pkg_hook_cmd = pkg_scripts.get(hook)
                src_hook_cmd = src_scripts.get(hook)

                if pkg_hook_cmd and not src_hook_cmd:
                    findings.append(Finding(
                        id="install_hook_added",
                        severity="high",
                        rule="install_hooks",
                        line=1,
                        snippet=f'"{hook}": "{pkg_hook_cmd}"',
                        reason=f"Dangerous install lifecycle script '{hook}' was added in published package.json but does not exist in source repository",
                        weight=40,
                    ))
                elif pkg_hook_cmd and src_hook_cmd and pkg_hook_cmd != src_hook_cmd:
                    findings.append(Finding(
                        id="install_hook_modified",
                        severity="high",
                        rule="install_hooks",
                        line=1,
                        snippet=f'"{hook}": "{pkg_hook_cmd}" (was: "{src_hook_cmd}")',
                        reason=f"Install lifecycle script '{hook}' was modified compared to source",
                        weight=40,
                    ))
        except Exception:
            pass

    # 2. Python .pth files (auto-executing on python startup)
    for pth in pkg_root.glob("**/*.pth"):
        rel_pth = str(pth.relative_to(pkg_root))
        src_match = src_root / rel_pth
        if not src_match.exists():
            findings.append(Finding(
                id="pth_file_added",
                severity="high",
                rule="install_hooks",
                line=1,
                snippet=pth.name,
                reason=f"New Python .pth file '{rel_pth}' added to package. Can execute arbitrary code on interpreter initialization.",
                weight=40,
            ))

    return findings
