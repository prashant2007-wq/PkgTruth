"""Watchlist release monitor for scheduled CI jobs and automated checks."""

import os
import sys
from pathlib import Path
from typing import Dict, List, Tuple

import yaml

from pkgtruth.models import Report


def load_watchlist(watchlist_path: Path) -> dict:
    """Load and parse watchlist YAML file."""
    if not watchlist_path.exists():
        raise FileNotFoundError(f"Watchlist file not found: {watchlist_path}")
    with open(watchlist_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def run_watchlist(watchlist_path: Path, no_llm_override: bool = False) -> int:
    """Analyze all packages configured in watchlist.
    
    Returns:
        Max exit code encountered across all analyzed packages:
        0 = all LOW, 1 = MEDIUM encountered, 2 = HIGH encountered.
    """
    from pkgtruth.cli import run_npm_analysis

    data = load_watchlist(watchlist_path)
    packages = data.get("packages", [])
    settings = data.get("settings", {})

    output_dir = Path(settings.get("output_dir", "./reports"))
    output_dir.mkdir(parents=True, exist_ok=True)

    no_llm = no_llm_override or settings.get("no_llm", False)
    fail_on = settings.get("fail_on", "medium").lower()

    max_exit_code = 0

    print(f"Monitoring {len(packages)} packages from {watchlist_path}...")
    for pkg in packages:
        name = pkg.get("name")
        version = pkg.get("version", "latest")
        ecosystem = pkg.get("ecosystem", "npm")

        if ecosystem != "npm":
            print(f"Skipping unsupported monitor ecosystem '{ecosystem}' for {name}")
            continue

        print(f"--> Checking {name}@{version}...")
        report_file = output_dir / f"{name.replace('/', '_')}-report.json"
        
        try:
            exit_code = run_npm_analysis(
                package_name=name,
                version=version,
                json_out=str(report_file),
                no_llm=no_llm,
                offline=False,
                fail_on=fail_on
            )
            max_exit_code = max(max_exit_code, exit_code)
        except Exception as e:
            print(f"Error checking {name}: {e}")
            max_exit_code = max(max_exit_code, 3)

    return max_exit_code
