"""Historical release pattern analysis to detect anomalous deviations."""

from typing import Dict, List, Optional
import requests


class ReleaseBaseline:
    """Historical profile of an npm/PyPI package across previous releases."""

    def __init__(self, package_name: str, ecosystem: str = "npm"):
        self.package_name = package_name
        self.ecosystem = ecosystem
        self.had_install_scripts: List[bool] = []
        self.had_provenance: List[bool] = []
        self.has_dist_folder: List[bool] = []

    def load_recent_versions(self, count: int = 5) -> bool:
        """Fetch historical release metadata from registry."""
        if self.ecosystem != "npm":
            return False

        try:
            url = f"https://registry.npmjs.org/{self.package_name}"
            resp = requests.get(url, timeout=10)
            if resp.status_code != 200:
                return False

            data = resp.json()
            versions = data.get("versions", {})
            version_keys = list(versions.keys())[-count:]

            for v in version_keys:
                v_meta = versions.get(v, {})
                scripts = v_meta.get("scripts", {})
                has_hooks = any(h in scripts for h in ("preinstall", "install", "postinstall"))
                self.had_install_scripts.append(has_hooks)

                dist = v_meta.get("dist", {})
                self.had_provenance.append("attestations" in dist)
            return True
        except Exception:
            return False

    def detect_pattern_breaks(
        self,
        current_has_hooks: bool,
        current_has_provenance: bool
    ) -> List[str]:
        """Compare current release characteristics against historical baselines."""
        breaks = []

        # 1. First-ever install lifecycle script
        if current_has_hooks and self.had_install_scripts:
            if not any(self.had_install_scripts):
                breaks.append("First-ever install script added: package never had install hooks across prior releases")

        # 2. Provenance downgrade
        if not current_has_provenance and self.had_provenance:
            if all(self.had_provenance[-3:]) and len(self.had_provenance) >= 3:
                breaks.append("Provenance downgrade: prior consecutive releases included verified attestations")

        return breaks
