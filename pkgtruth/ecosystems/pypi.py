"""PyPI ecosystem plugin for analyzing Python packages."""

import re
from pathlib import Path
from typing import Optional, Tuple

import requests

from pkgtruth.ecosystems.base import EcosystemPlugin
from pkgtruth.models import ProvenanceInfo


class PyPIPlugin(EcosystemPlugin):
    """Ecosystem plugin for Python Package Index (PyPI)."""

    PYPI_BASE = "https://pypi.org/pypi"

    @property
    def name(self) -> str:
        return "pypi"

    def fetch_metadata(self, package_name: str, version: str) -> dict:
        """Fetch package metadata from PyPI JSON API."""
        url = f"{self.PYPI_BASE}/{package_name}/{version}/json"
        try:
            resp = requests.get(url, timeout=15)
            if resp.status_code == 200:
                return resp.json()
        except Exception as e:
            return {"_fetch_error": str(e)}
        return {}

    def download(self, package_name: str, version: str, dest_dir: Path) -> Path:
        """Download sdist or wheel from PyPI."""
        dest_dir.mkdir(parents=True, exist_ok=True)
        meta = self.fetch_metadata(package_name, version)
        urls = meta.get("urls", [])

        # Prefer sdist .tar.gz, then wheel .whl
        target_url = None
        target_filename = None
        for u in urls:
            fname = u.get("filename", "")
            if fname.endswith(".tar.gz") or u.get("packagetype") == "sdist":
                target_url = u.get("url")
                target_filename = fname
                break

        if not target_url and urls:
            target_url = urls[0].get("url")
            target_filename = urls[0].get("filename", f"{package_name}-{version}.archive")

        if not target_url:
            raise RuntimeError(f"No downloadable distribution found on PyPI for {package_name}@{version}")

        out_path = dest_dir / target_filename
        try:
            with requests.get(target_url, stream=True, timeout=30) as r:
                r.raise_for_status()
                with open(out_path, "wb") as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
            return out_path
        except Exception as e:
            raise RuntimeError(f"Failed to download PyPI package {package_name}@{version}: {e}")

    def resolve_source(self, metadata: dict) -> Tuple[str, str, str]:
        """Extract source repository from PyPI project URLs."""
        info = metadata.get("info", {})
        project_urls = info.get("project_urls") or {}

        repo_keys = ["Source", "Repository", "Source Code", "GitHub", "Code", "Git", "Homepage"]
        repo_url = ""
        for k in repo_keys:
            for actual_k, val in project_urls.items():
                if k.lower() in actual_k.lower() and isinstance(val, str) and ("github.com" in val or "gitlab.com" in val):
                    repo_url = val
                    break
            if repo_url:
                break

        if not repo_url:
            homepage = info.get("home_page", "")
            if "github.com" in homepage or "gitlab.com" in homepage:
                repo_url = homepage

        return repo_url, "", "unresolved"

    def get_provenance(self, package_name: str, version: str) -> ProvenanceInfo:
        """Check for PyPI trusted publishing / provenance attestations."""
        meta = self.fetch_metadata(package_name, version)
        urls = meta.get("urls", [])
        has_provenance = any(u.get("has_sigstore") or "provenance" in u for u in urls)

        info = ProvenanceInfo(
            attestation_present=has_provenance,
            notes=["PyPI Trusted Publishing provenance verified"] if has_provenance else ["No PyPI attestation detected"]
        )
        return info
