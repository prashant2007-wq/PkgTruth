"""Base interface for package ecosystem plugins."""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional, Tuple

from pkgtruth.models import ProvenanceInfo, PackageInfo


class EcosystemPlugin(ABC):
    """Abstract base class for package ecosystems (npm, PyPI, etc.)."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the ecosystem (e.g. 'npm', 'pypi')."""
        pass

    @abstractmethod
    def fetch_metadata(self, package_name: str, version: str) -> dict:
        """Fetch package release metadata from the public registry.
        
        Must handle network failures gracefully by returning an empty dict
        or raising a descriptive RuntimeError/ConnectionError.
        """
        pass

    @abstractmethod
    def download(self, package_name: str, version: str, dest_dir: Path) -> Path:
        """Download package archive (.tgz, .whl, etc.) to dest_dir."""
        pass

    @abstractmethod
    def resolve_source(self, metadata: dict) -> Tuple[str, str, str]:
        """Extract repository URL, commit/ref, and resolution method from metadata.
        
        Returns:
            Tuple of (repo_url, commit_or_tag, resolution_method)
        """
        pass

    @abstractmethod
    def get_provenance(self, package_name: str, version: str) -> ProvenanceInfo:
        """Fetch and verify build provenance attestations if supported."""
        pass
