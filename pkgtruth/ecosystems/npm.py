"""npm ecosystem plugin for fetching packages, metadata, and provenance."""

import base64
import json
import re
import urllib.parse
from pathlib import Path
from typing import Optional, Tuple

import requests

from pkgtruth.ecosystems.base import EcosystemPlugin
from pkgtruth.models import ProvenanceInfo


class NpmPlugin(EcosystemPlugin):
    """Ecosystem plugin for the npm registry."""

    REGISTRY_BASE = "https://registry.npmjs.org"

    @property
    def name(self) -> str:
        return "npm"

    def _encode_package_name(self, package_name: str) -> str:
        """Escape scoped package names for npm URLs.
        
        @scope/foo becomes @scope%2ffoo
        """
        if package_name.startswith("@") and "/" in package_name:
            scope, pkg = package_name.split("/", 1)
            return f"{scope}%2f{pkg}"
        return urllib.parse.quote(package_name, safe="")

    def fetch_metadata(self, package_name: str, version: str) -> dict:
        """Fetch package release metadata from registry.npmjs.org."""
        enc_name = self._encode_package_name(package_name)
        url = f"{self.REGISTRY_BASE}/{enc_name}/{version}"
        
        try:
            resp = requests.get(url, timeout=15)
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 404:
                # Try fetching root document if specific version endpoint returned 404
                root_url = f"{self.REGISTRY_BASE}/{enc_name}"
                root_resp = requests.get(root_url, timeout=15)
                if root_resp.status_code == 200:
                    data = root_resp.json()
                    return data.get("versions", {}).get(version, {})
        except Exception as e:
            # Graceful network failure handling
            return {"_fetch_error": str(e)}
        return {}

    def download(self, package_name: str, version: str, dest_dir: Path) -> Path:
        """Download tarball to dest_dir."""
        dest_dir.mkdir(parents=True, exist_ok=True)
        safe_filename = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", f"{package_name}-{version}.tgz")
        out_path = dest_dir / safe_filename

        metadata = self.fetch_metadata(package_name, version)
        tarball_url = metadata.get("dist", {}).get("tarball")
        
        if not tarball_url:
            clean_pkg = package_name.split("/")[-1] if "/" in package_name else package_name
            enc_name = self._encode_package_name(package_name)
            tarball_url = f"{self.REGISTRY_BASE}/{enc_name}/-/{clean_pkg}-{version}.tgz"

        try:
            with requests.get(tarball_url, stream=True, timeout=30) as r:
                r.raise_for_status()
                with open(out_path, "wb") as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
            return out_path
        except Exception as e:
            raise RuntimeError(f"Failed to download npm package {package_name}@{version}: {e}")

    def resolve_source(self, metadata: dict) -> Tuple[str, str, str]:
        """Extract repo URL, commit, and resolution strategy from package.json metadata."""
        repo_data = metadata.get("repository", {})
        repo_url = ""
        if isinstance(repo_data, dict):
            repo_url = repo_data.get("url", "")
        elif isinstance(repo_data, str):
            repo_url = repo_data

        git_head = metadata.get("gitHead", "")
        resolution = "gitHead" if git_head else "unresolved"

        return repo_url, git_head, resolution

    def get_provenance(self, package_name: str, version: str) -> ProvenanceInfo:
        """Fetch and parse build attestations from npm."""
        enc_name = self._encode_package_name(package_name)
        url = f"{self.REGISTRY_BASE}/-/npm/v1/attestations/{enc_name}@{version}"

        info = ProvenanceInfo(attestation_present=False, notes=[])
        try:
            resp = requests.get(url, timeout=10)
            if resp.status_code != 200:
                info.notes.append(f"No attestation endpoint returned (HTTP {resp.status_code})")
                return info

            data = resp.json()
            attestations = data.get("attestations", [])
            if not attestations:
                info.notes.append("Empty attestations array")
                return info

            info.attestation_present = True
            for att in attestations:
                bundle = att.get("bundle", {})
                envelope = bundle.get("dsseEnvelope", {})
                payload_b64 = envelope.get("payload", "")
                if payload_b64:
                    try:
                        raw_payload = base64.b64decode(payload_b64).decode("utf-8")
                        payload_data = json.loads(raw_payload)
                        predicate = payload_data.get("predicate", {})
                        
                        # Extract materials / source references
                        materials = predicate.get("materials", [])
                        for mat in materials:
                            uri = mat.get("uri", "")
                            digest = mat.get("digest", {})
                            if uri:
                                info.notes.append(f"Attested source: {uri} (digest: {digest})")
                    except Exception as err:
                        info.notes.append(f"Attestation payload decode note: {err}")

        except Exception as e:
            info.notes.append(f"Attestation check failed gracefully: {e}")

        return info
