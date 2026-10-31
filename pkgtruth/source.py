"""Repository URL normalization and source tree resolution."""

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional, Tuple


def normalize_repo_url(raw_url: str) -> str:
    """Normalize various repository URL formats to clean HTTPS or SSH URLs.
    
    Handles:
    - git+https://github.com/owner/repo.git -> https://github.com/owner/repo
    - git://github.com/owner/repo -> https://github.com/owner/repo
    - git@github.com:owner/repo.git -> https://github.com/owner/repo
    - github:owner/repo -> https://github.com/owner/repo
    - owner/repo -> https://github.com/owner/repo
    """
    if not raw_url:
        return ""

    url = raw_url.strip()

    # GitHub shorthand: github:owner/repo
    if url.startswith("github:"):
        url = url[len("github:"):]
        return f"https://github.com/{url}".rstrip(".git")

    # owner/repo shorthand (alphanumeric with single slash, not containing protocol)
    if re.match(r"^[a-zA-Z0-9_\-\.]+/[a-zA-Z0-9_\-\.]+$", url) and ":" not in url:
        return f"https://github.com/{url}".rstrip(".git")

    # git+ssh://git@github.com/... or ssh://git@...
    if url.startswith("git+ssh://"):
        url = url[len("git+ssh://"):]
    elif url.startswith("git+"):
        url = url[len("git+"):]

    # git@github.com:owner/repo.git
    scp_match = re.match(r"^git@([^:]+):(.+)$", url)
    if scp_match:
        host, path = scp_match.groups()
        url = f"https://{host}/{path}"

    # git:// -> https://
    if url.startswith("git://"):
        url = "https://" + url[len("git://"):]

    # Strip .git suffix and trailing slash
    if url.endswith(".git"):
        url = url[:-4]
    return url.rstrip("/")


def guess_tag_names(package_name: str, version: str) -> list[str]:
    """Generate likely git tag patterns for a package version."""
    clean_name = package_name.split("/")[-1] if "/" in package_name else package_name
    return [
        f"v{version}",
        version,
        f"{package_name}@{version}",
        f"{clean_name}@{version}",
        f"release-{version}",
        f"release/v{version}",
        f"release/{version}",
        f"v_{version}",
    ]


def clone_repo_ref(repo_url: str, ref: str, dest_dir: Path) -> bool:
    """Attempt to clone or checkout a specific ref/branch/tag using git.
    
    Returns True if successful, False otherwise.
    """
    if not shutil.which("git"):
        return False

    dest_dir.mkdir(parents=True, exist_ok=True)
    try:
        # Try shallow clone of specific ref
        cmd = ["git", "clone", "--depth", "1", "--branch", ref, repo_url, str(dest_dir)]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45)
        if proc.returncode == 0:
            return True

        # If shallow branch failed (e.g. ref was a commit SHA), try full clone + checkout
        cmd_full = ["git", "clone", repo_url, str(dest_dir)]
        proc2 = subprocess.run(cmd_full, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
        if proc2.returncode == 0:
            checkout = subprocess.run(["git", "checkout", ref], cwd=str(dest_dir),
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return checkout.returncode == 0
    except (subprocess.TimeoutExpired, Exception):
        return False
    return False


def resolve_source_tree(
    repo_url: str,
    package_name: str,
    version: str,
    explicit_ref: Optional[str] = None,
    git_head: Optional[str] = None,
    provenance_commit: Optional[str] = None,
    dest_dir: Optional[Path] = None,
) -> Tuple[Optional[Path], str, str]:
    """Resolve source code directory by cloning repo at the best verifiable ref.
    
    Order of trust:
    1. Explicit user ref (--ref)
    2. Provenance verified commit
    3. gitHead from package metadata
    4. Guessed git tags
    
    Returns:
        Tuple of (source_directory_path or None, resolution_strategy, resolved_commit_or_ref)
    """
    if not repo_url:
        return None, "unresolved", ""

    normalized_repo = normalize_repo_url(repo_url)
    if not normalized_repo:
        return None, "unresolved", ""

    if dest_dir is None:
        dest_dir = Path(tempfile.mkdtemp(prefix="pkgtruth_src_"))

    # 1. Explicit ref
    if explicit_ref:
        if clone_repo_ref(normalized_repo, explicit_ref, dest_dir):
            return dest_dir, "ref", explicit_ref

    # 2. Provenance commit
    if provenance_commit:
        if clone_repo_ref(normalized_repo, provenance_commit, dest_dir):
            return dest_dir, "provenance", provenance_commit

    # 3. gitHead
    if git_head:
        if clone_repo_ref(normalized_repo, git_head, dest_dir):
            return dest_dir, "gitHead", git_head

    # 4. Tag guessing
    candidate_tags = guess_tag_names(package_name, version)
    for tag in candidate_tags:
        if clone_repo_ref(normalized_repo, tag, dest_dir):
            return dest_dir, "tag", tag

    return None, "unresolved", ""
