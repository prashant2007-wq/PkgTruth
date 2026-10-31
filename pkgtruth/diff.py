"""File tree comparison between package and source.

Builds hash trees for two directory trees and classifies each file:
- identical: same content (matching SHA-256)
- modified: present in both trees but content differs
- added: present in package but not in source
- missing: present in source but not in package (not a risk signal,
  since packages normally omit tests and docs)
"""

import hashlib
import os
from pathlib import Path
from typing import Tuple

from pkgtruth.models import FileDiff, FileBucket


def hash_file(path: str) -> str:
    """Compute the SHA-256 hex digest of a file.

    Reads the file in 8KB chunks to handle large files without
    excessive memory use.
    """
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def build_hash_tree(root: str) -> dict:
    """Walk a directory tree and return a map of relative paths to SHA-256 hashes.

    Skips hidden files/directories (starting with '.') and common
    non-distributable paths like node_modules and __pycache__.
    
    Args:
        root: Root directory to walk.
    
    Returns:
        Dictionary mapping relative file paths (using forward slashes)
        to their SHA-256 hex digests.
    """
    skip_dirs = {
        ".git", ".svn", ".hg", "node_modules", "__pycache__",
        ".tox", ".pytest_cache", ".mypy_cache",
    }
    
    tree = {}
    root_path = Path(root).resolve()
    
    for dirpath, dirnames, filenames in os.walk(root_path):
        # Filter out hidden and skipped directories in-place
        dirnames[:] = [
            d for d in dirnames
            if d not in skip_dirs and not d.startswith(".")
        ]
        
        for filename in filenames:
            if filename.startswith("."):
                continue
            
            full_path = os.path.join(dirpath, filename)
            rel_path = os.path.relpath(full_path, root_path)
            # Normalize path separators to forward slashes
            rel_path = rel_path.replace(os.sep, "/")
            
            try:
                tree[rel_path] = hash_file(full_path)
            except (OSError, PermissionError):
                # Skip files we cannot read
                continue
    
    return tree


def diff_trees(package_root: str,
               source_root: str) -> Tuple[list, dict]:
    """Compare a package tree against a source tree.

    Args:
        package_root: Root directory of the extracted package.
        source_root: Root directory of the source code.

    Returns:
        A tuple of:
        - List of FileDiff objects for every file found in either tree.
        - Dictionary of counts: {identical, modified, added, missing}.
    """
    pkg_tree = build_hash_tree(package_root)
    src_tree = build_hash_tree(source_root)
    
    all_paths = sorted(set(pkg_tree.keys()) | set(src_tree.keys()))
    
    diffs = []
    counts = {"identical": 0, "modified": 0, "added": 0, "missing": 0}
    
    for path in all_paths:
        pkg_hash = pkg_tree.get(path, "")
        src_hash = src_tree.get(path, "")
        
        if pkg_hash and src_hash:
            if pkg_hash == src_hash:
                bucket = FileBucket.IDENTICAL.value
                counts["identical"] += 1
            else:
                bucket = FileBucket.MODIFIED.value
                counts["modified"] += 1
        elif pkg_hash and not src_hash:
            bucket = FileBucket.ADDED.value
            counts["added"] += 1
        else:
            bucket = FileBucket.MISSING.value
            counts["missing"] += 1
        
        diffs.append(FileDiff(
            path=path,
            bucket=bucket,
            source_hash=src_hash,
            package_hash=pkg_hash,
        ))
    
    return diffs, counts
