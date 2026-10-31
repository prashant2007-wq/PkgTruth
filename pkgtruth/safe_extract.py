"""Safe extraction of package archives with security checks.

Handles .tar.gz, .tgz, .zip, and .whl files while guarding against:
- Path traversal attacks (../ or absolute paths)
- Symlinks escaping the extraction root
- Decompression bombs (file and total size limits)
"""

import os
import tarfile
import zipfile
import tempfile
from pathlib import Path, PurePosixPath

MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB per file
MAX_TOTAL_SIZE = 500 * 1024 * 1024  # 500 MB total


class ExtractionError(Exception):
    """Raised when archive extraction fails a safety check."""
    pass


def _validate_path(member_path: str, dest: Path) -> Path:
    """Validate that a member path is safe to extract.
    
    Rejects absolute paths and paths that traverse outside the
    destination directory.
    """
    clean = PurePosixPath(member_path)
    
    # Reject absolute paths
    if clean.is_absolute():
        raise ExtractionError(
            f"Absolute path rejected: {member_path}"
        )
    
    # Reject path traversal
    try:
        normalized = os.path.normpath(member_path)
    except (ValueError, OSError):
        raise ExtractionError(
            f"Invalid path rejected: {member_path}"
        )
    
    if normalized.startswith("..") or "/../" in normalized or normalized.startswith("/"):
        raise ExtractionError(
            f"Path traversal rejected: {member_path}"
        )
    
    # Resolve the final path and verify it's within dest
    resolved = (dest / normalized).resolve()
    dest_resolved = dest.resolve()
    if not str(resolved).startswith(str(dest_resolved) + os.sep) and resolved != dest_resolved:
        raise ExtractionError(
            f"Path escapes extraction root: {member_path}"
        )
    
    return resolved


def _strip_prefix(path: str, prefix: str) -> str:
    """Strip a common prefix from archive member paths.
    
    npm tarballs wrap everything in a 'package/' directory.
    This normalizes paths so they align with the source tree.
    """
    if prefix and path.startswith(prefix):
        stripped = path[len(prefix):]
        return stripped if stripped else path
    return path


def _detect_prefix(members: list) -> str:
    """Detect a common single-directory prefix in archive members.
    
    Returns the prefix string (e.g., 'package/') or empty string
    if there is no common prefix.
    """
    prefixes = set()
    for name in members:
        if name.startswith("/") or name.startswith("..") or "/../" in name:
            return ""
        parts = name.split("/", 1)
        if len(parts) > 1 and parts[0]:
            prefixes.add(parts[0] + "/")
        else:
            # A file at the root means no common prefix
            if name and not name.endswith("/"):
                return ""
    
    if len(prefixes) == 1:
        return prefixes.pop()
    return ""


def extract_tar(archive_path: str, dest_dir: str,
                strip_prefix: bool = True) -> Path:
    """Safely extract a tar archive (.tar.gz, .tgz, .tar).

    Args:
        archive_path: Path to the tar archive.
        dest_dir: Directory to extract into.
        strip_prefix: Whether to strip a common directory prefix.

    Returns:
        Path to the extraction directory.

    Raises:
        ExtractionError: If any safety check fails.
    """
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    total_size = 0

    try:
        with tarfile.open(archive_path, "r:*") as tf:
            members = [m for m in tf.getmembers()]
            
            # Detect prefix for stripping
            prefix = ""
            if strip_prefix:
                member_names = [m.name for m in members if not m.isdir()]
                prefix = _detect_prefix(member_names)
            
            for member in members:
                # Skip directories, we create them as needed
                if member.isdir():
                    continue
                
                # Block symlinks
                if member.issym() or member.islnk():
                    raise ExtractionError(
                        f"Symlink rejected: {member.name}"
                    )
                
                # Check for absolute path or path traversal on raw member name
                _validate_path(member.name, dest)
                
                # Check file size
                if member.size > MAX_FILE_SIZE:
                    raise ExtractionError(
                        f"File too large ({member.size} bytes): {member.name}"
                    )
                
                total_size += member.size
                if total_size > MAX_TOTAL_SIZE:
                    raise ExtractionError(
                        f"Total extraction size exceeds {MAX_TOTAL_SIZE} bytes"
                    )
                
                # Strip prefix and validate path
                stripped_name = _strip_prefix(member.name, prefix)
                if not stripped_name:
                    continue
                
                target = _validate_path(stripped_name, dest)
                target.parent.mkdir(parents=True, exist_ok=True)
                
                # Extract file content safely
                source = tf.extractfile(member)
                if source is None:
                    continue
                
                with open(target, "wb") as out:
                    while True:
                        chunk = source.read(8192)
                        if not chunk:
                            break
                        out.write(chunk)
    except tarfile.TarError as e:
        raise ExtractionError(f"Failed to read tar archive: {e}")
    
    return dest


def extract_zip(archive_path: str, dest_dir: str,
                strip_prefix: bool = True) -> Path:
    """Safely extract a zip archive (.zip, .whl).

    Args:
        archive_path: Path to the zip archive.
        dest_dir: Directory to extract into.
        strip_prefix: Whether to strip a common directory prefix.

    Returns:
        Path to the extraction directory.

    Raises:
        ExtractionError: If any safety check fails.
    """
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    total_size = 0

    try:
        with zipfile.ZipFile(archive_path, "r") as zf:
            infos = zf.infolist()
            
            # Detect prefix for stripping
            prefix = ""
            if strip_prefix:
                member_names = [i.filename for i in infos
                               if not i.filename.endswith("/")]
                prefix = _detect_prefix(member_names)
            
            for info in infos:
                # Skip directories
                if info.filename.endswith("/"):
                    continue
                
                # Check for absolute path or path traversal on raw member name
                _validate_path(info.filename, dest)
                
                # Check file size
                if info.file_size > MAX_FILE_SIZE:
                    raise ExtractionError(
                        f"File too large ({info.file_size} bytes): "
                        f"{info.filename}"
                    )
                
                total_size += info.file_size
                if total_size > MAX_TOTAL_SIZE:
                    raise ExtractionError(
                        f"Total extraction size exceeds {MAX_TOTAL_SIZE} bytes"
                    )
                
                # Strip prefix and validate path
                stripped_name = _strip_prefix(info.filename, prefix)
                if not stripped_name:
                    continue
                
                target = _validate_path(stripped_name, dest)
                target.parent.mkdir(parents=True, exist_ok=True)
                
                with zf.open(info) as source, open(target, "wb") as out:
                    while True:
                        chunk = source.read(8192)
                        if not chunk:
                            break
                        out.write(chunk)
    except zipfile.BadZipFile as e:
        raise ExtractionError(f"Failed to read zip archive: {e}")
    
    return dest


def extract(archive_path: str, dest_dir: str = None,
            strip_prefix: bool = True) -> Path:
    """Extract an archive, choosing the right method based on extension.

    Supports .tar.gz, .tgz, .tar, .zip, and .whl files.

    Args:
        archive_path: Path to the archive file.
        dest_dir: Directory to extract into. If None, creates a temp dir.
        strip_prefix: Whether to strip a common directory prefix
                     (e.g., npm's 'package/' wrapper).

    Returns:
        Path to the directory containing extracted files.

    Raises:
        ExtractionError: If the archive type is unsupported or a
                        safety check fails.
    """
    if dest_dir is None:
        dest_dir = tempfile.mkdtemp(prefix="pkgtruth_")
    
    archive_lower = archive_path.lower()
    
    if (archive_lower.endswith(".tar.gz") or
            archive_lower.endswith(".tgz") or
            archive_lower.endswith(".tar")):
        return extract_tar(archive_path, dest_dir, strip_prefix)
    elif archive_lower.endswith(".whl"):
        return extract_zip(archive_path, dest_dir, strip_prefix=False)
    elif archive_lower.endswith(".zip"):
        return extract_zip(archive_path, dest_dir, strip_prefix)
    else:
        raise ExtractionError(
            f"Unsupported archive format: {archive_path}"
        )
