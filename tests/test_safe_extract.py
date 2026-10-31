"""Tests for safe archive extraction."""

import io
import json
import tarfile
import zipfile
from pathlib import Path

import pytest

from pkgtruth.safe_extract import (
    ExtractionError,
    extract,
    extract_tar,
    extract_zip,
)


class TestTarExtraction:
    """Tests for tar archive extraction."""

    def test_clean_tarball_extracts(self, clean_tarball, tmp_path):
        """A normal npm tarball extracts correctly with prefix stripped."""
        dest = tmp_path / "out"
        result = extract(str(clean_tarball), str(dest))
        
        assert (result / "package.json").exists()
        assert (result / "dist" / "index.js").exists()
        assert (result / "dist" / "index.js.map").exists()
        assert (result / "LICENSE").exists()
        
        # Verify the package/ prefix was stripped
        assert not (result / "package").exists()

    def test_path_traversal_rejected(self, traversal_tarball, tmp_path):
        """Tarballs with path traversal members are rejected."""
        dest = tmp_path / "out"
        with pytest.raises(ExtractionError, match="traversal|escapes"):
            extract(str(traversal_tarball), str(dest))

    def test_symlink_rejected(self, symlink_tarball, tmp_path):
        """Tarballs with symlinks are rejected."""
        dest = tmp_path / "out"
        with pytest.raises(ExtractionError, match="[Ss]ymlink"):
            extract(str(symlink_tarball), str(dest))

    def test_absolute_path_rejected(self, tmp_path):
        """Tarballs with absolute path members are rejected."""
        tarball_path = tmp_path / "absolute.tgz"
        with tarfile.open(str(tarball_path), "w:gz") as tf:
            data = b"evil"
            info = tarfile.TarInfo(name="/etc/passwd")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        
        dest = tmp_path / "out"
        with pytest.raises(ExtractionError, match="[Aa]bsolute"):
            extract(str(tarball_path), str(dest))

    def test_no_prefix_tarball(self, tmp_path):
        """A tarball without a common prefix extracts files at the root."""
        tarball_path = tmp_path / "noprefix.tgz"
        with tarfile.open(str(tarball_path), "w:gz") as tf:
            data = b'{"name": "test"}'
            info = tarfile.TarInfo(name="package.json")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        
        dest = tmp_path / "out"
        result = extract(str(tarball_path), str(dest))
        assert (result / "package.json").exists()


class TestZipExtraction:
    """Tests for zip and wheel extraction."""

    def test_zip_extracts(self, tmp_path):
        """A normal zip file extracts correctly."""
        zip_path = tmp_path / "pkg.zip"
        with zipfile.ZipFile(str(zip_path), "w") as zf:
            zf.writestr("src/main.py", "print('hello')")
            zf.writestr("README.md", "# Hello")
        
        dest = tmp_path / "out"
        result = extract(str(zip_path), str(dest))
        assert (result / "src" / "main.py").exists()
        assert (result / "README.md").exists()

    def test_wheel_extracts(self, tmp_path):
        """A .whl file (which is a zip) extracts correctly."""
        whl_path = tmp_path / "pkg-1.0-py3-none-any.whl"
        with zipfile.ZipFile(str(whl_path), "w") as zf:
            zf.writestr("pkg/__init__.py", "__version__ = '1.0'")
            zf.writestr("pkg/core.py", "def main(): pass")
        
        dest = tmp_path / "out"
        result = extract(str(whl_path), str(dest))
        assert (result / "pkg" / "__init__.py").exists()

    def test_zip_traversal_rejected(self, tmp_path):
        """Zip files with path traversal are rejected."""
        zip_path = tmp_path / "evil.zip"
        with zipfile.ZipFile(str(zip_path), "w") as zf:
            zf.writestr("../../etc/evil", "malicious")
        
        dest = tmp_path / "out"
        with pytest.raises(ExtractionError, match="traversal|escapes"):
            extract(str(zip_path), str(dest))


class TestUnsupportedFormat:
    """Tests for unsupported archive formats."""

    def test_unsupported_extension(self, tmp_path):
        """An unsupported file extension raises ExtractionError."""
        fake = tmp_path / "package.rar"
        fake.write_text("not a real archive")
        
        with pytest.raises(ExtractionError, match="[Uu]nsupported"):
            extract(str(fake))
