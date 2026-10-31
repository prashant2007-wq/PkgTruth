"""Tests for file tree diffing."""

import json
from pathlib import Path

import pytest

from pkgtruth.diff import build_hash_tree, diff_trees, hash_file
from pkgtruth.models import FileBucket


class TestHashFile:
    """Tests for single-file hashing."""

    def test_consistent_hash(self, tmp_path):
        """Same content produces the same hash."""
        f = tmp_path / "test.txt"
        f.write_text("hello world")
        
        h1 = hash_file(str(f))
        h2 = hash_file(str(f))
        assert h1 == h2
        assert len(h1) == 64  # SHA-256 hex digest length

    def test_different_content_different_hash(self, tmp_path):
        """Different content produces different hashes."""
        f1 = tmp_path / "a.txt"
        f2 = tmp_path / "b.txt"
        f1.write_text("hello")
        f2.write_text("world")
        
        assert hash_file(str(f1)) != hash_file(str(f2))


class TestBuildHashTree:
    """Tests for directory tree hashing."""

    def test_basic_tree(self, tmp_path):
        """Builds a hash map for a simple directory tree."""
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "main.js").write_text("console.log('hi')")
        (tmp_path / "README.md").write_text("# Hello")
        
        tree = build_hash_tree(str(tmp_path))
        assert "src/main.js" in tree
        assert "README.md" in tree
        assert len(tree) == 2

    def test_skips_hidden_files(self, tmp_path):
        """Hidden files and directories are excluded."""
        (tmp_path / ".git").mkdir()
        (tmp_path / ".git" / "config").write_text("gitconfig")
        (tmp_path / ".hidden").write_text("secret")
        (tmp_path / "visible.txt").write_text("public")
        
        tree = build_hash_tree(str(tmp_path))
        assert "visible.txt" in tree
        assert ".hidden" not in tree
        assert ".git/config" not in tree

    def test_skips_node_modules(self, tmp_path):
        """node_modules directory is excluded."""
        (tmp_path / "node_modules" / "dep").mkdir(parents=True)
        (tmp_path / "node_modules" / "dep" / "index.js").write_text("x")
        (tmp_path / "index.js").write_text("main")
        
        tree = build_hash_tree(str(tmp_path))
        assert "index.js" in tree
        assert len(tree) == 1


class TestDiffTrees:
    """Tests for comparing package and source trees."""

    def test_identical_trees(self, tmp_path):
        """Two identical trees produce all-identical results."""
        pkg = tmp_path / "pkg"
        src = tmp_path / "src"
        pkg.mkdir()
        src.mkdir()
        
        content = "module.exports = {}"
        (pkg / "index.js").write_text(content)
        (src / "index.js").write_text(content)
        (pkg / "package.json").write_text('{"name":"x"}')
        (src / "package.json").write_text('{"name":"x"}')
        
        diffs, counts = diff_trees(str(pkg), str(src))
        assert counts["identical"] == 2
        assert counts["modified"] == 0
        assert counts["added"] == 0
        assert counts["missing"] == 0

    def test_modified_file(self, tmp_path):
        """A file with different content is marked as modified."""
        pkg = tmp_path / "pkg"
        src = tmp_path / "src"
        pkg.mkdir()
        src.mkdir()
        
        (pkg / "index.js").write_text("compiled version")
        (src / "index.js").write_text("source version")
        
        diffs, counts = diff_trees(str(pkg), str(src))
        assert counts["modified"] == 1
        mod = [d for d in diffs if d.bucket == FileBucket.MODIFIED.value]
        assert len(mod) == 1
        assert mod[0].path == "index.js"

    def test_added_file(self, tmp_path):
        """A file only in the package is marked as added."""
        pkg = tmp_path / "pkg"
        src = tmp_path / "src"
        pkg.mkdir()
        src.mkdir()
        
        (pkg / "dist" / "bundle.js").parent.mkdir(parents=True)
        (pkg / "dist" / "bundle.js").write_text("bundled code")
        (src / "src" / "index.ts").parent.mkdir(parents=True)
        (src / "src" / "index.ts").write_text("source code")
        
        diffs, counts = diff_trees(str(pkg), str(src))
        assert counts["added"] == 1
        assert counts["missing"] == 1
        
        added = [d for d in diffs if d.bucket == FileBucket.ADDED.value]
        assert added[0].path == "dist/bundle.js"

    def test_missing_file(self, tmp_path):
        """A file only in source (like tests) is marked as missing."""
        pkg = tmp_path / "pkg"
        src = tmp_path / "src"
        pkg.mkdir()
        src.mkdir()
        
        (pkg / "index.js").write_text("code")
        (src / "index.js").write_text("code")
        (src / "tests" / "test.js").parent.mkdir()
        (src / "tests" / "test.js").write_text("test code")
        
        diffs, counts = diff_trees(str(pkg), str(src))
        assert counts["identical"] == 1
        assert counts["missing"] == 1
        
        missing = [d for d in diffs
                   if d.bucket == FileBucket.MISSING.value]
        assert missing[0].path == "tests/test.js"

    def test_clean_compiled_package(self, clean_source, clean_tarball,
                                    tmp_path):
        """A clean compiled package has expected diff pattern.
        
        The package should have:
        - modified: package.json (publish-time fields added)
        - added: dist/index.js, dist/index.js.map, LICENSE
        - missing: src/index.ts, tsconfig.json, tests/
        """
        from pkgtruth.safe_extract import extract
        
        pkg_dir = tmp_path / "pkg_extracted"
        extract(str(clean_tarball), str(pkg_dir))
        
        diffs, counts = diff_trees(str(pkg_dir), str(clean_source))
        
        # package.json is modified (publish-time fields)
        assert counts["modified"] >= 1
        # dist/ files are added
        assert counts["added"] >= 1
        # src/ files are missing from the package (normal)
        assert counts["missing"] >= 1

    def test_tampered_package_has_extra_files(self, clean_source,
                                              tampered_tarball, tmp_path):
        """A tampered package has suspicious added files."""
        from pkgtruth.safe_extract import extract
        
        pkg_dir = tmp_path / "pkg_extracted"
        extract(str(tampered_tarball), str(pkg_dir))
        
        diffs, counts = diff_trees(str(pkg_dir), str(clean_source))
        
        # lib/x.min.js should be added (not in source)
        added_paths = [
            d.path for d in diffs
            if d.bucket == FileBucket.ADDED.value
        ]
        assert "lib/x.min.js" in added_paths
