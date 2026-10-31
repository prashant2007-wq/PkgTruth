"""Capability extraction and comparison across source and package trees."""

import math
import os
import re
from pathlib import Path
from typing import Dict, List, Set, Tuple

from pkgtruth.models import CapabilityCategory, GainedCapability

# Compiled regex patterns for capability detection
DOMAIN_REGEX = re.compile(r"https?://([a-zA-Z0-9.\-]+(?:\:[0-9]+)?)", re.IGNORECASE)
EXEC_PATTERNS = [
    re.compile(r"\b(?:child_process|cp)\.(?:exec|spawn|execSync|execFile|fork)\b"),
    re.compile(r"\brequire\([\"']child_process[\"']\)"),
    re.compile(r"\b(?:subprocess|os)\.(?:Popen|run|call|check_call|check_output|system|popen)\b"),
    re.compile(r"curl\s+[^|\n]+(?:\s*\|\s*(?:ba)?sh)?"),
    re.compile(r"wget\s+[^|\n]+(?:\s*\|\s*(?:ba)?sh)?"),
]
EVAL_PATTERNS = [
    re.compile(r"\b(?<!\.)eval\s*\("),
    re.compile(r"\bnew\s+Function\s*\("),
    re.compile(r"\bFunction\s*\(\s*[\"']return\s+this[\"']\s*\)"),
    re.compile(r"String\.fromCharCode\s*\("),
]
FS_SENSITIVE_PATTERNS = [
    re.compile(r"[\"'](?:\~|\/root|\/home\/[^\/]+)?\/\.(?:ssh|aws|npmrc|docker|kube|gitconfig)[\"']"),
    re.compile(r"[\"'](?:\/etc\/(?:passwd|shadow|hosts))[\"']"),
    re.compile(r"\.ssh\/id_rsa"),
]
ENV_PATTERNS = [
    re.compile(r"\bprocess\.env\b"),
    re.compile(r"\bos\.environ\b"),
    re.compile(r"\bos\.getenv\b"),
]
DYNAMIC_REQUIRE_PATTERNS = [
    re.compile(r"\brequire\s*\(\s*[^\"'\s\)]+\s*\)"),
    re.compile(r"\bimport\s*\(\s*[^\"'\s\)]+\s*\)"),
]

BINARY_MAGIC = [
    (b"\x7fELF", "ELF executable"),
    (b"MZ", "DOS/PE executable"),
    (b"\xfe\xed\xfa\xce", "Mach-O 32-bit"),
    (b"\xfe\xed\xfa\xcf", "Mach-O 64-bit"),
    (b"\xcf\xfa\xed\xfe", "Mach-O 64-bit"),
    (b"\xca\xfe\xba\xbe", "Mach-O Universal / Java class"),
]


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    frequencies = {}
    for char in data:
        frequencies[char] = frequencies.get(char, 0) + 1
    for count in frequencies.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def is_native_binary(path: Path) -> bool:
    """Check if file starts with native executable magic headers."""
    try:
        with open(path, "rb") as f:
            header = f.read(4)
            for magic, _ in BINARY_MAGIC:
                if header.startswith(magic):
                    return True
    except (OSError, PermissionError):
        pass
    return False


def extract_file_capabilities(filepath: Path, rel_path: str) -> List[Tuple[str, str, int]]:
    """Extract capabilities from a single file with line numbers.
    
    Returns:
        List of tuples: (category, detail, line_number)
    """
    results: List[Tuple[str, str, int]] = []

    # Check for binary headers
    if is_native_binary(filepath):
        results.append((CapabilityCategory.NATIVE_BINARY.value, f"Binary executable at {rel_path}", 1))
        return results

    # Only inspect text files
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except (OSError, PermissionError):
        return results

    for line_idx, line in enumerate(lines, start=1):
        # 1. NETWORK
        for match in DOMAIN_REGEX.finditer(line):
            domain = match.group(1).lower()
            # Ignore standard schema/doc hosts
            if domain not in ("schema.org", "json-schema.org", "w3.org", "registry.npmjs.org", "github.com", "localhost"):
                results.append((CapabilityCategory.NETWORK.value, domain, line_idx))

        # 2. EXEC
        for pattern in EXEC_PATTERNS:
            if pattern.search(line):
                snippet = line.strip()[:60]
                results.append((CapabilityCategory.EXEC.value, snippet, line_idx))
                break

        # 3. EVAL
        for pattern in EVAL_PATTERNS:
            if pattern.search(line):
                snippet = line.strip()[:60]
                results.append((CapabilityCategory.EVAL.value, snippet, line_idx))
                break

        # 4. FS_SENSITIVE
        for pattern in FS_SENSITIVE_PATTERNS:
            if pattern.search(line):
                snippet = line.strip()[:60]
                results.append((CapabilityCategory.FS_SENSITIVE.value, snippet, line_idx))
                break

        # 5. ENV_ACCESS
        for pattern in ENV_PATTERNS:
            if pattern.search(line):
                results.append((CapabilityCategory.ENV_ACCESS.value, "process.env or os.environ read", line_idx))
                break

        # 6. DYNAMIC_REQUIRE
        for pattern in DYNAMIC_REQUIRE_PATTERNS:
            if pattern.search(line):
                snippet = line.strip()[:60]
                results.append((CapabilityCategory.DYNAMIC_REQUIRE.value, snippet, line_idx))
                break

        # 7. OBFUSCATION
        if len(line) > 1200 or re.search(r"_0x[a-f0-9]{4,}", line):
            results.append((CapabilityCategory.OBFUSCATION.value, "High entropy / hex obfuscated line", line_idx))
        elif len(line) > 80 and shannon_entropy(line) > 5.2 and not filepath.suffix == ".map":
            results.append((CapabilityCategory.OBFUSCATION.value, "High Shannon entropy string blob", line_idx))

    return results


def build_tree_capabilities(root_dir: str) -> Tuple[Dict[str, List[str]], List[Tuple[str, str, str, int]]]:
    """Scan all files in root_dir and aggregate capability dictionary and detailed records.
    
    Returns:
        (category_map, list of (category, detail, rel_path, line))
    """
    category_map: Dict[str, Set[str]] = {}
    detailed_records: List[Tuple[str, str, str, int]] = []

    root_path = Path(root_dir).resolve()
    for dirpath, dirnames, filenames in os.walk(root_path):
        dirnames[:] = [d for d in dirnames if not d.startswith(".") and d not in ("node_modules", ".git", "__pycache__")]
        for fname in filenames:
            if fname.startswith("."):
                continue
            full_path = Path(dirpath) / fname
            rel_path = str(full_path.relative_to(root_path)).replace(os.sep, "/")
            
            caps = extract_file_capabilities(full_path, rel_path)
            for cat, detail, line in caps:
                category_map.setdefault(cat, set()).add(detail)
                detailed_records.append((cat, detail, rel_path, line))

    # Convert sets to sorted lists
    clean_category_map = {k: sorted(list(v)) for k, v in category_map.items()}
    return clean_category_map, detailed_records


def compare_capabilities(
    source_root: str,
    package_root: str
) -> Tuple[Dict[str, List[str]], Dict[str, List[str]], List[GainedCapability]]:
    """Compare capability sets between source and package trees.
    
    Returns:
        (source_caps, package_caps, gained_caps)
    """
    src_map, _ = build_tree_capabilities(source_root)
    pkg_map, pkg_records = build_tree_capabilities(package_root)

    gained: List[GainedCapability] = []
    seen_gained = set()

    for cat, detail, rel_path, line in pkg_records:
        src_details = src_map.get(cat, [])
        if detail not in src_details:
            key = (cat, detail, rel_path, line)
            if key not in seen_gained:
                seen_gained.add(key)
                gained.append(GainedCapability(
                    category=cat,
                    detail=detail,
                    file=rel_path,
                    line=line,
                ))

    return src_map, pkg_map, gained
