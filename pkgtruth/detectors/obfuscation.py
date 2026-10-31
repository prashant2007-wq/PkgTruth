"""Detector for code obfuscation patterns and payload packagers."""

import re
from pathlib import Path
from typing import List

from pkgtruth.capabilities import shannon_entropy
from pkgtruth.models import Finding

HEX_VAR_PATTERN = re.compile(r"\b_0x[a-f0-9]{3,8}\b")
HEX_ESCAPES = re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}")
FROM_CHAR_CODE = re.compile(r"String\.fromCharCode\s*\(\s*(?:\d+\s*,\s*)+\d+\s*\)")
BASE64_DECODE = re.compile(r"Buffer\.from\s*\(\s*[\"'][A-Za-z0-9+/=]{20,}[\"']\s*,\s*[\"']base64[\"']\s*\)")
PACKED_EVAL = re.compile(r"eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*d\s*\)")


def check_file_obfuscation(file_path: Path, rel_path: str) -> List[Finding]:
    """Inspect file for obfuscation indicators."""
    findings: List[Finding] = []

    # Skip maps or binary files
    if file_path.suffix.lower() in (".map", ".png", ".jpg", ".woff", ".ttf", ".svg"):
        return findings

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return findings

    for line_idx, line in enumerate(lines, start=1):
        clean = line.strip()
        if not clean:
            continue

        # 1. Packed eval
        if PACKED_EVAL.search(clean):
            findings.append(Finding(
                id="packed_eval",
                severity="high",
                rule="obfuscation",
                line=line_idx,
                snippet=clean[:100],
                reason="Packed JavaScript eval loader detected (p,a,c,k,e,d unpacker)",
                weight=30,
            ))

        # 2. String.fromCharCode sequence
        if FROM_CHAR_CODE.search(clean):
            findings.append(Finding(
                id="char_code_chain",
                severity="high",
                rule="obfuscation",
                line=line_idx,
                snippet=clean[:100],
                reason="Concealed string construction via String.fromCharCode chain",
                weight=30,
            ))

        # 3. Hex variable patterns like _0x1a2b
        hex_matches = HEX_VAR_PATTERN.findall(clean)
        if len(hex_matches) >= 3:
            findings.append(Finding(
                id="hex_identifiers",
                severity="high",
                rule="obfuscation",
                line=line_idx,
                snippet=clean[:100],
                reason=f"Multiple obfuscator-style hex identifiers detected ({len(hex_matches)} occurrences)",
                weight=30,
            ))

        # 4. Dense hex escapes
        if HEX_ESCAPES.search(clean):
            findings.append(Finding(
                id="dense_hex_escapes",
                severity="high",
                rule="obfuscation",
                line=line_idx,
                snippet=clean[:100],
                reason="High-density hex character escape sequences detected",
                weight=30,
            ))

        # 5. Base64 payload decode
        if BASE64_DECODE.search(clean):
            findings.append(Finding(
                id="base64_decode_payload",
                severity="medium",
                rule="obfuscation",
                line=line_idx,
                snippet=clean[:100],
                reason="Base64 payload buffer decoding detected",
                weight=20,
            ))

        # 6. Ultra-long high-entropy line
        if len(clean) > 800 and shannon_entropy(clean) > 5.3:
            findings.append(Finding(
                id="high_entropy_blob",
                severity="medium",
                rule="obfuscation",
                line=line_idx,
                snippet=clean[:80] + "...",
                reason="Extremely long line with high information entropy (>5.3)",
                weight=25,
            ))

    return findings
