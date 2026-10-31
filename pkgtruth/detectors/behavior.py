"""Detector for high-risk runtime behaviors, commands, and gained capabilities."""

from pathlib import Path
from typing import List, Set

from pkgtruth.capabilities import DOMAIN_REGEX, EXEC_PATTERNS, EVAL_PATTERNS, FS_SENSITIVE_PATTERNS, is_native_binary
from pkgtruth.models import Finding


def check_file_behavior(
    file_path: Path,
    rel_path: str,
    known_source_domains: Set[str],
    has_matching_source: bool = False
) -> List[Finding]:
    """Inspect file for dangerous runtime behavior not present in source."""
    findings: List[Finding] = []

    # 1. Native binary without source
    if is_native_binary(file_path):
        if not has_matching_source:
            findings.append(Finding(
                id="native_binary_unexplained",
                severity="high",
                rule="behavior",
                line=1,
                snippet=f"Binary header in {rel_path}",
                reason="Native executable or binary object added with no corresponding source",
                weight=30,
            ))
        return findings

    # Skip non-code extensions
    if file_path.suffix.lower() in (".map", ".png", ".jpg", ".txt", ".json", ".md"):
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

        # 2. Process execution
        for pattern in EXEC_PATTERNS:
            if pattern.search(clean):
                findings.append(Finding(
                    id="exec_or_eval_gained",
                    severity="high",
                    rule="behavior",
                    line=line_idx,
                    snippet=clean[:100],
                    reason="Command or child process execution invocation",
                    weight=25,
                ))
                break

        # 3. Dynamic code evaluation
        for pattern in EVAL_PATTERNS:
            if pattern.search(clean):
                findings.append(Finding(
                    id="eval_gained",
                    severity="high",
                    rule="behavior",
                    line=line_idx,
                    snippet=clean[:100],
                    reason="Dynamic code evaluation (eval / Function constructor)",
                    weight=25,
                ))
                break

        # 4. Sensitive filesystem paths
        for pattern in FS_SENSITIVE_PATTERNS:
            if pattern.search(clean):
                findings.append(Finding(
                    id="sensitive_fs_access",
                    severity="high",
                    rule="behavior",
                    line=line_idx,
                    snippet=clean[:100],
                    reason="Access to sensitive credential or configuration path (~/.ssh, ~/.npmrc, /etc/shadow)",
                    weight=30,
                ))
                break

        # 5. External network domains not present in source
        for match in DOMAIN_REGEX.finditer(clean):
            domain = match.group(1).lower()
            if domain not in ("schema.org", "json-schema.org", "w3.org", "registry.npmjs.org", "github.com", "localhost"):
                if domain not in known_source_domains:
                    findings.append(Finding(
                        id="network_domain_gained",
                        severity="high",
                        rule="behavior",
                        line=line_idx,
                        snippet=clean[:100],
                        reason=f"Network communication with novel domain not found in source: '{domain}'",
                        weight=25,
                    ))

    return findings
