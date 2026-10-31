"""Containment explainer: verifies that symbols and literals in output exist in source."""

import os
import re
from pathlib import Path
from typing import List, Set, Tuple

LITERAL_REGEX = re.compile(r"[\"']([a-zA-Z0-9_\-\./:]{4,})[\"']")
SENSITIVE_IDENTIFIERS = [
    "child_process",
    "exec",
    "spawn",
    "eval",
    "Function",
    "process.env",
    "http",
    "https",
    "curl",
    "wget",
]


def extract_tokens(text: str) -> Set[str]:
    """Extract strings and identifier tokens from code text."""
    tokens = set()
    for match in LITERAL_REGEX.finditer(text):
        tokens.add(match.group(1))
    for ident in SENSITIVE_IDENTIFIERS:
        if ident in text:
            tokens.add(ident)
    return tokens


def build_source_token_index(source_root: Path) -> Set[str]:
    """Build an index of all string literals and tokens across source tree."""
    index: Set[str] = set()
    for dirpath, dirnames, filenames in os.walk(source_root):
        dirnames[:] = [d for d in dirnames if not d.startswith(".") and d not in ("node_modules", ".git")]
        for fname in filenames:
            if fname.startswith("."):
                continue
            fpath = Path(dirpath) / fname
            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
                index.update(extract_tokens(content))
            except Exception:
                continue
    return index


def explain_containment(pkg_file: Path, source_token_index: Set[str]) -> Tuple[bool, str, List[Tuple[str, int]]]:
    """Verify that all sensitive tokens in the package file are present in source tree.
    
    Returns:
        (is_contained, explanation_reason, novel_tokens_with_line_numbers)
    """
    novel_items: List[Tuple[str, int]] = []

    try:
        with open(pkg_file, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return False, "Unreadable file", []

    for line_idx, line in enumerate(lines, start=1):
        line_tokens = extract_tokens(line)
        for tok in line_tokens:
            if tok in SENSITIVE_IDENTIFIERS or tok.startswith("http://") or tok.startswith("https://"):
                if tok not in source_token_index:
                    novel_items.append((tok, line_idx))

    if not novel_items:
        return True, "All sensitive tokens and external strings are contained in source repository", []

    first_novel, first_line = novel_items[0]
    return False, f"Novel sensitive string or identifier not in source: '{first_novel}' at line {first_line}", novel_items
