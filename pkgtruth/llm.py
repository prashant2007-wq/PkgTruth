"""Local LLM integration via Ollama with strict grounded quote verification."""

import json
import os
import re
from pathlib import Path
from typing import List, Optional, Tuple

import requests

from pkgtruth.models import AIExplanation, AIQuote, AIReport, FileDiff, Finding

DEFAULT_MODEL = "qwen2.5-coder:7b"
OLLAMA_ENDPOINT = os.getenv("OLLAMA_HOST", "http://localhost:11434")


def normalize_whitespace(text: str) -> str:
    """Collapse consecutive whitespace and strip margins for resilient substring matching."""
    return re.sub(r"\s+", " ", text).strip()


def verify_quote_in_file(quote: str, file_path: Path) -> Tuple[bool, int]:
    """Verify that a quoted string appears in the target file, returning line number."""
    if not quote or not file_path.exists():
        return False, 0

    norm_quote = normalize_whitespace(quote)
    if not norm_quote:
        return False, 0

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return False, 0

    # Line-by-line normalized check
    for idx, line in enumerate(lines, start=1):
        if norm_quote in normalize_whitespace(line):
            return True, idx

    # Multi-line check across full content
    full_content = normalize_whitespace(" ".join(lines))
    if norm_quote in full_content:
        # Approximate line search
        first_word = norm_quote.split()[0]
        for idx, line in enumerate(lines, start=1):
            if first_word in line:
                return True, idx
        return True, 1

    return False, 0


def generate_template_explanation(file_diff: FileDiff) -> AIExplanation:
    """Deterministic fallback explanation when local AI is disabled or unreachable."""
    if not file_diff.findings:
        return AIExplanation(
            file=file_diff.path,
            text=f"File {file_diff.path} matches normal repository structure.",
            quotes=[],
        )

    reasons = [f.reason for f in file_diff.findings]
    summary_text = "Deterministic analysis flagged: " + "; ".join(reasons)

    quotes: List[AIQuote] = []
    for f in file_diff.findings:
        if f.snippet:
            quotes.append(AIQuote(
                text=f.snippet,
                line=f.line,
                verified=True,
            ))

    return AIExplanation(
        file=file_diff.path,
        text=summary_text,
        quotes=quotes,
    )


def query_ollama(
    model_name: str,
    prompt: str,
    timeout: int = 10,
) -> Optional[dict]:
    """Execute request to local Ollama instance for JSON structured response."""
    url = f"{OLLAMA_ENDPOINT.rstrip('/')}/api/generate"
    payload = {
        "model": model_name,
        "prompt": prompt,
        "stream": False,
        "format": "json",
        "options": {
            "temperature": 0.0,
        },
    }

    try:
        resp = requests.post(url, json=payload, timeout=timeout)
        if resp.status_code == 200:
            res_json = resp.json()
            raw_text = res_json.get("response", "")
            return json.loads(raw_text)
    except Exception:
        return None
    return None


def explain_findings_with_llm(
    file_diff: FileDiff,
    actual_file_path: Path,
    model_name: Optional[str] = None,
    no_llm: bool = False,
) -> AIExplanation:
    """Generate grounded AI explanation for a suspicious or unexplained file."""
    if no_llm:
        return generate_template_explanation(file_diff)

    model = model_name or os.getenv("PKGTRUTH_MODEL", DEFAULT_MODEL)

    # Read snippet of suspicious code
    snippet = ""
    try:
        with open(actual_file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()[:40]
            snippet = "".join(lines)
    except Exception:
        return generate_template_explanation(file_diff)

    finding_summaries = [f"{f.rule}: {f.reason} (line {f.line})" for f in file_diff.findings]
    prompt = (
        f"You are a code security analyzer. Analyze this file ({file_diff.path}) with flags: {', '.join(finding_summaries)}.\n"
        f"Code:\n```\n{snippet[:1500]}\n```\n"
        "Return a JSON object with two fields:\n"
        "1. 'explanation': a plain-English 1-2 sentence explanation of why this code is risky or benign.\n"
        "2. 'quotes': array of exact verbatim string snippets from the code that support your explanation."
    )

    result = query_ollama(model, prompt)
    if not result or "explanation" not in result:
        return generate_template_explanation(file_diff)

    raw_quotes = result.get("quotes", [])
    verified_quotes: List[AIQuote] = []

    for q in raw_quotes:
        if isinstance(q, str):
            is_valid, line_no = verify_quote_in_file(q, actual_file_path)
            if is_valid:
                verified_quotes.append(AIQuote(text=q, line=line_no, verified=True))

    # Strict Grounding Rule: If no quotes could be verified, discard hallucinated explanation
    if raw_quotes and not verified_quotes:
        return generate_template_explanation(file_diff)

    return AIExplanation(
        file=file_diff.path,
        text=result.get("explanation", ""),
        quotes=verified_quotes,
    )
