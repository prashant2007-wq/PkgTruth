"""Scoring engine: computes overall risk score, verdict, and weights."""

from typing import Dict, List, Tuple
from pkgtruth.models import Finding, FileDiff, ProvenanceInfo, Verdict

WEIGHTS: Dict[str, int] = {
    "install_hook_added": 40,
    "install_hook_modified": 40,
    "pth_file_added": 40,
    "new_dependency": 15,
    "url_dependency": 20,
    "typosquat_dependency": 25,
    "obfuscated": 30,
    "packed_eval": 30,
    "char_code_chain": 30,
    "hex_identifiers": 30,
    "dense_hex_escapes": 30,
    "base64_decode_payload": 20,
    "high_entropy_blob": 25,
    "exec_or_eval_gained": 25,
    "eval_gained": 25,
    "sensitive_fs_access": 30,
    "network_domain_gained": 25,
    "string_not_in_source": 20,
    "unexplained_file": 10,
    "source_unresolved": 15,
    "provenance_missing": 5,
    "provenance_mismatch": 35,
    "native_binary_unexplained": 30,
    "pattern_break": 20,
}

PROVENANCE_MATCH_DISCOUNT = 20
EXPLAINED_FILE_WEIGHT_FACTOR = 0.10


def calculate_verdict(score: int) -> str:
    """Classify score into LOW, MEDIUM, or HIGH verdict."""
    if score < 30:
        return Verdict.LOW.value
    elif score < 60:
        return Verdict.MEDIUM.value
    else:
        return Verdict.HIGH.value


def score_analysis(
    file_diffs: List[FileDiff],
    provenance: ProvenanceInfo,
    source_resolved: bool,
    pattern_break_count: int = 0,
) -> Tuple[int, str, str]:
    """Calculate aggregate score, verdict, and human-readable headline.
    
    Returns:
        (total_score, verdict_string, headline)
    """
    total_score = 0.0
    critical_signals: List[str] = []

    # 1. Source resolution signal
    if not source_resolved:
        weight = WEIGHTS.get("source_unresolved", 15)
        total_score += weight
        critical_signals.append("Source code repository or matching commit could not be verified")

    # 2. Provenance signals
    if not provenance.attestation_present:
        total_score += WEIGHTS.get("provenance_missing", 5)
    else:
        if provenance.repo_match is False or provenance.commit_match is False:
            weight = WEIGHTS.get("provenance_mismatch", 35)
            total_score += weight
            critical_signals.append("Provenance attestation does not match claimed repository or commit")
        elif provenance.repo_match is True and provenance.commit_match is True:
            # Trusted provenance bonus
            total_score -= PROVENANCE_MATCH_DISCOUNT

    # 3. Pattern breaks
    if pattern_break_count > 0:
        total_score += pattern_break_count * WEIGHTS.get("pattern_break", 20)
        critical_signals.append("Release history pattern break detected")

    # 4. File-level findings and status
    for fd in file_diffs:
        # Unexplained added file with no explicit findings
        if fd.bucket == "added" and fd.status == "normal" and fd.explained_by == "none":
            total_score += WEIGHTS.get("unexplained_file", 10)

        is_explained = (fd.status == "explained")
        weight_mult = EXPLAINED_FILE_WEIGHT_FACTOR if is_explained else 1.0

        for f in fd.findings:
            rule_weight = f.weight if f.weight else WEIGHTS.get(f.id, 10)
            added_weight = rule_weight * weight_mult
            total_score += added_weight

            if f.severity == "high" and not is_explained:
                critical_signals.append(f.reason)

    final_score = max(0, int(round(total_score)))
    verdict = calculate_verdict(final_score)

    # Headline generation
    if verdict == Verdict.HIGH.value:
        headline = f"High risk: {critical_signals[0]}" if critical_signals else "Multiple critical security anomalies detected in release"
    elif verdict == Verdict.MEDIUM.value:
        headline = f"Caution: {critical_signals[0]}" if critical_signals else "Release contains novel dependencies or unexplained build changes"
    else:
        headline = "Clean release: all capabilities and files match or are explained by source repository"

    return final_score, verdict, headline
