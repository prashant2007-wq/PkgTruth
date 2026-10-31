"""Report generation: terminal display, JSON export, and standalone HTML."""

import json
from pathlib import Path
from typing import Optional

from pkgtruth.models import Report

# ANSI terminal colors
RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
CYAN = "\033[36m"
GRAY = "\033[90m"


def format_terminal_report(report: Report) -> str:
    """Format report into clean, readable terminal output."""
    verdict = report.summary.verdict
    score = report.summary.score

    if verdict == "HIGH":
        verdict_color = RED
    elif verdict == "MEDIUM":
        verdict_color = YELLOW
    else:
        verdict_color = GREEN

    lines = []
    lines.append(f"\n{BOLD}======================================================================{RESET}")
    lines.append(f"{BOLD} PkgTruth Integrity Analysis Report{RESET}")
    lines.append(f"{BOLD}======================================================================{RESET}")
    
    # Header summary
    lines.append(f" Package:    {BOLD}{report.package.name}@{report.package.version}{RESET} ({report.package.ecosystem})")
    lines.append(f" Repository: {report.package.repo or 'Not specified'}")
    lines.append(f" Resolution: {report.package.source_resolution} ({report.package.commit or 'no commit ref'})")
    lines.append(f" Verdict:    {verdict_color}{BOLD}{verdict}{RESET} (Score: {score}/100)")
    lines.append(f" Headline:   {report.summary.headline}")
    lines.append(f" Generated:  {report.generated_at}")
    lines.append("----------------------------------------------------------------------")

    # Counts
    c = report.summary.counts
    lines.append(f"{BOLD}File Diff Summary:{RESET}")
    lines.append(f"  Identical: {c.identical} | Modified: {c.modified} | Added: {c.added} | Missing: {c.missing}")
    lines.append(f"  Explained: {c.explained} | Suspicious: {c.suspicious}")
    lines.append("----------------------------------------------------------------------")

    # Provenance
    p = report.provenance
    prov_status = f"{GREEN}Present{RESET}" if p.attestation_present else f"{YELLOW}Missing{RESET}"
    lines.append(f"{BOLD}Provenance Attestation:{RESET} {prov_status}")
    if p.notes:
        for note in p.notes:
            lines.append(f"  * {GRAY}{note}{RESET}")
    lines.append("----------------------------------------------------------------------")

    # Gained capabilities
    gained = report.capabilities.gained
    lines.append(f"{BOLD}Gained Capabilities ({len(gained)} novel powers):{RESET}")
    if not gained:
        lines.append(f"  {GREEN}[None] Package has no extra capabilities beyond source code.{RESET}")
    else:
        for g in gained:
            lines.append(f"  {RED}! [{g.category}]{RESET} {g.detail} ({GRAY}{g.file}:{g.line}{RESET})")
    lines.append("----------------------------------------------------------------------")

    # Suspicious Files & Findings
    suspicious_files = [f for f in report.files if f.status == "suspicious" or f.findings]
    if suspicious_files:
        lines.append(f"{BOLD}Flagged Findings:{RESET}")
        for f in suspicious_files:
            lines.append(f"  * {BOLD}{f.path}{RESET} ({f.bucket}, explained_by: {f.explained_by})")
            for fd in f.findings:
                sev_color = RED if fd.severity == "high" else YELLOW
                lines.append(f"    - {sev_color}[{fd.severity.upper()}]{RESET} {fd.rule}: {fd.reason}")
                if fd.snippet:
                    lines.append(f"      {GRAY}Line {fd.line}: {fd.snippet}{RESET}")
    else:
        lines.append(f"  {GREEN}[None] No suspicious file anomalies detected.{RESET}")

    lines.append(f"{BOLD}======================================================================{RESET}\n")
    return "\n".join(lines)


def generate_html_report(report: Report) -> str:
    """Generate a modern, self-contained standalone HTML report."""
    verdict = report.summary.verdict
    score = report.summary.score
    v_class = "verdict-high" if verdict == "HIGH" else ("verdict-medium" if verdict == "MEDIUM" else "verdict-low")

    # Render files rows
    file_rows = []
    for f in report.files:
        status_badge = f'<span class="badge {f.status}">{f.status}</span>'
        findings_html = ""
        if f.findings:
            findings_html = "<ul>" + "".join(f"<li><strong>[{fd.severity.upper()}]</strong> {fd.reason}</li>" for fd in f.findings) + "</ul>"
        file_rows.append(f"""
        <tr>
            <td><code>{f.path}</code></td>
            <td>{f.bucket}</td>
            <td>{status_badge}</td>
            <td>{f.explained_by}</td>
            <td>{findings_html or f.reason or '-'}</td>
        </tr>
        """)

    # Render capabilities gained
    cap_items = []
    for g in report.capabilities.gained:
        cap_items.append(f"""
        <div class="cap-item">
            <span class="badge high">{g.category}</span>
            <strong>{g.detail}</strong>
            <span class="muted">{g.file}:{g.line}</span>
        </div>
        """)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PkgTruth Report: {report.package.name}@{report.package.version}</title>
    <style>
        :root {{
            --bg: #0d1117;
            --card-bg: #161b22;
            --border: #30363d;
            --text: #c9d1d9;
            --heading: #f0f6fc;
            --low: #238636;
            --medium: #d29922;
            --high: #f85149;
            --accent: #58a6ff;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background: var(--bg);
            color: var(--text);
            margin: 0;
            padding: 24px;
            line-height: 1.5;
        }}
        .container {{ max-width: 1100px; margin: 0 auto; }}
        .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 16px; margin-bottom: 24px; }}
        .header h1 {{ margin: 0; color: var(--heading); font-size: 1.6rem; }}
        .badge {{ padding: 3px 8px; border-radius: 12px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }}
        .badge.low, .badge.normal, .badge.explained {{ background: rgba(35, 134, 54, 0.2); color: #3fb950; border: 1px solid #238636; }}
        .badge.medium {{ background: rgba(210, 153, 34, 0.2); color: #e3b341; border: 1px solid #d29922; }}
        .badge.high, .badge.suspicious {{ background: rgba(248, 81, 73, 0.2); color: #ff7b72; border: 1px solid #f85149; }}
        .card {{ background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; padding: 20px; margin-bottom: 24px; }}
        .verdict-banner {{ display: flex; align-items: center; gap: 20px; }}
        .score-circle {{ width: 72px; height: 72px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 1.4rem; font-weight: bold; }}
        .verdict-low .score-circle {{ border: 4px solid var(--low); color: #3fb950; }}
        .verdict-medium .score-circle {{ border: 4px solid var(--medium); color: #e3b341; }}
        .verdict-high .score-circle {{ border: 4px solid var(--high); color: #ff7b72; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 0.9rem; }}
        th, td {{ text-align: left; padding: 10px; border-bottom: 1px solid var(--border); }}
        th {{ color: var(--heading); }}
        code {{ background: rgba(110, 118, 129, 0.2); padding: 2px 5px; border-radius: 4px; font-family: monospace; }}
        .cap-item {{ display: flex; align-items: center; gap: 12px; padding: 8px 0; border-bottom: 1px solid var(--border); }}
        .muted {{ color: #8b949e; font-size: 0.85rem; }}
        ul {{ margin: 0; padding-left: 18px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>PkgTruth Integrity Report</h1>
                <div class="muted">Published Package vs Source Code Capability Analyzer</div>
            </div>
            <div><code>{report.generated_at}</code></div>
        </div>

        <div class="card verdict-banner {v_class}">
            <div class="score-circle">{score}</div>
            <div>
                <h2 style="margin: 0; color: var(--heading);">{report.package.name}@{report.package.version} &mdash; <span class="badge {verdict.lower()}">{verdict}</span></h2>
                <p style="margin: 6px 0 0 0;">{report.summary.headline}</p>
                <div class="muted" style="margin-top: 4px;">Repo: {report.package.repo or 'None'} | Source Resolution: {report.package.source_resolution}</div>
            </div>
        </div>

        <div class="card">
            <h3 style="margin-top: 0; color: var(--heading);">Gained Capabilities</h3>
            {"".join(cap_items) if cap_items else '<p class="muted">No novel capabilities detected beyond source code.</p>'}
        </div>

        <div class="card">
            <h3 style="margin-top: 0; color: var(--heading);">Files & Diffs</h3>
            <table>
                <thead>
                    <tr>
                        <th>Path</th>
                        <th>Bucket</th>
                        <th>Status</th>
                        <th>Explained By</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
                    {"".join(file_rows)}
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
"""
