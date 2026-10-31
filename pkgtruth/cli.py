"""Command-Line Interface and pipeline orchestrator for PkgTruth."""

import argparse
import json
import os
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from pkgtruth.capabilities import compare_capabilities, build_tree_capabilities
from pkgtruth.detectors.behavior import check_file_behavior
from pkgtruth.detectors.deps import check_dependencies
from pkgtruth.detectors.install_hooks import check_install_hooks
from pkgtruth.detectors.obfuscation import check_file_obfuscation
from pkgtruth.diff import diff_trees
from pkgtruth.ecosystems.npm import NpmPlugin
from pkgtruth.ecosystems.pypi import PyPIPlugin
from pkgtruth.explainers.config import explain_config
from pkgtruth.explainers.containment import build_source_token_index, explain_containment
from pkgtruth.explainers.metadata_only import explain_metadata_only
from pkgtruth.explainers.sourcemap import explain_sourcemap
from pkgtruth.llm import explain_findings_with_llm
from pkgtruth.models import (
    AIReport,
    CapabilityReport,
    ExplainedBy,
    FileBucket,
    FileDiff,
    FileStatus,
    Finding,
    PackageInfo,
    ProvenanceInfo,
    Report,
    Summary,
    SummaryCounts,
    Verdict,
)
from pkgtruth.report import format_terminal_report, generate_html_report
from pkgtruth.safe_extract import extract
from pkgtruth.source import resolve_source_tree


def analyze_extracted_trees(
    pkg_root: Path,
    src_root: Path,
    package_info: PackageInfo,
    provenance_info: ProvenanceInfo,
    no_llm: bool = False,
) -> Report:
    """Run full diff, explainer, detector, and capability pipeline across two directories."""
    # 1. Diff trees
    file_diffs, counts = diff_trees(str(pkg_root), str(src_root))

    # 2. Extract capabilities & build indexes
    src_caps, pkg_caps, gained_caps = compare_capabilities(str(src_root), str(pkg_root))
    source_token_index = build_source_token_index(src_root)
    source_domains = set(src_caps.get("NETWORK", []))

    # 3. Detectors at package root level
    install_hook_findings = check_install_hooks(pkg_root, src_root)
    dep_findings = check_dependencies(pkg_root, src_root)

    # Index diffs by path
    diff_map = {d.path: d for d in file_diffs}

    # Attach package.json and hook findings to their corresponding files
    for f in install_hook_findings:
        if f.id == "pth_file_added":
            for path, fd in diff_map.items():
                if path.endswith(".pth"):
                    fd.add_finding(f)
        elif "package.json" in diff_map:
            diff_map["package.json"].add_finding(f)

    if "package.json" in diff_map:
        for f in dep_findings:
            diff_map["package.json"].add_finding(f)
    elif dep_findings:
        synthetic = FileDiff(path="package.json", bucket=FileBucket.MODIFIED.value)
        for f in dep_findings:
            synthetic.add_finding(f)
        diff_map["package.json"] = synthetic
        file_diffs.append(synthetic)

    # Attach gained capabilities as file findings
    for g in gained_caps:
        rule_name = "behavior"
        sev = "high"
        f_id = "exec_or_eval_gained"
        weight = 25
        if g.category == "NETWORK":
            f_id = "network_domain_gained"
            reason = f"Network connection to novel domain: '{g.detail}'"
        elif g.category in ("EXEC", "EVAL"):
            f_id = "exec_or_eval_gained"
            reason = f"Execution or dynamic code evaluation: {g.detail}"
        elif g.category == "OBFUSCATION":
            rule_name = "obfuscation"
            f_id = "obfuscated"
            reason = f"Obfuscated structure or packed encoding: {g.detail}"
            weight = 30
        else:
            reason = f"Novel capability gained ({g.category}): {g.detail}"

        finding = Finding(
            id=f_id,
            severity=sev,
            rule=rule_name,
            line=g.line,
            snippet=g.detail,
            reason=reason,
            weight=weight,
        )
        if g.file in diff_map:
            diff_map[g.file].add_finding(finding)

    # 4. Explainers and File-level Detectors
    explained_count = 0
    suspicious_count = 0

    for fd in file_diffs:
        if fd.bucket == FileBucket.IDENTICAL.value:
            fd.status = FileStatus.NORMAL.value
            continue
        elif fd.bucket == FileBucket.MISSING.value:
            fd.status = FileStatus.NORMAL.value
            fd.reason = "Omitted from package (typical for tests and documentation)"
            continue

        pkg_file = pkg_root / fd.path
        src_file = src_root / fd.path

        # Run file-level detectors (obfuscation and behavior)
        if pkg_file.exists():
            obf_findings = check_file_obfuscation(pkg_file, fd.path)
            for f in obf_findings:
                fd.add_finding(f)

            has_matching_src = src_file.exists()
            beh_findings = check_file_behavior(pkg_file, fd.path, source_domains, has_matching_src)
            for f in beh_findings:
                fd.add_finding(f)

        # Check containment against source token index
        ok_cont, cont_reason, novel = explain_containment(pkg_file, source_token_index)
        if not ok_cont and novel:
            first_tok, first_ln = novel[0]
            fd.add_finding(Finding(
                id="string_not_in_source",
                severity="medium",
                rule="containment",
                line=first_ln,
                snippet=first_tok,
                reason=f"Novel sensitive token '{first_tok}' not found in source repository",
                weight=20,
            ))

        # A file with high severity findings cannot be considered explained
        has_high_findings = any(f.severity == "high" for f in fd.findings)

        if not has_high_findings:
            # Try Explainers
            # a. Metadata only for package.json
            ok_meta, meta_reason = explain_metadata_only(pkg_file, src_file)
            if ok_meta and not fd.findings:
                fd.status = FileStatus.EXPLAINED.value
                fd.explained_by = ExplainedBy.METADATA_ONLY.value
                fd.reason = meta_reason
                explained_count += 1
                continue

            # b. Sourcemap
            ok_sm, sm_reason = explain_sourcemap(pkg_file, src_root)
            if ok_sm and ok_cont:
                fd.status = FileStatus.EXPLAINED.value
                fd.explained_by = ExplainedBy.SOURCEMAP.value
                fd.reason = sm_reason
                explained_count += 1
                continue

            # c. Config build output
            ok_cfg, cfg_reason = explain_config(fd.path, src_root)
            if ok_cfg and ok_cont:
                fd.status = FileStatus.EXPLAINED.value
                fd.explained_by = ExplainedBy.CONFIG.value
                fd.reason = f"{cfg_reason}; {cont_reason}"
                explained_count += 1
                continue

            # d. General Containment
            if ok_cont and not fd.findings:
                fd.status = FileStatus.EXPLAINED.value
                fd.explained_by = ExplainedBy.CONTAINMENT.value
                fd.reason = cont_reason
                explained_count += 1
                continue

        if fd.findings:
            fd.status = FileStatus.SUSPICIOUS.value
            suspicious_count += 1
        elif fd.explained_by == ExplainedBy.NONE.value and fd.bucket == FileBucket.ADDED.value:
            fd.reason = "Added file not present in source repository and not declared by build config"

    # 5. Score computation
    from pkgtruth.score import score_analysis
    source_resolved = package_info.source_resolution != "unresolved"
    score, verdict, headline = score_analysis(file_diffs, provenance_info, source_resolved)

    summary_counts = SummaryCounts(
        identical=counts["identical"],
        modified=counts["modified"],
        added=counts["added"],
        missing=counts["missing"],
        explained=explained_count,
        suspicious=suspicious_count,
    )

    # 6. AI Explanations
    ai_report = AIReport(
        model=os.getenv("PKGTRUTH_MODEL", "qwen2.5-coder:7b") if not no_llm else "",
        used=not no_llm,
        explanations=[],
    )

    for fd in file_diffs:
        if fd.status == FileStatus.SUSPICIOUS.value:
            actual_f = pkg_root / fd.path
            exp = explain_findings_with_llm(fd, actual_f, no_llm=no_llm)
            ai_report.explanations.append(exp)

    report = Report(
        schema_version="1.0",
        package=package_info,
        summary=Summary(
            verdict=verdict,
            score=score,
            headline=headline,
            counts=summary_counts,
        ),
        provenance=provenance_info,
        capabilities=CapabilityReport(
            source=src_caps,
            package=pkg_caps,
            gained=gained_caps,
        ),
        files=file_diffs,
        ai=ai_report,
        generated_at=datetime.now(timezone.utc).isoformat(),
    )
    return report


def exit_code_for_verdict(verdict: str, fail_on: str = "high") -> int:
    """Determine CLI exit code based on verdict and fail_on setting."""
    v_upper = verdict.upper()
    fail_on_lower = fail_on.lower()

    if fail_on_lower == "medium":
        if v_upper in ("MEDIUM", "HIGH"):
            return 1 if v_upper == "MEDIUM" else 2
        return 0

    # Default fail_on == "high"
    if v_upper == "HIGH":
        return 2
    elif v_upper == "MEDIUM":
        return 1
    return 0


def run_file_analysis(
    package_file: str,
    source_dir: Optional[str] = None,
    repo_url: Optional[str] = None,
    ref: Optional[str] = None,
    json_out: Optional[str] = None,
    no_llm: bool = False,
    fail_on: str = "high",
) -> int:
    """Analyze a local archive file against local source directory or git repository."""
    pkg_path = Path(package_file).resolve()
    if not pkg_path.exists():
        print(f"Error: Package archive file not found: {package_file}", file=sys.stderr)
        return 3

    temp_dirs_to_clean = []
    try:
        # Extract archive
        pkg_extract_dir = Path(tempfile.mkdtemp(prefix="pkgtruth_pkg_"))
        temp_dirs_to_clean.append(pkg_extract_dir)
        extract(str(pkg_path), str(pkg_extract_dir))

        # Resolve source
        resolved_src_dir: Optional[Path] = None
        resolution_strategy = "unresolved"
        commit_ref = ref or ""

        if source_dir:
            resolved_src_dir = Path(source_dir).resolve()
            if not resolved_src_dir.exists():
                print(f"Error: Source directory not found: {source_dir}", file=sys.stderr)
                return 3
            resolution_strategy = "local"
        elif repo_url:
            clone_dir = Path(tempfile.mkdtemp(prefix="pkgtruth_git_"))
            temp_dirs_to_clean.append(clone_dir)
            resolved_src_dir, resolution_strategy, commit_ref = resolve_source_tree(
                repo_url=repo_url,
                package_name=pkg_path.stem,
                version="1.0.0",
                explicit_ref=ref,
                dest_dir=clone_dir
            )
        else:
            print("Error: Either --source-dir or --repo must be provided.", file=sys.stderr)
            return 3

        if not resolved_src_dir or not resolved_src_dir.exists():
            print(f"Warning: Could not clone or resolve source repository {repo_url}. Analyzing with empty source.", file=sys.stderr)
            dummy_src = Path(tempfile.mkdtemp(prefix="pkgtruth_empty_"))
            temp_dirs_to_clean.append(dummy_src)
            resolved_src_dir = dummy_src
            resolution_strategy = "unresolved"

        pkg_info = PackageInfo(
            ecosystem="npm" if pkg_path.suffix in (".tgz", ".tar", ".gz") else "pypi",
            name=pkg_path.name.split("-")[0],
            version="unknown",
            repo=repo_url or "",
            commit=commit_ref,
            source_resolution=resolution_strategy,
        )

        provenance = ProvenanceInfo(attestation_present=False, notes=["Local file analysis"])
        report = analyze_extracted_trees(pkg_extract_dir, resolved_src_dir, pkg_info, provenance, no_llm=no_llm)

        print(format_terminal_report(report))
        if json_out:
            Path(json_out).parent.mkdir(parents=True, exist_ok=True)
            Path(json_out).write_text(report.to_json(), encoding="utf-8")
            print(f"Report saved to {json_out}")

        return exit_code_for_verdict(report.summary.verdict, fail_on)

    finally:
        for d in temp_dirs_to_clean:
            shutil.rmtree(d, ignore_errors=True)


def run_npm_analysis(
    package_name: str,
    version: str,
    json_out: Optional[str] = None,
    no_llm: bool = False,
    offline: bool = False,
    fail_on: str = "high",
) -> int:
    """Analyze a published package from the npm registry against its source repo."""
    if offline:
        print("Error: Cannot fetch from npm registry in offline mode. Use 'pkgtruth file ...' for offline analysis.", file=sys.stderr)
        return 3

    plugin = NpmPlugin()
    print(f"Fetching metadata for npm package {package_name}@{version}...")
    meta = plugin.fetch_metadata(package_name, version)
    if not meta or "_fetch_error" in meta:
        err = meta.get("_fetch_error", "Package or version not found on npm")
        print(f"Error fetching npm package: {err}", file=sys.stderr)
        return 3

    # Resolve latest version string if requested
    actual_version = meta.get("version", version)
    repo_url, git_head, resolution = plugin.resolve_source(meta)
    provenance = plugin.get_provenance(package_name, actual_version)

    temp_dirs = []
    try:
        download_dir = Path(tempfile.mkdtemp(prefix="pkgtruth_dl_"))
        temp_dirs.append(download_dir)
        tarball_path = plugin.download(package_name, actual_version, download_dir)

        pkg_extract_dir = Path(tempfile.mkdtemp(prefix="pkgtruth_pkg_"))
        temp_dirs.append(pkg_extract_dir)
        extract(str(tarball_path), str(pkg_extract_dir))

        # Clone matching source tree
        src_clone_dir = Path(tempfile.mkdtemp(prefix="pkgtruth_src_"))
        temp_dirs.append(src_clone_dir)

        resolved_src_dir, resolved_strategy, resolved_commit = resolve_source_tree(
            repo_url=repo_url,
            package_name=package_name,
            version=actual_version,
            git_head=git_head,
            dest_dir=src_clone_dir
        )

        if not resolved_src_dir or not resolved_src_dir.exists():
            dummy = Path(tempfile.mkdtemp(prefix="pkgtruth_dummy_"))
            temp_dirs.append(dummy)
            resolved_src_dir = dummy
            resolved_strategy = "unresolved"
            resolved_commit = ""

        pkg_info = PackageInfo(
            ecosystem="npm",
            name=package_name,
            version=actual_version,
            repo=repo_url,
            commit=resolved_commit or git_head,
            source_resolution=resolved_strategy,
        )

        report = analyze_extracted_trees(pkg_extract_dir, resolved_src_dir, pkg_info, provenance, no_llm=no_llm)
        print(format_terminal_report(report))

        if json_out:
            Path(json_out).parent.mkdir(parents=True, exist_ok=True)
            Path(json_out).write_text(report.to_json(), encoding="utf-8")
            print(f"Report saved to {json_out}")

        return exit_code_for_verdict(report.summary.verdict, fail_on)

    finally:
        for d in temp_dirs:
            shutil.rmtree(d, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(
        prog="pkgtruth",
        description="PkgTruth: Published Package vs Source Code Integrity Analyzer"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # 1. npm command
    npm_p = subparsers.add_parser("npm", help="Analyze package from npm registry")
    npm_p.add_argument("name", help="Package name (e.g. express, @types/node)")
    npm_p.add_argument("version", help="Package version (e.g. 1.0.0)")
    npm_p.add_argument("--json", dest="json_out", help="Path to write JSON report output")
    npm_p.add_argument("--no-llm", action="store_true", help="Disable local Ollama LLM queries")
    npm_p.add_argument("--offline", action="store_true", help="Run without network calls")
    npm_p.add_argument("--fail-on", choices=["medium", "high"], default="high", help="Exit code failure threshold")

    # 2. file command
    file_p = subparsers.add_parser("file", help="Analyze local package archive (.tgz, .zip, .whl)")
    file_p.add_argument("package_file", help="Path to package archive file")
    file_p.add_argument("--source-dir", help="Path to local source code directory")
    file_p.add_argument("--repo", help="Git repository URL")
    file_p.add_argument("--ref", help="Git branch, tag, or commit hash")
    file_p.add_argument("--json", dest="json_out", help="Path to write JSON report output")
    file_p.add_argument("--no-llm", action="store_true", help="Disable local Ollama LLM queries")
    file_p.add_argument("--fail-on", choices=["medium", "high"], default="high", help="Exit code failure threshold")

    # 3. report command
    rep_p = subparsers.add_parser("report", help="Pretty print a saved report in the terminal")
    rep_p.add_argument("report_json", help="Path to report JSON file")

    # 4. html command
    html_p = subparsers.add_parser("html", help="Generate standalone HTML report")
    html_p.add_argument("report_json", help="Path to report JSON file")
    html_p.add_argument("-o", "--output", default="report.html", help="Output HTML file path")

    # 5. watch command
    watch_p = subparsers.add_parser("watch", help="Check packages in watchlist file")
    watch_p.add_argument("watchlist_file", help="Path to watchlist YAML file")
    watch_p.add_argument("--json", dest="json_out", help="Directory or file for report outputs")
    watch_p.add_argument("--no-llm", action="store_true", help="Disable local Ollama LLM queries")
    watch_p.add_argument("--fail-on", choices=["medium", "high"], default="medium")

    args = parser.parse_args()

    try:
        if args.command == "npm":
            code = run_npm_analysis(
                package_name=args.name,
                version=args.version,
                json_out=args.json_out,
                no_llm=args.no_llm,
                offline=args.offline,
                fail_on=args.fail_on,
            )
            sys.exit(code)

        elif args.command == "file":
            code = run_file_analysis(
                package_file=args.package_file,
                source_dir=args.source_dir,
                repo_url=args.repo,
                ref=args.ref,
                json_out=args.json_out,
                no_llm=args.no_llm,
                fail_on=args.fail_on,
            )
            sys.exit(code)

        elif args.command == "report":
            path = Path(args.report_json)
            if not path.exists():
                print(f"Error: File not found: {args.report_json}", file=sys.stderr)
                sys.exit(3)
            data = json.loads(path.read_text(encoding="utf-8"))
            rep = Report.from_dict(data)
            print(format_terminal_report(rep))
            sys.exit(0)

        elif args.command == "html":
            path = Path(args.report_json)
            if not path.exists():
                print(f"Error: File not found: {args.report_json}", file=sys.stderr)
                sys.exit(3)
            data = json.loads(path.read_text(encoding="utf-8"))
            rep = Report.from_dict(data)
            html_content = generate_html_report(rep)
            Path(args.output).write_text(html_content, encoding="utf-8")
            print(f"HTML report generated at {args.output}")
            sys.exit(0)

        elif args.command == "watch":
            from pkgtruth.monitor import run_watchlist
            code = run_watchlist(Path(args.watchlist_file), no_llm_override=args.no_llm)
            sys.exit(code)

    except KeyboardInterrupt:
        print("\nAnalysis interrupted by user.", file=sys.stderr)
        sys.exit(3)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(3)


if __name__ == "__main__":
    main()
