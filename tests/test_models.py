"""Tests for data models and report serialization."""

import json

from pkgtruth.models import (
    AIReport,
    CapabilityReport,
    FileDiff,
    Finding,
    GainedCapability,
    PackageInfo,
    ProvenanceInfo,
    Report,
    Summary,
    SummaryCounts,
)


class TestFinding:
    """Tests for the Finding dataclass."""

    def test_creation(self):
        f = Finding(
            id="install_hook_added",
            severity="high",
            rule="install_hooks",
            line=5,
            snippet='  "postinstall": "node payload.js"',
            reason="New postinstall script added in package.json",
            weight=40,
        )
        assert f.id == "install_hook_added"
        assert f.weight == 40

    def test_defaults(self):
        f = Finding(id="test", severity="low", rule="test_rule")
        assert f.line == 0
        assert f.snippet == ""
        assert f.weight == 0


class TestFileDiff:
    """Tests for the FileDiff dataclass."""

    def test_add_finding_sets_suspicious(self):
        fd = FileDiff(path="dist/index.js", bucket="modified")
        assert fd.status == "normal"
        
        fd.add_finding(Finding(
            id="exec_gained", severity="high",
            rule="behavior", weight=25
        ))
        assert fd.status == "suspicious"
        assert len(fd.findings) == 1

    def test_add_low_finding_stays_normal(self):
        fd = FileDiff(path="LICENSE", bucket="added")
        fd.add_finding(Finding(
            id="info", severity="low",
            rule="metadata_only", weight=0
        ))
        assert fd.status == "normal"


class TestReport:
    """Tests for report serialization and deserialization."""

    def _make_report(self) -> Report:
        report = Report()
        report.package = PackageInfo(
            ecosystem="npm", name="test-pkg",
            version="1.0.0",
            repo="https://github.com/example/test-pkg",
            commit="abc123",
            source_resolution="gitHead",
        )
        report.summary = Summary(
            verdict="LOW", score=5,
            headline="Clean release",
            counts=SummaryCounts(identical=10, modified=1),
        )
        report.provenance = ProvenanceInfo(attestation_present=False)
        report.capabilities = CapabilityReport(
            source={"NETWORK": ["lodash"]},
            package={"NETWORK": ["lodash"]},
            gained=[],
        )
        report.files = [
            FileDiff(path="package.json", bucket="modified",
                    status="explained", explained_by="metadata_only"),
        ]
        report.ai = AIReport(model="", used=False)
        return report

    def test_round_trip(self):
        """A report survives serialization and deserialization."""
        original = self._make_report()
        json_str = original.to_json()
        data = json.loads(json_str)
        restored = Report.from_dict(data)
        
        assert restored.package.name == "test-pkg"
        assert restored.summary.verdict == "LOW"
        assert restored.summary.counts.identical == 10
        assert len(restored.files) == 1
        assert restored.files[0].explained_by == "metadata_only"

    def test_schema_version(self):
        report = self._make_report()
        data = report.to_dict()
        assert data["schema_version"] == "1.0"

    def test_generated_at_auto_filled(self):
        report = self._make_report()
        data = report.to_dict()
        assert data["generated_at"] != ""

    def test_to_json_is_valid(self):
        report = self._make_report()
        parsed = json.loads(report.to_json())
        assert parsed["package"]["ecosystem"] == "npm"
        assert parsed["summary"]["counts"]["identical"] == 10
