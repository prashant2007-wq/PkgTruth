"""Data models for PkgTruth analysis reports.

Defines the complete type hierarchy for package analysis results,
from individual file findings up to the full JSON-serializable report.
"""

from dataclasses import dataclass, field, asdict
from typing import Optional
from enum import Enum
import json
from datetime import datetime, timezone


class Verdict(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class Severity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class FileBucket(Enum):
    IDENTICAL = "identical"
    MODIFIED = "modified"
    ADDED = "added"
    MISSING = "missing"


class FileStatus(Enum):
    NORMAL = "normal"
    EXPLAINED = "explained"
    SUSPICIOUS = "suspicious"


class ExplainedBy(Enum):
    SOURCEMAP = "sourcemap"
    CONFIG = "config"
    CONTAINMENT = "containment"
    METADATA_ONLY = "metadata_only"
    NONE = "none"


class CapabilityCategory(Enum):
    NETWORK = "NETWORK"
    EXEC = "EXEC"
    EVAL = "EVAL"
    FS_SENSITIVE = "FS_SENSITIVE"
    ENV_ACCESS = "ENV_ACCESS"
    INSTALL_HOOK = "INSTALL_HOOK"
    NEW_DEPENDENCY = "NEW_DEPENDENCY"
    NATIVE_BINARY = "NATIVE_BINARY"
    DYNAMIC_REQUIRE = "DYNAMIC_REQUIRE"
    OBFUSCATION = "OBFUSCATION"


class SourceResolution(Enum):
    PROVENANCE = "provenance"
    GITHEAD = "gitHead"
    TAG = "tag"
    LOCAL = "local"
    UNRESOLVED = "unresolved"


@dataclass
class Finding:
    """A single risk finding attached to a file."""
    id: str
    severity: str  # "low", "medium", "high"
    rule: str
    line: int = 0
    snippet: str = ""
    reason: str = ""
    weight: int = 0


@dataclass
class FileDiff:
    """Comparison result for a single file."""
    path: str
    bucket: str  # "identical", "modified", "added", "missing"
    status: str = "normal"  # "normal", "explained", "suspicious"
    explained_by: str = "none"
    reason: str = ""
    findings: list = field(default_factory=list)  # List[Finding]
    source_hash: str = ""
    package_hash: str = ""

    def add_finding(self, finding: Finding):
        self.findings.append(finding)
        if finding.severity == "high":
            self.status = "suspicious"
        elif finding.severity == "medium" and self.status != "suspicious":
            self.status = "suspicious"


@dataclass
class Capability:
    """A single capability detected in code."""
    category: str  # CapabilityCategory value
    detail: str
    file: str
    line: int = 0


@dataclass
class GainedCapability:
    """A capability present in the package but not in the source."""
    category: str
    detail: str
    file: str
    line: int = 0


@dataclass
class CapabilityReport:
    """Comparison of capabilities between source and package."""
    source: dict = field(default_factory=dict)  # category -> list of details
    package: dict = field(default_factory=dict)
    gained: list = field(default_factory=list)  # List[GainedCapability]


@dataclass
class AIQuote:
    """A quote from the model's explanation, with verification status."""
    text: str
    line: int = 0
    verified: bool = False


@dataclass
class AIExplanation:
    """Model explanation for a specific file."""
    file: str
    text: str
    quotes: list = field(default_factory=list)  # List[AIQuote]


@dataclass
class AIReport:
    """Summary of AI model usage in the analysis."""
    model: str = ""
    used: bool = False
    explanations: list = field(default_factory=list)  # List[AIExplanation]


@dataclass
class ProvenanceInfo:
    """Provenance attestation information."""
    attestation_present: bool = False
    repo_match: Optional[bool] = None
    commit_match: Optional[bool] = None
    notes: list = field(default_factory=list)


@dataclass
class PackageInfo:
    """Metadata about the analyzed package."""
    ecosystem: str = ""
    name: str = ""
    version: str = ""
    repo: str = ""
    commit: str = ""
    source_resolution: str = "unresolved"


@dataclass
class SummaryCounts:
    """File counts by category."""
    identical: int = 0
    modified: int = 0
    added: int = 0
    missing: int = 0
    explained: int = 0
    suspicious: int = 0


@dataclass
class Summary:
    """Overall analysis summary."""
    verdict: str = "LOW"
    score: int = 0
    headline: str = ""
    counts: SummaryCounts = field(default_factory=SummaryCounts)


@dataclass
class Report:
    """Complete analysis report matching the JSON schema."""
    schema_version: str = "1.0"
    package: PackageInfo = field(default_factory=PackageInfo)
    summary: Summary = field(default_factory=Summary)
    provenance: ProvenanceInfo = field(default_factory=ProvenanceInfo)
    capabilities: CapabilityReport = field(default_factory=CapabilityReport)
    files: list = field(default_factory=list)  # List[FileDiff]
    ai: AIReport = field(default_factory=AIReport)
    generated_at: str = ""

    def to_dict(self) -> dict:
        """Serialize the report to a dictionary matching the JSON schema."""
        d = asdict(self)
        if not d["generated_at"]:
            d["generated_at"] = datetime.now(timezone.utc).isoformat()
        return d

    def to_json(self, indent: int = 2) -> str:
        """Serialize the report to a JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: dict) -> "Report":
        """Deserialize a report from a dictionary."""
        report = cls()
        report.schema_version = data.get("schema_version", "1.0")
        report.generated_at = data.get("generated_at", "")

        pkg = data.get("package", {})
        report.package = PackageInfo(**{k: v for k, v in pkg.items()
                                        if k in PackageInfo.__dataclass_fields__})

        summ = data.get("summary", {})
        counts_data = summ.pop("counts", {})
        counts = SummaryCounts(**{k: v for k, v in counts_data.items()
                                   if k in SummaryCounts.__dataclass_fields__})
        report.summary = Summary(
            verdict=summ.get("verdict", "LOW"),
            score=summ.get("score", 0),
            headline=summ.get("headline", ""),
            counts=counts,
        )

        prov = data.get("provenance", {})
        report.provenance = ProvenanceInfo(**{k: v for k, v in prov.items()
                                              if k in ProvenanceInfo.__dataclass_fields__})

        caps = data.get("capabilities", {})
        cap_report = CapabilityReport()
        cap_report.source = caps.get("source", {})
        cap_report.package = caps.get("package", {})
        cap_report.gained = [
            GainedCapability(**g) for g in caps.get("gained", [])
        ]
        report.capabilities = cap_report

        for f in data.get("files", []):
            findings = [Finding(**fd) for fd in f.get("findings", [])]
            fd = FileDiff(
                path=f["path"],
                bucket=f["bucket"],
                status=f.get("status", "normal"),
                explained_by=f.get("explained_by", "none"),
                reason=f.get("reason", ""),
                findings=findings,
                source_hash=f.get("source_hash", ""),
                package_hash=f.get("package_hash", ""),
            )
            report.files.append(fd)

        ai = data.get("ai", {})
        ai_report = AIReport(
            model=ai.get("model", ""),
            used=ai.get("used", False),
        )
        for exp in ai.get("explanations", []):
            quotes = [AIQuote(**q) for q in exp.get("quotes", [])]
            ai_report.explanations.append(AIExplanation(
                file=exp["file"],
                text=exp["text"],
                quotes=quotes,
            ))
        report.ai = ai_report

        return report
