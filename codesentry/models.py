"""Pydantic models for CodeSentry scan results."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


class Severity(str, Enum):
    """Severity levels for security findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ScannerType(str, Enum):
    """Types of security scanners."""

    CODE = "CODE"
    DEPENDENCY = "DEPENDENCY"
    SECRET = "SECRET"
    IAC = "IAC"
    CONTAINER = "CONTAINER"
    LICENSE = "LICENSE"
    DAST = "DAST"
    API = "API"
    SUPPLY_CHAIN = "SUPPLY_CHAIN"
    COMPLIANCE = "COMPLIANCE"


class CWEEntry(BaseModel):
    """Common Weakness Enumeration entry."""

    model_config = ConfigDict(use_enum_values=True)

    id: str = Field(..., description="CWE identifier, e.g. 'CWE-79'")
    name: str = Field(..., description="Short name of the weakness")
    description: Optional[str] = Field(
        default=None, description="Detailed description of the weakness"
    )


class OWASPCategory(BaseModel):
    """OWASP Top-10 category reference."""

    model_config = ConfigDict(use_enum_values=True)

    id: str = Field(..., description="OWASP category id, e.g. 'A01'")
    year: int = Field(default=2025, description="OWASP Top-10 edition year")
    name: str = Field(..., description="Category name")
    description: Optional[str] = Field(
        default=None, description="Category description"
    )


class Finding(BaseModel):
    """A single security finding produced by a scanner."""

    model_config = ConfigDict(use_enum_values=True)

    id: str = Field(default_factory=lambda: str(uuid4()))
    scanner: ScannerType
    title: str
    description: str
    severity: Severity

    # Location
    file_path: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None

    # Classification
    cwe: Optional[CWEEntry] = None
    owasp: Optional[OWASPCategory] = None
    cvss_score: Optional[float] = None
    cve_id: Optional[str] = None

    # Dependency-specific
    package_name: Optional[str] = None
    package_version: Optional[str] = None
    fixed_version: Optional[str] = None

    # Context
    evidence: Optional[str] = Field(
        default=None, description="Snippet of vulnerable code or config"
    )
    recommendation: Optional[str] = None
    rule_id: Optional[str] = None
    confidence: str = Field(
        default="HIGH", description="Confidence level: HIGH, MEDIUM, LOW"
    )
    metadata: Dict[str, object] = Field(default_factory=dict)


class ScanResult(BaseModel):
    """Aggregated result from a single scanner run."""

    model_config = ConfigDict(use_enum_values=True)

    scanner: ScannerType
    findings: List[Finding] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)
    duration_seconds: float = 0.0
    scanned_files: int = 0
    skipped_files: int = 0


class FullScanResult(BaseModel):
    """Combined result across all scanners for a project."""

    model_config = ConfigDict(use_enum_values=True)

    scan_results: List[ScanResult] = Field(default_factory=list)
    project_path: str
    scan_duration_seconds: float = 0.0
    scanned_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    config_used: Dict[str, object] = Field(default_factory=dict)

    @property
    def all_findings(self) -> List[Finding]:
        """Flatten findings from every scanner result."""
        return [f for sr in self.scan_results for f in sr.findings]

    @property
    def total_findings(self) -> int:
        """Total number of findings across all scanners."""
        return len(self.all_findings)

    @property
    def findings_by_severity(self) -> Dict[str, int]:
        """Count of findings grouped by severity level."""
        counts: Dict[str, int] = {s.value: 0 for s in Severity}
        for finding in self.all_findings:
            sev = (
                finding.severity
                if isinstance(finding.severity, str)
                else finding.severity.value
            )
            counts[sev] = counts.get(sev, 0) + 1
        return counts
