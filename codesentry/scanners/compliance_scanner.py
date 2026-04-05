"""Compliance and ASVS verification scanner."""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional, Set

from codesentry.cwe_mapping import enrich_finding, get_cwe_entry
from codesentry.models import (
    Finding,
    ScannerType,
    ScanResult,
    Severity,
)
from codesentry.scanners.base_scanner import BaseScanner

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# OWASP ASVS v5.0 category → CWE mapping
# ---------------------------------------------------------------------------

_ASVS_CATEGORIES: Dict[str, Dict[str, Any]] = {
    "V2-Authentication": {
        "name": "V2: Authentication",
        "cwes": {287, 798, 306},
        "description": "Verify authentication mechanisms are strong and properly implemented.",
    },
    "V3-Session-Management": {
        "name": "V3: Session Management",
        "cwes": {384, 613},
        "description": "Verify session management is secure and sessions are properly invalidated.",
    },
    "V4-Access-Control": {
        "name": "V4: Access Control",
        "cwes": {862, 863, 639},
        "description": "Verify access controls are enforced at a trusted server-side layer.",
    },
    "V5-Validation": {
        "name": "V5: Validation, Sanitization and Encoding",
        "cwes": {79, 89, 78, 94},
        "description": "Verify all input is validated, sanitized, and output is encoded.",
    },
    "V6-Cryptography": {
        "name": "V6: Stored Cryptography",
        "cwes": {327, 328, 330, 311},
        "description": "Verify cryptographic controls are properly implemented.",
    },
    "V8-Data-Protection": {
        "name": "V8: Data Protection",
        "cwes": {200, 312, 319},
        "description": "Verify sensitive data is protected in transit and at rest.",
    },
    "V9-Communication": {
        "name": "V9: Communication Security",
        "cwes": {319, 295},
        "description": "Verify all communications use TLS and certificates are validated.",
    },
    "V14-Configuration": {
        "name": "V14: Configuration",
        "cwes": {16, 489},
        "description": "Verify the application is securely configured.",
    },
}

# Build a reverse map: CWE → list of ASVS categories
_CWE_TO_ASVS: Dict[int, List[str]] = {}
for _cat_id, _cat in _ASVS_CATEGORIES.items():
    for _cwe_id in _cat["cwes"]:
        _CWE_TO_ASVS.setdefault(_cwe_id, []).append(_cat_id)


class ComplianceScanner(BaseScanner):
    """Map findings to OWASP ASVS v5.0 and generate a compliance scorecard."""

    scanner_type = ScannerType.COMPLIANCE

    async def scan(self, path: str, **kwargs) -> ScanResult:
        result = self._create_result()
        start = time.time()

        existing_findings: List[Finding] = kwargs.get("existing_findings", [])

        try:
            scorecard = self._build_scorecard(existing_findings, result)
            # Summary stored in a dedicated finding
            summary = self._summarise(scorecard)
            result.findings.append(
                Finding(
                    scanner=ScannerType.COMPLIANCE,
                    rule_id="ASVS-SUMMARY",
                    title=f"ASVS Compliance: {summary['passed']}/{summary['total_categories']} categories passed ({summary['compliance_pct']}%)",
                    description=(
                        f"Passed: {summary['passed']}, Failed: {summary['failed']}, "
                        f"Total categories: {summary['total_categories']}"
                    ),
                    severity=Severity.INFO if summary['failed'] == 0 else Severity.HIGH,
                    confidence="HIGH",
                )
            )
        except Exception as exc:
            result.errors.append(f"Compliance scan error: {exc}")
            logger.exception("Compliance scan failed")

        result.duration_seconds = round(time.time() - start, 3)
        result.findings = [enrich_finding(f) for f in result.findings]
        return result

    # -- Scorecard generation ----------------------------------------------

    def _build_scorecard(
        self,
        existing_findings: List[Finding],
        result: ScanResult,
    ) -> Dict[str, Dict[str, Any]]:
        """Build a pass/fail scorecard per ASVS category based on findings."""
        scorecard: Dict[str, Dict[str, Any]] = {}

        # Collect all CWEs from existing findings
        finding_cwes: Dict[int, List[Finding]] = {}
        for f in existing_findings:
            cwe_id = self._extract_cwe_id(f)
            if cwe_id is not None:
                finding_cwes.setdefault(cwe_id, []).append(f)

        for cat_id, cat_info in _ASVS_CATEGORIES.items():
            mapped_findings: List[Finding] = []
            for cwe_id in cat_info["cwes"]:
                mapped_findings.extend(finding_cwes.get(cwe_id, []))

            status = "FAIL" if mapped_findings else "PASS"
            critical_or_high = sum(
                1
                for f in mapped_findings
                if f.severity in (Severity.CRITICAL, Severity.HIGH, "CRITICAL", "HIGH")
            )

            scorecard[cat_id] = {
                "name": cat_info["name"],
                "description": cat_info["description"],
                "status": status,
                "finding_count": len(mapped_findings),
                "critical_high_count": critical_or_high,
                "cwes_checked": sorted(cat_info["cwes"]),
            }

            # Emit a compliance finding per category
            if status == "FAIL":
                worst_severity = self._worst_severity(mapped_findings)
                sample_cwes = sorted({
                    self._extract_cwe_id(f)
                    for f in mapped_findings
                    if self._extract_cwe_id(f) is not None
                })
                result.findings.append(
                    Finding(
                        scanner=ScannerType.COMPLIANCE,
                        rule_id=f"ASVS-{cat_id}",
                        title=f"{cat_info['name']}: {len(mapped_findings)} finding(s)",
                        description=(
                            f"ASVS category {cat_info['name']} has {len(mapped_findings)} "
                            f"finding(s) ({critical_or_high} critical/high). "
                            f"Related CWEs: {', '.join(f'CWE-{c}' for c in sample_cwes)}."
                        ),
                        severity=worst_severity,
                        recommendation=(
                            f"Address the {len(mapped_findings)} finding(s) related to "
                            f"{cat_info['name']} to achieve compliance."
                        ),
                        confidence="HIGH",
                        metadata={
                            "asvs_category": cat_id,
                            "finding_count": len(mapped_findings),
                            "cwes": sample_cwes,
                        },
                    )
                )
            else:
                result.findings.append(
                    Finding(
                        scanner=ScannerType.COMPLIANCE,
                        rule_id=f"ASVS-{cat_id}",
                        title=f"{cat_info['name']}: PASS",
                        description=(
                            f"No findings detected for ASVS category {cat_info['name']}."
                        ),
                        severity=Severity.INFO,
                        confidence="HIGH",
                        metadata={
                            "asvs_category": cat_id,
                            "status": "PASS",
                        },
                    )
                )

        return scorecard

    def _summarise(
        self, scorecard: Dict[str, Dict[str, Any]]
    ) -> Dict[str, Any]:
        total = len(scorecard)
        passed = sum(1 for v in scorecard.values() if v["status"] == "PASS")
        failed = total - passed
        return {
            "total_categories": total,
            "passed": passed,
            "failed": failed,
            "compliance_pct": round(passed / total * 100, 1) if total else 0.0,
        }

    # -- Helpers -----------------------------------------------------------

    @staticmethod
    def _extract_cwe_id(finding: Finding) -> Optional[int]:
        """Extract the numeric CWE ID from a Finding."""
        if finding.cwe is not None:
            cwe_str = finding.cwe.id  # e.g. "CWE-89"
            try:
                return int(cwe_str.split("-")[1])
            except (IndexError, ValueError):
                pass
        return None

    @staticmethod
    def _worst_severity(findings: List[Finding]) -> Severity:
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        for sev in order:
            if any(f.severity == sev or f.severity == sev.value for f in findings):
                return sev
        return Severity.INFO
