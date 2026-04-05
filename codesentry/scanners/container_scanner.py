"""Container image scanner — Trivy → Grype → Dockerfile fallback."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from codesentry.cwe_mapping import enrich_finding, get_cwe_entry
from codesentry.models import (
    Finding,
    ScannerType,
    ScanResult,
    Severity,
)
from codesentry.scanners.base_scanner import BaseScanner

logger = logging.getLogger(__name__)


class ContainerScanner(BaseScanner):
    """Scan container images for vulnerabilities.

    Resolution order:
    1. Trivy (if installed)
    2. Grype (if installed)
    3. Dockerfile analysis (deferred to IaCScanner logic)
    """

    scanner_type = ScannerType.CONTAINER

    async def scan(self, path: str, **kwargs) -> ScanResult:
        result = self._create_result()
        start = time.time()
        image: Optional[str] = kwargs.get("image")

        try:
            if image:
                if self._check_tool_available("trivy"):
                    await self._run_trivy(image, result)
                elif self._check_tool_available("grype"):
                    await self._run_grype(image, result)
                else:
                    result.errors.append("[warning] Neither trivy nor grype found; falling back to Dockerfile analysis.")
                    self._scan_dockerfiles(path, result)
            else:
                result.errors.append("[warning] No container image specified; scanning Dockerfiles instead.")
                self._scan_dockerfiles(path, result)
        except Exception as exc:
            result.errors.append(f"Container scan error: {exc}")
            logger.exception("Container scan failed")

        result.duration_seconds = round(time.time() - start, 3)
        result.findings = [enrich_finding(f) for f in result.findings]
        return result

    # -- Trivy -------------------------------------------------------------

    async def _run_trivy(self, image: str, result: ScanResult) -> None:
        cmd = ["trivy", "image", "--format", "json", image]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
        except (FileNotFoundError, OSError) as exc:
            result.errors.append(f"Failed to run trivy: {exc}")
            return

        if proc.returncode not in (0, 1):
            result.errors.append(
                f"trivy exited {proc.returncode}: "
                f"{stderr.decode(errors='replace')[:500]}"
            )
            return

        try:
            data = json.loads(stdout.decode(errors="replace"))
        except json.JSONDecodeError as exc:
            result.errors.append(f"Failed to parse trivy JSON: {exc}")
            return

        results_list = data.get("Results", [])
        for target in results_list:
            for vuln in target.get("Vulnerabilities", []):
                sev = _map_trivy_severity(vuln.get("Severity", "UNKNOWN"))
                cve_id = vuln.get("VulnerabilityID", "")
                result.findings.append(
                    Finding(
                        scanner=ScannerType.CONTAINER,
                        rule_id=cve_id,
                        title=vuln.get("Title", cve_id),
                        description=vuln.get("Description", "")[:500],
                        severity=sev,
                        file_path=target.get("Target", image),
                        cve_id=cve_id if cve_id.startswith("CVE") else None,
                        package_name=vuln.get("PkgName"),
                        package_version=vuln.get("InstalledVersion"),
                        fixed_version=vuln.get("FixedVersion"),
                        cwe=get_cwe_entry("CWE-1035"),
                        confidence="HIGH",
                        metadata={
                            "data_source": vuln.get("DataSource", {}),
                            "cvss": vuln.get("CVSS", {}),
                        },
                    )
                )

    # -- Grype -------------------------------------------------------------

    async def _run_grype(self, image: str, result: ScanResult) -> None:
        cmd = ["grype", image, "-o", "json"]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
        except (FileNotFoundError, OSError) as exc:
            result.errors.append(f"Failed to run grype: {exc}")
            return

        if proc.returncode not in (0, 1):
            result.errors.append(
                f"grype exited {proc.returncode}: "
                f"{stderr.decode(errors='replace')[:500]}"
            )
            return

        try:
            data = json.loads(stdout.decode(errors="replace"))
        except json.JSONDecodeError as exc:
            result.errors.append(f"Failed to parse grype JSON: {exc}")
            return

        for match in data.get("matches", []):
            vuln = match.get("vulnerability", {})
            artifact = match.get("artifact", {})
            sev = _map_grype_severity(vuln.get("severity", "Unknown"))
            cve_id = vuln.get("id", "")
            fix_versions = vuln.get("fix", {}).get("versions", [])

            result.findings.append(
                Finding(
                    scanner=ScannerType.CONTAINER,
                    rule_id=cve_id,
                    title=vuln.get("description", cve_id)[:120],
                    description=vuln.get("description", "")[:500],
                    severity=sev,
                    file_path=artifact.get("locations", [{}])[0].get("path", image)
                    if artifact.get("locations")
                    else image,
                    cve_id=cve_id if cve_id.startswith("CVE") else None,
                    package_name=artifact.get("name"),
                    package_version=artifact.get("version"),
                    fixed_version=fix_versions[0] if fix_versions else None,
                    cwe=get_cwe_entry("CWE-1035"),
                    confidence="HIGH",
                )
            )

    # -- Dockerfile fallback -----------------------------------------------

    def _scan_dockerfiles(self, path: str, result: ScanResult) -> None:
        """Scan Dockerfiles found in the project for common issues."""
        from codesentry.scanners.iac_scanner import IaCScanner

        iac = IaCScanner(config=self.config)
        root = Path(path)
        iac._scan_dockerfiles(root, result)
        # Re-tag findings as CONTAINER scanner
        for finding in result.findings:
            if finding.scanner == ScannerType.IAC:
                finding.scanner = ScannerType.CONTAINER


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _map_trivy_severity(sev: str) -> Severity:
    return {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
        "UNKNOWN": Severity.INFO,
    }.get(sev.upper(), Severity.MEDIUM)


def _map_grype_severity(sev: str) -> Severity:
    return {
        "Critical": Severity.CRITICAL,
        "High": Severity.HIGH,
        "Medium": Severity.MEDIUM,
        "Low": Severity.LOW,
        "Negligible": Severity.INFO,
    }.get(sev, Severity.MEDIUM)



