"""DAST scanner — ZAP → Nuclei → built-in HTTP header checks."""

from __future__ import annotations

import asyncio
import json
import logging
import time
import urllib.request
import urllib.error
import ssl
from http.client import HTTPResponse
from typing import Any, Dict, List, Optional, Tuple

from codesentry.cwe_mapping import enrich_finding, get_cwe_entry
from codesentry.models import (
    Finding,
    ScannerType,
    ScanResult,
    Severity,
)
from codesentry.scanners.base_scanner import BaseScanner

logger = logging.getLogger(__name__)

# Headers that should be present for security
_REQUIRED_HEADERS: List[Tuple[str, str, str, Severity]] = [
    (
        "Strict-Transport-Security",
        "CWE-319",
        "Missing HTTP Strict Transport Security header",
        Severity.MEDIUM,
    ),
    (
        "Content-Security-Policy",
        "CWE-693",
        "Missing Content-Security-Policy header",
        Severity.MEDIUM,
    ),
    (
        "X-Content-Type-Options",
        "CWE-693",
        "Missing X-Content-Type-Options header",
        Severity.LOW,
    ),
    (
        "X-Frame-Options",
        "CWE-1021",
        "Missing X-Frame-Options header",
        Severity.MEDIUM,
    ),
]


class DASTScanner(BaseScanner):
    """Dynamic Application Security Testing scanner.

    Resolution order:
    1. OWASP ZAP (if installed)
    2. Nuclei (if installed)
    3. Built-in HTTP header checks
    """

    scanner_type = ScannerType.DAST

    async def scan(self, path: str, **kwargs) -> ScanResult:
        result = self._create_result()
        start = time.time()
        target_url: Optional[str] = kwargs.get("target_url")

        if not target_url:
            result.errors.append(
                "DAST scan requires a 'target_url' keyword argument."
            )
            result.duration_seconds = round(time.time() - start, 3)
            return result

        try:
            if self._check_tool_available("zap-baseline.py") or self._check_tool_available("zap-cli"):
                await self._run_zap(target_url, result)
            elif self._check_tool_available("nuclei"):
                await self._run_nuclei(target_url, result)
            else:
                result.errors.append("[warning] Neither ZAP nor nuclei found; running built-in HTTP header checks.")
                await self._run_builtin_checks(target_url, result)
        except Exception as exc:
            result.errors.append(f"DAST scan error: {exc}")
            logger.exception("DAST scan failed")

        result.duration_seconds = round(time.time() - start, 3)
        result.findings = [enrich_finding(f) for f in result.findings]
        return result

    # -- ZAP ---------------------------------------------------------------

    async def _run_zap(self, url: str, result: ScanResult) -> None:
        cmd = ["zap-baseline.py", "-t", url, "-J", "zap_report.json"]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
        except (FileNotFoundError, OSError) as exc:
            result.errors.append(f"Failed to run ZAP: {exc}")
            await self._run_builtin_checks(url, result)
            return

        # ZAP returns 0 for pass, 1 for warnings, 2 for fails
        try:
            data = json.loads(stdout.decode(errors="replace"))
        except json.JSONDecodeError:
            # Try reading the output file
            try:
                from pathlib import Path as _P
                report = _P("zap_report.json")
                if report.exists():
                    data = json.loads(report.read_text(encoding="utf-8"))
                else:
                    result.errors.append("ZAP did not produce parseable JSON output.")
                    return
            except Exception as exc:
                result.errors.append(f"Failed to parse ZAP output: {exc}")
                return

        for site in data.get("site", []):
            for alert in site.get("alerts", []):
                sev = _map_zap_risk(alert.get("riskcode", "1"))
                cwe_str = f"CWE-{alert.get('cweid', '0')}"
                cwe_entry = get_cwe_entry(cwe_str) if alert.get("cweid") else None

                for instance in alert.get("instances", [{}]):
                    result.findings.append(
                        Finding(
                            scanner=ScannerType.DAST,
                            rule_id=f"ZAP-{alert.get('pluginid', '0')}",
                            title=alert.get("name", "ZAP finding"),
                            description=alert.get("desc", "")[:500],
                            severity=sev,
                            file_path=instance.get("uri", url),
                            evidence=instance.get("evidence", "")[:200],
                            cwe=cwe_entry,
                            recommendation=alert.get("solution", ""),
                            confidence=_map_zap_confidence(
                                alert.get("confidence", "2")
                            ),
                            metadata={"method": instance.get("method", "")},
                        )
                    )

    # -- Nuclei ------------------------------------------------------------

    async def _run_nuclei(self, url: str, result: ScanResult) -> None:
        cmd = [
            "nuclei", "-u", url, "-jsonl",
            "-severity", "critical,high,medium",
        ]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
        except (FileNotFoundError, OSError) as exc:
            result.errors.append(f"Failed to run nuclei: {exc}")
            await self._run_builtin_checks(url, result)
            return

        for line in stdout.decode(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue

            info = item.get("info", {})
            sev = _map_nuclei_severity(info.get("severity", "medium"))

            cwe_ids = info.get("classification", {}).get("cwe-id", [])
            cwe_str = f"CWE-{cwe_ids[0]}" if cwe_ids else None
            cwe_entry = get_cwe_entry(cwe_str) if cwe_str else None

            result.findings.append(
                Finding(
                    scanner=ScannerType.DAST,
                    rule_id=item.get("template-id", "nuclei"),
                    title=info.get("name", "Nuclei finding"),
                    description=info.get("description", "")[:500],
                    severity=sev,
                    file_path=item.get("matched-at", url),
                    evidence=item.get("extracted-results", [""])[0][:200]
                    if item.get("extracted-results")
                    else "",
                    cwe=cwe_entry,
                    recommendation=info.get("remediation", ""),
                    confidence="HIGH",
                )
            )

    # -- Built-in HTTP header checks ---------------------------------------

    async def _run_builtin_checks(self, url: str, result: ScanResult) -> None:
        headers: Dict[str, str] = {}
        cookies: List[str] = []
        server_header: Optional[str] = None

        try:
            # Allow self-signed certs for scanning
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            req = urllib.request.Request(url, method="GET")
            req.add_header("User-Agent", "CodeSentry-DAST/0.1")
            resp: HTTPResponse = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: urllib.request.urlopen(req, timeout=15, context=ctx),
            )
            for key, value in resp.getheaders():
                headers[key.lower()] = value
                if key.lower() == "set-cookie":
                    cookies.append(value)
                if key.lower() == "server":
                    server_header = value
        except urllib.error.HTTPError as exc:
            for key, value in exc.headers.items():
                headers[key.lower()] = value
                if key.lower() == "set-cookie":
                    cookies.append(value)
                if key.lower() == "server":
                    server_header = value
        except Exception as exc:
            result.errors.append(
                f"Failed to connect to {url}: {exc}"
            )
            return

        result.scanned_files += 1

        # Check required security headers
        for header_name, cwe_str, title, severity in _REQUIRED_HEADERS:
            if header_name.lower() not in headers:
                result.findings.append(
                    Finding(
                        scanner=ScannerType.DAST,
                        rule_id=f"DAST-MISSING-{header_name.upper().replace('-', '_')}",
                        title=title,
                        description=f"The response from {url} is missing the {header_name} header.",
                        severity=severity,
                        file_path=url,
                        cwe=get_cwe_entry(cwe_str),
                        recommendation=f"Add the {header_name} response header.",
                        confidence="HIGH",
                    )
                )

        # Server header disclosure
        if server_header:
            result.findings.append(
                Finding(
                    scanner=ScannerType.DAST,
                    rule_id="DAST-SERVER-DISCLOSURE",
                    title="Server header discloses technology",
                    description=f"The Server header reveals: {server_header}",
                    severity=Severity.LOW,
                    file_path=url,
                    evidence=f"Server: {server_header}",
                    cwe=get_cwe_entry("CWE-200"),
                    recommendation="Remove or genericise the Server header.",
                    confidence="HIGH",
                )
            )

        # Cookie security
        for cookie in cookies:
            cookie_lower = cookie.lower()
            cookie_name = cookie.split("=")[0].strip()

            if "secure" not in cookie_lower:
                result.findings.append(
                    Finding(
                        scanner=ScannerType.DAST,
                        rule_id="DAST-COOKIE-NO-SECURE",
                        title=f"Cookie '{cookie_name}' missing Secure flag",
                        description="Cookies without the Secure flag can be transmitted over HTTP.",
                        severity=Severity.MEDIUM,
                        file_path=url,
                        evidence=cookie[:200],
                        cwe=get_cwe_entry("CWE-319"),
                        recommendation="Add the Secure flag to cookies.",
                        confidence="HIGH",
                    )
                )

            if "httponly" not in cookie_lower:
                result.findings.append(
                    Finding(
                        scanner=ScannerType.DAST,
                        rule_id="DAST-COOKIE-NO-HTTPONLY",
                        title=f"Cookie '{cookie_name}' missing HttpOnly flag",
                        description="Cookies without HttpOnly can be accessed by JavaScript.",
                        severity=Severity.MEDIUM,
                        file_path=url,
                        evidence=cookie[:200],
                        cwe=get_cwe_entry("CWE-693"),
                        recommendation="Add the HttpOnly flag to cookies.",
                        confidence="HIGH",
                    )
                )

            if "samesite" not in cookie_lower:
                result.findings.append(
                    Finding(
                        scanner=ScannerType.DAST,
                        rule_id="DAST-COOKIE-NO-SAMESITE",
                        title=f"Cookie '{cookie_name}' missing SameSite attribute",
                        description="Cookies without SameSite may be vulnerable to CSRF.",
                        severity=Severity.LOW,
                        file_path=url,
                        evidence=cookie[:200],
                        cwe=get_cwe_entry("CWE-693"),
                        recommendation="Add SameSite=Strict or SameSite=Lax to cookies.",
                        confidence="MEDIUM",
                    )
                )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _map_zap_risk(code: str) -> Severity:
    return {"3": Severity.HIGH, "2": Severity.MEDIUM, "1": Severity.LOW, "0": Severity.INFO}.get(
        str(code), Severity.MEDIUM
    )


def _map_zap_confidence(code: str) -> str:
    return {"3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "LOW"}.get(str(code), "MEDIUM")


def _map_nuclei_severity(sev: str) -> Severity:
    return {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }.get(sev.lower(), Severity.MEDIUM)



