"""Dependency vulnerability scanner — pip-audit → safety → built-in check."""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from pathlib import Path
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

# ---------------------------------------------------------------------------
# Small built-in known-vulnerability database (demo/fallback only)
# ---------------------------------------------------------------------------

_KNOWN_VULNS: Dict[str, List[Dict[str, Any]]] = {
    # Python
    "requests": [
        {
            "cve": "CVE-2023-32681",
            "fixed": "2.31.0",
            "severity": Severity.MEDIUM,
            "title": "Unintended leak of Proxy-Authorization header",
        },
    ],
    "urllib3": [
        {
            "cve": "CVE-2023-45803",
            "fixed": "2.0.7",
            "severity": Severity.MEDIUM,
            "title": "Request body not stripped after redirect",
        },
    ],
    "cryptography": [
        {
            "cve": "CVE-2023-49083",
            "fixed": "41.0.6",
            "severity": Severity.HIGH,
            "title": "NULL pointer dereference when loading PKCS7 certificates",
        },
    ],
    "flask": [
        {
            "cve": "CVE-2023-30861",
            "fixed": "2.3.2",
            "severity": Severity.HIGH,
            "title": "Cookie set on every response when using SecureCookieSessionInterface",
        },
    ],
    "django": [
        {
            "cve": "CVE-2024-24680",
            "fixed": "4.2.10",
            "severity": Severity.HIGH,
            "title": "Potential denial-of-service in intcomma template filter",
        },
    ],
    # npm
    "express": [
        {
            "cve": "CVE-2024-29041",
            "fixed": "4.19.2",
            "severity": Severity.MEDIUM,
            "title": "Open redirect via malicious URL",
        },
    ],
    "lodash": [
        {
            "cve": "CVE-2021-23337",
            "fixed": "4.17.21",
            "severity": Severity.HIGH,
            "title": "Command injection via template function",
        },
    ],
}

# Version comparison regex
_VERSION_RE = re.compile(r"^(\d+(?:\.\d+)*)")


class DependencyScanner(BaseScanner):
    """Scan project dependencies for known vulnerabilities."""

    scanner_type = ScannerType.DEPENDENCY

    async def scan(self, path: str, **kwargs) -> ScanResult:
        result = self._create_result()
        start = time.time()

        root = Path(path)
        try:
            # Python ecosystem
            req_file = root / "requirements.txt"
            if req_file.exists():
                await self._scan_python(root, req_file, result)

            # JavaScript ecosystem
            pkg_json = root / "package.json"
            if pkg_json.exists():
                await self._scan_javascript(root, result)
        except Exception as exc:
            result.errors.append(f"Dependency scan error: {exc}")
            logger.exception("Dependency scan failed")

        result.duration_seconds = round(time.time() - start, 3)
        result.findings = [enrich_finding(f) for f in result.findings]
        return result

    # -- Python ------------------------------------------------------------

    async def _scan_python(
        self, root: Path, req_file: Path, result: ScanResult
    ) -> None:
        if self._check_tool_available("pip-audit"):
            await self._run_pip_audit(req_file, result)
        elif self._check_tool_available("safety"):
            await self._run_safety(req_file, result)
        else:
            result.errors.append("[warning] Neither pip-audit nor safety found; using built-in vulnerability list.")
            self._builtin_python_check(req_file, result)

    async def _run_pip_audit(self, req_file: Path, result: ScanResult) -> None:
        cmd = ["pip-audit", "--format", "json", "-r", str(req_file)]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
        except (FileNotFoundError, OSError) as exc:
            result.errors.append(f"Failed to run pip-audit: {exc}")
            self._builtin_python_check(req_file, result)
            return

        if proc.returncode not in (0, 1):
            result.errors.append(
                f"pip-audit exited {proc.returncode}: "
                f"{stderr.decode(errors='replace')[:500]}"
            )
            self._builtin_python_check(req_file, result)
            return

        try:
            data = json.loads(stdout.decode(errors="replace"))
        except json.JSONDecodeError as exc:
            result.errors.append(f"Failed to parse pip-audit JSON: {exc}")
            return

        deps = data if isinstance(data, list) else data.get("dependencies", [])
        for dep in deps:
            for vuln in dep.get("vulns", []):
                result.findings.append(
                    Finding(
                        scanner=ScannerType.DEPENDENCY,
                        rule_id=vuln.get("id", "pip-audit"),
                        title=f"Vulnerability in {dep.get('name', '?')}",
                        description=vuln.get("description", vuln.get("id", "")),
                        severity=_map_pip_audit_severity(vuln),
                        file_path=str(req_file),
                        cve_id=vuln.get("id"),
                        package_name=dep.get("name"),
                        package_version=dep.get("version"),
                        fixed_version=vuln.get("fix_versions", [None])[0]
                        if vuln.get("fix_versions")
                        else None,
                        cwe=get_cwe_entry("CWE-1035"),
                        confidence="HIGH",
                    )
                )

    async def _run_safety(self, req_file: Path, result: ScanResult) -> None:
        cmd = ["safety", "check", "--file", str(req_file), "--json"]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
        except (FileNotFoundError, OSError) as exc:
            result.errors.append(f"Failed to run safety: {exc}")
            self._builtin_python_check(req_file, result)
            return

        try:
            data = json.loads(stdout.decode(errors="replace"))
        except json.JSONDecodeError as exc:
            result.errors.append(f"Failed to parse safety JSON: {exc}")
            return

        vulns = data if isinstance(data, list) else data.get("vulnerabilities", [])
        for vuln in vulns:
            if isinstance(vuln, list) and len(vuln) >= 5:
                pkg, affected, installed, desc, vuln_id = (
                    vuln[0], vuln[1], vuln[2], vuln[3], vuln[4],
                )
            elif isinstance(vuln, dict):
                pkg = vuln.get("package_name", "?")
                installed = vuln.get("analyzed_version", "")
                desc = vuln.get("advisory", "")
                vuln_id = vuln.get("vulnerability_id", "")
                affected = vuln.get("vulnerable_spec", "")
            else:
                continue

            result.findings.append(
                Finding(
                    scanner=ScannerType.DEPENDENCY,
                    rule_id=str(vuln_id),
                    title=f"Vulnerability in {pkg}",
                    description=str(desc)[:500],
                    severity=Severity.HIGH,
                    file_path=str(req_file),
                    cve_id=str(vuln_id) if str(vuln_id).startswith("CVE") else None,
                    package_name=str(pkg),
                    package_version=str(installed),
                    cwe=get_cwe_entry("CWE-1035"),
                    confidence="HIGH",
                    metadata={"affected_spec": str(affected)},
                )
            )

    def _builtin_python_check(self, req_file: Path, result: ScanResult) -> None:
        deps = _parse_requirements(req_file)
        result.scanned_files += 1
        for pkg_name, installed_version in deps:
            vulns = _KNOWN_VULNS.get(pkg_name.lower(), [])
            for vuln in vulns:
                if installed_version and _version_lt(
                    installed_version, vuln["fixed"]
                ):
                    result.findings.append(
                        Finding(
                            scanner=ScannerType.DEPENDENCY,
                            rule_id=vuln["cve"],
                            title=vuln["title"],
                            description=f"{pkg_name}=={installed_version} is affected by {vuln['cve']}. "
                            f"Fixed in {vuln['fixed']}.",
                            severity=vuln["severity"],
                            file_path=str(req_file),
                            cve_id=vuln["cve"],
                            package_name=pkg_name,
                            package_version=installed_version,
                            fixed_version=vuln["fixed"],
                            cwe=get_cwe_entry("CWE-1035"),
                            confidence="MEDIUM",
                        )
                    )

    # -- JavaScript --------------------------------------------------------

    async def _scan_javascript(self, root: Path, result: ScanResult) -> None:
        if self._check_tool_available("npm"):
            await self._run_npm_audit(root, result)
        else:
            result.errors.append("[warning] npm not found; using built-in vulnerability list for JS deps.")
            pkg_json = root / "package.json"
            self._builtin_js_check(pkg_json, result)

    async def _run_npm_audit(self, root: Path, result: ScanResult) -> None:
        cmd = ["npm", "audit", "--json"]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(root),
            )
            stdout, stderr = await proc.communicate()
        except (FileNotFoundError, OSError) as exc:
            result.errors.append(f"Failed to run npm audit: {exc}")
            return

        try:
            data = json.loads(stdout.decode(errors="replace"))
        except json.JSONDecodeError as exc:
            result.errors.append(f"Failed to parse npm audit JSON: {exc}")
            return

        advisories = data.get("vulnerabilities", data.get("advisories", {}))
        if isinstance(advisories, dict):
            for name, info in advisories.items():
                via = info.get("via", [])
                title = ""
                cve_id = None
                if via and isinstance(via[0], dict):
                    title = via[0].get("title", "")
                    cve_id = via[0].get("cve")
                elif via and isinstance(via[0], str):
                    title = via[0]
                sev = _map_npm_severity(info.get("severity", "moderate"))
                result.findings.append(
                    Finding(
                        scanner=ScannerType.DEPENDENCY,
                        rule_id=cve_id or f"npm-{name}",
                        title=title or f"Vulnerability in {name}",
                        description=title,
                        severity=sev,
                        file_path=str(root / "package.json"),
                        cve_id=cve_id,
                        package_name=name,
                        package_version=info.get("range", ""),
                        fixed_version=info.get("fixAvailable", {}).get("version")
                        if isinstance(info.get("fixAvailable"), dict)
                        else None,
                        cwe=get_cwe_entry("CWE-1035"),
                        confidence="HIGH",
                    )
                )

    def _builtin_js_check(self, pkg_json: Path, result: ScanResult) -> None:
        try:
            data = json.loads(pkg_json.read_text(encoding="utf-8"))
        except Exception:
            return
        result.scanned_files += 1
        all_deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
        for pkg_name, ver_spec in all_deps.items():
            version = ver_spec.lstrip("^~>=<")
            vulns = _KNOWN_VULNS.get(pkg_name.lower(), [])
            for vuln in vulns:
                if _version_lt(version, vuln["fixed"]):
                    result.findings.append(
                        Finding(
                            scanner=ScannerType.DEPENDENCY,
                            rule_id=vuln["cve"],
                            title=vuln["title"],
                            description=f"{pkg_name}@{version} is affected by {vuln['cve']}. "
                            f"Fixed in {vuln['fixed']}.",
                            severity=vuln["severity"],
                            file_path=str(pkg_json),
                            cve_id=vuln["cve"],
                            package_name=pkg_name,
                            package_version=version,
                            fixed_version=vuln["fixed"],
                            cwe=get_cwe_entry("CWE-1035"),
                            confidence="MEDIUM",
                        )
                    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_requirements(req_file: Path) -> List[Tuple[str, Optional[str]]]:
    """Parse requirements.txt into (package, version) tuples."""
    results: List[Tuple[str, Optional[str]]] = []
    try:
        for line in req_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            m = re.match(r"^([A-Za-z0-9_.-]+)\s*(?:[=<>!~]+\s*(.+))?", line)
            if m:
                name = m.group(1)
                ver = m.group(2).split(",")[0].strip() if m.group(2) else None
                results.append((name, ver))
    except Exception:
        pass
    return results


def _version_lt(installed: str, fixed: str) -> bool:
    """Simple version less-than comparison by numeric segments."""
    try:
        inst_parts = [int(x) for x in _VERSION_RE.findall(installed)[0].split(".")]
        fix_parts = [int(x) for x in _VERSION_RE.findall(fixed)[0].split(".")]
        return inst_parts < fix_parts
    except (IndexError, ValueError):
        return False


def _map_pip_audit_severity(vuln: Dict[str, Any]) -> Severity:
    aliases = vuln.get("aliases", [])
    for alias in aliases:
        if "CRITICAL" in alias.upper():
            return Severity.CRITICAL
    return Severity.HIGH


def _map_npm_severity(sev: str) -> Severity:
    return {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "moderate": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }.get(sev.lower(), Severity.MEDIUM)



