"""Infrastructure-as-Code scanner — Checkov → built-in Dockerfile/Compose checks."""

from __future__ import annotations

import asyncio
import json
import logging
import re
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


class IaCScanner(BaseScanner):
    """Scan Dockerfiles, docker-compose files, and IaC templates for misconfigurations."""

    scanner_type = ScannerType.IAC

    async def scan(self, path: str, **kwargs) -> ScanResult:
        result = self._create_result()
        start = time.time()

        try:
            if self._check_tool_available("checkov"):
                await self._run_checkov(path, result)
            else:
                result.errors.append("[warning] checkov not found; using built-in Dockerfile/Compose checks.")
                root = Path(path)
                self._scan_dockerfiles(root, result)
                self._scan_compose_files(root, result)
        except Exception as exc:
            result.errors.append(f"IaC scan error: {exc}")
            logger.exception("IaC scan failed")

        result.duration_seconds = round(time.time() - start, 3)
        result.findings = [enrich_finding(f) for f in result.findings]
        return result

    # -- Checkov -----------------------------------------------------------

    async def _run_checkov(self, path: str, result: ScanResult) -> None:
        cmd = ["checkov", "-d", path, "--output", "json", "--quiet"]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
        except (FileNotFoundError, OSError) as exc:
            result.errors.append(f"Failed to run checkov: {exc}")
            root = Path(path)
            self._scan_dockerfiles(root, result)
            self._scan_compose_files(root, result)
            return

        if proc.returncode not in (0, 1):
            result.errors.append(
                f"checkov exited {proc.returncode}: "
                f"{stderr.decode(errors='replace')[:500]}"
            )
            root = Path(path)
            self._scan_dockerfiles(root, result)
            self._scan_compose_files(root, result)
            return

        try:
            data = json.loads(stdout.decode(errors="replace"))
        except json.JSONDecodeError as exc:
            result.errors.append(f"Failed to parse checkov JSON: {exc}")
            return

        checks = data if isinstance(data, list) else [data]
        for check_block in checks:
            for failed in check_block.get("results", {}).get("failed_checks", []):
                sev = _map_checkov_severity(
                    failed.get("severity", "MEDIUM")
                )
                result.findings.append(
                    Finding(
                        scanner=ScannerType.IAC,
                        rule_id=failed.get("check_id", "checkov"),
                        title=failed.get("check_result", {}).get(
                            "name", failed.get("check_id", "IaC finding")
                        ),
                        description=failed.get("guideline", ""),
                        severity=sev,
                        file_path=failed.get("file_path", ""),
                        line_start=failed.get("file_line_range", [None])[0],
                        line_end=failed.get("file_line_range", [None, None])[1],
                        evidence="\n".join(
                            failed.get("code_block", [])
                            if isinstance(failed.get("code_block"), list)
                            else []
                        ),
                        confidence="HIGH",
                    )
                )

    # -- Built-in Dockerfile scanner ---------------------------------------

    def _scan_dockerfiles(self, root: Path, result: ScanResult) -> None:
        dockerfiles = list(root.rglob("Dockerfile*"))
        for df in dockerfiles:
            if self._is_excluded(str(df)):
                result.skipped_files += 1
                continue
            try:
                content = df.read_text(encoding="utf-8", errors="replace")
            except OSError:
                result.skipped_files += 1
                continue
            result.scanned_files += 1
            rel = str(df)
            self._check_dockerfile(content, rel, result)

    def _check_dockerfile(
        self, content: str, file_path: str, result: ScanResult
    ) -> None:
        lines = content.splitlines()
        has_user = False

        for lineno, line in enumerate(lines, start=1):
            stripped = line.strip()
            upper = stripped.upper()

            # USER instruction?
            if upper.startswith("USER "):
                has_user = True

            # Latest tag
            if upper.startswith("FROM ") and ":latest" in stripped:
                result.findings.append(
                    Finding(
                        scanner=ScannerType.IAC,
                        rule_id="IAC-DOCKER-LATEST",
                        title="Docker image uses :latest tag",
                        description="Using the :latest tag makes builds non-reproducible.",
                        severity=Severity.MEDIUM,
                        file_path=file_path,
                        line_start=lineno,
                        evidence=stripped[:200],
                        cwe=get_cwe_entry("CWE-829"),
                        recommendation="Pin image to a specific version or digest.",
                        confidence="HIGH",
                    )
                )

            # FROM without tag at all (implies latest)
            if upper.startswith("FROM "):
                img = stripped.split()[1] if len(stripped.split()) > 1 else ""
                if img and ":" not in img and "@" not in img and img.lower() != "scratch":
                    result.findings.append(
                        Finding(
                            scanner=ScannerType.IAC,
                            rule_id="IAC-DOCKER-NO-TAG",
                            title="Docker image has no version tag",
                            description="Images without an explicit tag default to :latest.",
                            severity=Severity.MEDIUM,
                            file_path=file_path,
                            line_start=lineno,
                            evidence=stripped[:200],
                            cwe=get_cwe_entry("CWE-829"),
                            recommendation="Pin image to a specific version tag.",
                            confidence="HIGH",
                        )
                    )

            # COPY with secrets patterns
            if upper.startswith("COPY ") or upper.startswith("ADD "):
                secret_patterns = [
                    ".env", "id_rsa", "id_dsa", "id_ed25519",
                    ".pem", ".key", "credentials", ".npmrc",
                    ".pypirc", ".netrc",
                ]
                for pat in secret_patterns:
                    if pat in stripped.lower():
                        result.findings.append(
                            Finding(
                                scanner=ScannerType.IAC,
                                rule_id="IAC-DOCKER-COPY-SECRET",
                                title="Potential secret copied into Docker image",
                                description=f"COPY/ADD may include sensitive file matching '{pat}'.",
                                severity=Severity.HIGH,
                                file_path=file_path,
                                line_start=lineno,
                                evidence=stripped[:200],
                                cwe=get_cwe_entry("CWE-798"),
                                recommendation="Use Docker secrets or multi-stage builds to avoid copying secrets.",
                                confidence="MEDIUM",
                            )
                        )
                        break

            # ADD used instead of COPY
            if upper.startswith("ADD ") and not stripped.split()[1].startswith("http"):
                result.findings.append(
                    Finding(
                        scanner=ScannerType.IAC,
                        rule_id="IAC-DOCKER-ADD",
                        title="Use of ADD instead of COPY",
                        description="ADD has implicit tar extraction and URL fetch behaviour which is risky.",
                        severity=Severity.LOW,
                        file_path=file_path,
                        line_start=lineno,
                        evidence=stripped[:200],
                        cwe=get_cwe_entry("CWE-829"),
                        recommendation="Use COPY unless you specifically need ADD functionality.",
                        confidence="HIGH",
                    )
                )

            # Exposed ports check (broad ports)
            if upper.startswith("EXPOSE "):
                ports_str = stripped[len("EXPOSE "):].strip()
                for port_tok in ports_str.split():
                    try:
                        port_num = int(port_tok.split("/")[0])
                        if port_num in (22, 23, 3389, 5900):
                            result.findings.append(
                                Finding(
                                    scanner=ScannerType.IAC,
                                    rule_id="IAC-DOCKER-EXPOSED-PORT",
                                    title=f"Unnecessary port exposed: {port_num}",
                                    description=f"Port {port_num} is commonly associated with management protocols.",
                                    severity=Severity.MEDIUM,
                                    file_path=file_path,
                                    line_start=lineno,
                                    evidence=stripped[:200],
                                    cwe=get_cwe_entry("CWE-284"),
                                    recommendation="Remove unnecessary EXPOSE directives.",
                                    confidence="MEDIUM",
                                )
                            )
                    except ValueError:
                        pass

        # Running as root (no USER instruction)
        if not has_user and lines:
            result.findings.append(
                Finding(
                    scanner=ScannerType.IAC,
                    rule_id="IAC-DOCKER-ROOT",
                    title="Container runs as root (no USER instruction)",
                    description="Running containers as root increases the blast radius of a compromise.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_start=1,
                    cwe=get_cwe_entry("CWE-250"),
                    recommendation="Add a USER instruction to run as a non-root user.",
                    confidence="HIGH",
                )
            )

    # -- Built-in docker-compose scanner -----------------------------------

    def _scan_compose_files(self, root: Path, result: ScanResult) -> None:
        compose_names = [
            "docker-compose.yml",
            "docker-compose.yaml",
            "compose.yml",
            "compose.yaml",
        ]
        for name in compose_names:
            cf = root / name
            if cf.exists():
                try:
                    content = cf.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                result.scanned_files += 1
                self._check_compose(content, str(cf), result)

        # Also scan nested compose files
        for cf in root.rglob("docker-compose*.y*ml"):
            if self._is_excluded(str(cf)):
                continue
            try:
                content = cf.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            result.scanned_files += 1
            self._check_compose(content, str(cf), result)

    def _check_compose(
        self, content: str, file_path: str, result: ScanResult
    ) -> None:
        lines = content.splitlines()
        for lineno, line in enumerate(lines, start=1):
            stripped = line.strip()

            # privileged: true
            if re.match(r"^\s*privileged\s*:\s*true\s*$", line, re.IGNORECASE):
                result.findings.append(
                    Finding(
                        scanner=ScannerType.IAC,
                        rule_id="IAC-COMPOSE-PRIVILEGED",
                        title="Container runs in privileged mode",
                        description="Privileged containers have full access to the host.",
                        severity=Severity.CRITICAL,
                        file_path=file_path,
                        line_start=lineno,
                        evidence=stripped[:200],
                        cwe=get_cwe_entry("CWE-250"),
                        recommendation="Remove 'privileged: true' unless absolutely necessary.",
                        confidence="HIGH",
                    )
                )

            # Ports bound to 0.0.0.0
            if re.match(r"""^\s*-\s*['"]?0\.0\.0\.0:""", line):
                result.findings.append(
                    Finding(
                        scanner=ScannerType.IAC,
                        rule_id="IAC-COMPOSE-BIND-ALL",
                        title="Port bound to all interfaces (0.0.0.0)",
                        description="Binding to 0.0.0.0 exposes the port to all network interfaces.",
                        severity=Severity.MEDIUM,
                        file_path=file_path,
                        line_start=lineno,
                        evidence=stripped[:200],
                        cwe=get_cwe_entry("CWE-284"),
                        recommendation="Bind to 127.0.0.1 or a specific interface.",
                        confidence="HIGH",
                    )
                )

            # Hardcoded credentials in environment
            env_secret_re = re.compile(
                r"""(?i)(password|secret|api_key|token)\s*[=:]\s*\S{4,}"""
            )
            if env_secret_re.search(stripped):
                # Only flag inside environment sections
                if _in_environment_context(lines, lineno):
                    result.findings.append(
                        Finding(
                            scanner=ScannerType.IAC,
                            rule_id="IAC-COMPOSE-HARDCODED-SECRET",
                            title="Hardcoded credential in docker-compose environment",
                            description="Secrets should not be hardcoded in compose files.",
                            severity=Severity.HIGH,
                            file_path=file_path,
                            line_start=lineno,
                            evidence=_redact(stripped[:200]),
                            cwe=get_cwe_entry("CWE-798"),
                            recommendation="Use Docker secrets, .env files (excluded from VCS), or a vault.",
                            confidence="MEDIUM",
                        )
                    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _in_environment_context(lines: List[str], target_lineno: int) -> bool:
    """Heuristic: check if target line is under an 'environment:' key."""
    for i in range(target_lineno - 2, -1, -1):
        stripped = lines[i].strip()
        if stripped.startswith("environment"):
            return True
        if stripped and not stripped.startswith("-") and not stripped.startswith("#"):
            if ":" in stripped and not stripped.startswith(" "):
                return False
    return False


def _map_checkov_severity(sev: str) -> Severity:
    return {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
        "INFO": Severity.INFO,
    }.get(sev.upper(), Severity.MEDIUM)


def _redact(text: str) -> str:
    return re.sub(
        r"""([=:]\s*)(\S{4,})""",
        r"\1****",
        text,
    )



