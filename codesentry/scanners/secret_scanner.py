"""Secret detection scanner — built-in regex + optional detect-secrets."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Pattern, Tuple

from codesentry.cwe_mapping import enrich_finding, get_cwe_entry
from codesentry.models import (
    Finding,
    ScannerType,
    ScanResult,
    Severity,
)
from codesentry.scanners.base_scanner import BaseScanner

logger = logging.getLogger(__name__)

# Maximum file size to scan (1 MB)
_MAX_FILE_BYTES = 1_048_576

# ---------------------------------------------------------------------------
# Regex patterns — each tuple is (rule_id, title, compiled regex, severity, cwe)
# ---------------------------------------------------------------------------

_SECRET_PATTERNS: List[Tuple[str, str, Pattern[str], Severity, str]] = [
    (
        "SECRET-AWS-KEY",
        "AWS Access Key ID",
        re.compile(r"AKIA[0-9A-Z]{16}"),
        Severity.CRITICAL,
        "CWE-798",
    ),
    (
        "SECRET-AWS-SECRET",
        "AWS Secret Access Key",
        re.compile(
            r"""(?i)aws_secret_access_key\s*=\s*['"][A-Za-z0-9/+=]{40}['"]"""
        ),
        Severity.CRITICAL,
        "CWE-798",
    ),
    (
        "SECRET-AZURE-STORAGE",
        "Azure Storage Account Key",
        re.compile(
            r"""(?i)AccountKey\s*=\s*[A-Za-z0-9+/=]{44,}"""
        ),
        Severity.CRITICAL,
        "CWE-798",
    ),
    (
        "SECRET-GITHUB-TOKEN",
        "GitHub Personal Access Token",
        re.compile(r"ghp_[A-Za-z0-9]{36}"),
        Severity.CRITICAL,
        "CWE-798",
    ),
    (
        "SECRET-GITHUB-OAUTH",
        "GitHub OAuth Token",
        re.compile(r"gho_[A-Za-z0-9]{36}"),
        Severity.CRITICAL,
        "CWE-798",
    ),
    (
        "SECRET-GITHUB-APP",
        "GitHub App Token",
        re.compile(r"ghs_[A-Za-z0-9]{36}"),
        Severity.HIGH,
        "CWE-798",
    ),
    (
        "SECRET-GITHUB-REFRESH",
        "GitHub Refresh Token",
        re.compile(r"ghr_[A-Za-z0-9]{36}"),
        Severity.HIGH,
        "CWE-798",
    ),
    (
        "SECRET-GITHUB-PAT",
        "GitHub Fine-grained PAT",
        re.compile(r"github_pat_[A-Za-z0-9_]{22,}"),
        Severity.CRITICAL,
        "CWE-798",
    ),
    (
        "SECRET-GITLAB-TOKEN",
        "GitLab Personal Access Token",
        re.compile(r"glpat-[A-Za-z0-9\-]{20,}"),
        Severity.CRITICAL,
        "CWE-798",
    ),
    (
        "SECRET-SLACK-TOKEN",
        "Slack Token",
        re.compile(r"xox[bpsa]-[A-Za-z0-9\-]{10,}"),
        Severity.CRITICAL,
        "CWE-798",
    ),
    (
        "SECRET-GENERIC-API-KEY",
        "Generic API Key",
        re.compile(
            r"""(?i)(api[_\-]?key|apikey)\s*[=:]\s*['"][A-Za-z0-9]{20,}['"]"""
        ),
        Severity.HIGH,
        "CWE-798",
    ),
    (
        "SECRET-PRIVATE-KEY",
        "Private Key",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        Severity.CRITICAL,
        "CWE-321",
    ),
    (
        "SECRET-JWT",
        "JSON Web Token",
        re.compile(
            r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
        ),
        Severity.HIGH,
        "CWE-798",
    ),
    (
        "SECRET-CONN-STRING-PWD",
        "Connection string with password",
        re.compile(r"(?i)(password|pwd)\s*=\s*[^\s;]{8,}"),
        Severity.HIGH,
        "CWE-798",
    ),
]

# File extensions to always skip (binary / non-text)
_BINARY_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
    ".woff", ".woff2", ".ttf", ".eot",
    ".zip", ".gz", ".tar", ".bz2", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".o", ".a",
    ".pyc", ".pyo", ".class", ".jar",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".mp3", ".mp4", ".avi", ".mov", ".wav",
    ".sqlite", ".db", ".lock",
})


class SecretScanner(BaseScanner):
    """Detect hard-coded secrets and credentials in source files."""

    scanner_type = ScannerType.SECRET

    async def scan(self, path: str, **kwargs) -> ScanResult:
        result = self._create_result()
        start = time.time()

        try:
            # Always run the built-in regex scanner
            self._run_builtin(path, result)

            # Optionally augment with detect-secrets
            if self._check_tool_available("detect-secrets"):
                await self._run_detect_secrets(path, result)
        except Exception as exc:
            result.errors.append(f"Secret scan error: {exc}")
            logger.exception("Secret scan failed")

        result.duration_seconds = round(time.time() - start, 3)
        result.findings = [enrich_finding(f) for f in result.findings]
        return result

    # -- Built-in regex scanner --------------------------------------------

    def _run_builtin(self, path: str, result: ScanResult) -> None:
        root = Path(path)
        files = root.rglob("*") if root.is_dir() else [root]

        for file_path in files:
            if not file_path.is_file():
                continue
            rel = str(file_path)
            if self._is_excluded(rel):
                result.skipped_files += 1
                continue
            if file_path.suffix.lower() in _BINARY_EXTENSIONS:
                result.skipped_files += 1
                continue
            try:
                size = file_path.stat().st_size
            except OSError:
                result.skipped_files += 1
                continue
            if size > _MAX_FILE_BYTES or size == 0:
                result.skipped_files += 1
                continue
            if _is_binary(file_path):
                result.skipped_files += 1
                continue

            result.scanned_files += 1
            self._scan_file(file_path, rel, result)

    def _scan_file(self, file_path: Path, rel: str, result: ScanResult) -> None:
        try:
            lines = file_path.read_text(
                encoding="utf-8", errors="replace"
            ).splitlines()
        except (OSError, PermissionError):
            return

        for lineno, line in enumerate(lines, start=1):
            for rule_id, title, pattern, severity, cwe_str in _SECRET_PATTERNS:
                if pattern.search(line):
                    result.findings.append(
                        Finding(
                            scanner=ScannerType.SECRET,
                            rule_id=rule_id,
                            title=title,
                            description=f"Detected {title} in {rel} at line {lineno}.",
                            severity=severity,
                            file_path=rel,
                            line_start=lineno,
                            evidence=_redact_line(line.strip()[:200]),
                            cwe=get_cwe_entry(cwe_str),
                            recommendation="Remove the secret and use environment variables or a secrets manager.",
                            confidence="HIGH",
                        )
                    )

    # -- detect-secrets integration ----------------------------------------

    async def _run_detect_secrets(self, path: str, result: ScanResult) -> None:
        cmd = ["detect-secrets", "scan", path]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
        except (FileNotFoundError, OSError) as exc:
            result.errors.append(f"Failed to run detect-secrets: {exc}")
            return

        if proc.returncode != 0:
            result.errors.append(
                f"detect-secrets exited {proc.returncode}: "
                f"{stderr.decode(errors='replace')[:500]}"
            )
            return

        try:
            data = json.loads(stdout.decode(errors="replace"))
        except json.JSONDecodeError as exc:
            result.errors.append(f"Failed to parse detect-secrets JSON: {exc}")
            return

        seen = {(f.file_path, f.line_start, f.rule_id) for f in result.findings}
        for file_rel, secrets in data.get("results", {}).items():
            for secret in secrets:
                lineno = secret.get("line_number", 0)
                stype = secret.get("type", "unknown")
                key = (file_rel, lineno, f"detect-secrets-{stype}")
                if key in seen:
                    continue
                seen.add(key)
                result.findings.append(
                    Finding(
                        scanner=ScannerType.SECRET,
                        rule_id=f"detect-secrets-{stype}",
                        title=f"Secret detected: {stype}",
                        description=f"detect-secrets found a {stype} in {file_rel} at line {lineno}.",
                        severity=Severity.HIGH,
                        file_path=file_rel,
                        line_start=lineno,
                        cwe=get_cwe_entry("CWE-798"),
                        recommendation="Remove the secret and rotate the credential.",
                        confidence="HIGH",
                    )
                )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_binary(file_path: Path) -> bool:
    """Return *True* if the file looks like a binary (contains null bytes)."""
    try:
        chunk = file_path.read_bytes()[:8192]
        return b"\x00" in chunk
    except OSError:
        return True


def _redact_line(line: str) -> str:
    """Mask the secret portion of a line for safe display in reports."""
    return re.sub(
        r"""(['"])[A-Za-z0-9+/=_\-]{8,}(['"])""",
        r"\1****\2",
        line,
    )
