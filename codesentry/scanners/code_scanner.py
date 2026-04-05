"""SAST scanner — Semgrep → Bandit → built-in AST fallback."""

from __future__ import annotations

import ast
import asyncio
import json
import logging
import os
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from codesentry.cwe_mapping import enrich_finding, get_cwe_entry
from codesentry.models import (
    CWEEntry,
    Finding,
    ScannerType,
    ScanResult,
    Severity,
)
from codesentry.scanners.base_scanner import BaseScanner

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Built-in AST patterns
# ---------------------------------------------------------------------------

_AST_RULES: List[Dict[str, Any]] = [
    {
        "id": "SAST-EVAL",
        "title": "Use of eval()",
        "cwe": "CWE-94",
        "severity": Severity.HIGH,
        "description": "eval() can execute arbitrary code and should be avoided.",
        "recommendation": "Replace eval() with ast.literal_eval() or a safe parser.",
        "match": lambda node: (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "eval"
        ),
    },
    {
        "id": "SAST-EXEC",
        "title": "Use of exec()",
        "cwe": "CWE-94",
        "severity": Severity.HIGH,
        "description": "exec() can execute arbitrary code and should be avoided.",
        "recommendation": "Remove exec() and use safer alternatives.",
        "match": lambda node: (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "exec"
        ),
    },
    {
        "id": "SAST-SHELL-TRUE",
        "title": "subprocess call with shell=True",
        "cwe": "CWE-78",
        "severity": Severity.HIGH,
        "description": "Using shell=True with subprocess can lead to OS command injection.",
        "recommendation": "Use shell=False and pass arguments as a list.",
        "match": lambda node: (
            isinstance(node, ast.Call)
            and _is_subprocess_call(node)
            and _has_shell_true(node)
        ),
    },
    {
        "id": "SAST-OS-SYSTEM",
        "title": "Use of os.system()",
        "cwe": "CWE-78",
        "severity": Severity.HIGH,
        "description": "os.system() is vulnerable to OS command injection.",
        "recommendation": "Use subprocess.run() with shell=False instead.",
        "match": lambda node: (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "system"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "os"
        ),
    },
    {
        "id": "SAST-PICKLE-LOADS",
        "title": "Use of pickle.loads()",
        "cwe": "CWE-502",
        "severity": Severity.HIGH,
        "description": "Deserialization of untrusted data via pickle can lead to arbitrary code execution.",
        "recommendation": "Use a safe serialization format like JSON.",
        "match": lambda node: (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in ("loads", "load")
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "pickle"
        ),
    },
    {
        "id": "SAST-YAML-UNSAFE",
        "title": "yaml.load() without SafeLoader",
        "cwe": "CWE-502",
        "severity": Severity.HIGH,
        "description": "yaml.load() without Loader=SafeLoader can execute arbitrary Python objects.",
        "recommendation": "Use yaml.safe_load() or pass Loader=yaml.SafeLoader.",
        "match": lambda node: (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "load"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "yaml"
            and not _has_safe_loader(node)
        ),
    },
    {
        "id": "SAST-SQL-FORMAT",
        "title": "Potential SQL injection via string formatting",
        "cwe": "CWE-89",
        "severity": Severity.HIGH,
        "description": "SQL queries built with string formatting are vulnerable to injection.",
        "recommendation": "Use parameterised queries or an ORM.",
    },
    {
        "id": "SAST-WEAK-HASH",
        "title": "Use of weak hash algorithm (MD5/SHA1)",
        "cwe": "CWE-327",
        "severity": Severity.MEDIUM,
        "description": "MD5 and SHA1 are cryptographically broken and should not be used for security.",
        "recommendation": "Use SHA-256 or stronger via hashlib.sha256().",
        "match": lambda node: (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in ("md5", "sha1")
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "hashlib"
        ),
    },
    {
        "id": "SAST-PATH-TRAVERSAL",
        "title": "Potential path traversal via open()",
        "cwe": "CWE-22",
        "severity": Severity.MEDIUM,
        "description": "open() with a variable path may allow path traversal attacks.",
        "recommendation": "Validate and sanitise file paths before opening.",
        "match": lambda node: (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "open"
            and len(node.args) >= 1
            and isinstance(node.args[0], (ast.Name, ast.BinOp, ast.JoinedStr))
        ),
    },
    {
        "id": "SAST-VERIFY-FALSE",
        "title": "SSL verification disabled (verify=False)",
        "cwe": "CWE-295",
        "severity": Severity.HIGH,
        "description": "Disabling SSL certificate verification exposes the connection to MITM attacks.",
        "recommendation": "Remove verify=False or use a trusted CA bundle.",
        "match": lambda node: (
            isinstance(node, ast.Call)
            and _has_verify_false(node)
        ),
    },
    {
        "id": "SAST-DEBUG-TRUE",
        "title": "Debug mode enabled (debug=True)",
        "cwe": "CWE-489",
        "severity": Severity.MEDIUM,
        "description": "Running with debug=True in production exposes sensitive information.",
        "recommendation": "Disable debug mode in production deployments.",
        "match": lambda node: (
            isinstance(node, ast.Call)
            and _has_debug_true(node)
        ),
    },
    {
        "id": "SAST-HARDCODED-PASSWORD",
        "title": "Potential hard-coded password",
        "cwe": "CWE-798",
        "severity": Severity.HIGH,
        "description": "Hard-coded passwords or secrets should be stored in environment variables or a vault.",
        "recommendation": "Move secrets to environment variables or a secrets manager.",
    },
]


# ---------------------------------------------------------------------------
# AST helper predicates
# ---------------------------------------------------------------------------

def _is_subprocess_call(node: ast.Call) -> bool:
    if isinstance(node.func, ast.Attribute):
        if node.func.attr in ("call", "Popen", "run", "check_output", "check_call"):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess":
                return True
    return False


def _has_shell_true(node: ast.Call) -> bool:
    for kw in node.keywords:
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


def _has_safe_loader(node: ast.Call) -> bool:
    for kw in node.keywords:
        if kw.arg == "Loader":
            return True
    if len(node.args) >= 2:
        return True
    return False


def _has_verify_false(node: ast.Call) -> bool:
    for kw in node.keywords:
        if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
            return True
    return False


def _has_debug_true(node: ast.Call) -> bool:
    for kw in node.keywords:
        if kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


# Regex for SQL-in-format-string heuristic
_SQL_FORMAT_RE = re.compile(
    r"""(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\s+.{0,40}(%s|%d|\{|\+\s*['"])""",
)

# Regex for hardcoded password assignments
_PASSWORD_RE = re.compile(
    r"""(?i)(password|passwd|pwd|secret|token|api_key|apikey)\s*=\s*['"][^'"]{4,}['"]""",
)


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class CodeScanner(BaseScanner):
    """Static Application Security Testing (SAST) scanner.

    Resolution order:
    1. Semgrep (if installed)
    2. Bandit (if installed, Python only)
    3. Built-in AST scanner (Python only)
    """

    scanner_type = ScannerType.CODE

    async def scan(self, path: str, **kwargs) -> ScanResult:
        result = self._create_result()
        start = time.time()

        try:
            if self._check_tool_available("semgrep"):
                await self._run_semgrep(path, result)
            elif self._check_tool_available("bandit"):
                await self._run_bandit(path, result)
            else:
                result.errors.append("[warning] Neither semgrep nor bandit found; using built-in AST scanner (Python only).")
                await self._run_builtin(path, result)
        except Exception as exc:
            result.errors.append(f"Code scan error: {exc}")
            logger.exception("Code scan failed")

        result.duration_seconds = round(time.time() - start, 3)
        result.findings = [enrich_finding(f) for f in result.findings]
        return result

    # -- Semgrep -----------------------------------------------------------

    async def _run_semgrep(self, path: str, result: ScanResult) -> None:
        cmd = ["semgrep", "scan", "--config", "auto", "--json", path]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
        except (FileNotFoundError, OSError) as exc:
            result.errors.append(f"Failed to run semgrep: {exc}")
            await self._run_builtin(path, result)
            return

        if proc.returncode not in (0, 1):
            result.errors.append(
                f"semgrep exited with code {proc.returncode}: {stderr.decode(errors='replace')[:500]}"
            )
            await self._run_builtin(path, result)
            return

        try:
            data = json.loads(stdout.decode(errors="replace"))
        except json.JSONDecodeError as exc:
            result.errors.append(f"Failed to parse semgrep JSON: {exc}")
            return

        for item in data.get("results", []):
            sev = _map_semgrep_severity(item.get("extra", {}).get("severity", "WARNING"))
            cwe_ids = item.get("extra", {}).get("metadata", {}).get("cwe", [])
            cwe_str = cwe_ids[0] if cwe_ids else None
            cwe_entry = get_cwe_entry(cwe_str) if cwe_str else None

            result.findings.append(
                Finding(
                    scanner=ScannerType.CODE,
                    rule_id=item.get("check_id", "semgrep-rule"),
                    title=item.get("extra", {}).get("message", "Semgrep finding")[:120],
                    description=item.get("extra", {}).get("message", ""),
                    severity=sev,
                    file_path=item.get("path", ""),
                    line_start=item.get("start", {}).get("line"),
                    line_end=item.get("end", {}).get("line"),
                    evidence=item.get("extra", {}).get("lines", ""),
                    cwe=cwe_entry,
                    confidence=item.get("extra", {}).get("metadata", {}).get("confidence", "HIGH"),
                )
            )

    # -- Bandit ------------------------------------------------------------

    async def _run_bandit(self, path: str, result: ScanResult) -> None:
        cmd = ["bandit", "-r", path, "-f", "json"]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
        except (FileNotFoundError, OSError) as exc:
            result.errors.append(f"Failed to run bandit: {exc}")
            await self._run_builtin(path, result)
            return

        if proc.returncode not in (0, 1):
            result.errors.append(
                f"bandit exited with code {proc.returncode}: {stderr.decode(errors='replace')[:500]}"
            )
            await self._run_builtin(path, result)
            return

        try:
            data = json.loads(stdout.decode(errors="replace"))
        except json.JSONDecodeError as exc:
            result.errors.append(f"Failed to parse bandit JSON: {exc}")
            return

        for item in data.get("results", []):
            sev = _map_bandit_severity(item.get("issue_severity", "MEDIUM"))
            cwe_raw = item.get("issue_cwe", {})
            cwe_str = f"CWE-{cwe_raw.get('id', '')}" if cwe_raw.get("id") else None
            cwe_entry = get_cwe_entry(cwe_str) if cwe_str else None

            result.findings.append(
                Finding(
                    scanner=ScannerType.CODE,
                    rule_id=item.get("test_id", "bandit-rule"),
                    title=item.get("issue_text", "Bandit finding")[:120],
                    description=item.get("issue_text", ""),
                    severity=sev,
                    file_path=item.get("filename", ""),
                    line_start=item.get("line_number"),
                    evidence=item.get("code", ""),
                    cwe=cwe_entry,
                    confidence=item.get("issue_confidence", "HIGH"),
                )
            )

    # -- Built-in AST scanner ----------------------------------------------

    async def _run_builtin(self, path: str, result: ScanResult) -> None:
        root = Path(path)
        py_files = list(root.rglob("*.py")) if root.is_dir() else [root]

        for py_file in py_files:
            rel = str(py_file)
            if self._is_excluded(rel):
                result.skipped_files += 1
                continue
            try:
                source = py_file.read_text(encoding="utf-8", errors="replace")
            except (OSError, PermissionError):
                result.skipped_files += 1
                continue

            result.scanned_files += 1
            self._scan_file_ast(source, rel, result)
            self._scan_file_regex(source, rel, result)

    def _scan_file_ast(self, source: str, file_path: str, result: ScanResult) -> None:
        try:
            tree = ast.parse(source, filename=file_path)
        except SyntaxError:
            return

        for node in ast.walk(tree):
            for rule in _AST_RULES:
                matcher = rule.get("match")
                if matcher is None:
                    continue
                try:
                    if matcher(node):
                        cwe_entry = get_cwe_entry(rule["cwe"])
                        result.findings.append(
                            Finding(
                                scanner=ScannerType.CODE,
                                rule_id=rule["id"],
                                title=rule["title"],
                                description=rule["description"],
                                severity=rule["severity"],
                                file_path=file_path,
                                line_start=getattr(node, "lineno", None),
                                line_end=getattr(node, "end_lineno", None),
                                evidence=ast.get_source_segment(source, node) or "",
                                cwe=cwe_entry,
                                recommendation=rule.get("recommendation", ""),
                                confidence="HIGH",
                            )
                        )
                except Exception:
                    pass

    def _scan_file_regex(self, source: str, file_path: str, result: ScanResult) -> None:
        lines = source.splitlines()
        for lineno, line in enumerate(lines, start=1):
            # SQL formatting
            if _SQL_FORMAT_RE.search(line):
                result.findings.append(
                    Finding(
                        scanner=ScannerType.CODE,
                        rule_id="SAST-SQL-FORMAT",
                        title="Potential SQL injection via string formatting",
                        description="SQL queries built with string formatting are vulnerable to injection.",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_start=lineno,
                        evidence=line.strip()[:200],
                        cwe=get_cwe_entry("CWE-89"),
                        recommendation="Use parameterised queries or an ORM.",
                        confidence="MEDIUM",
                    )
                )
            # Hardcoded passwords
            if _PASSWORD_RE.search(line):
                result.findings.append(
                    Finding(
                        scanner=ScannerType.CODE,
                        rule_id="SAST-HARDCODED-PASSWORD",
                        title="Potential hard-coded password",
                        description="Hard-coded passwords or secrets should not appear in source code.",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_start=lineno,
                        evidence=_redact_value(line.strip()[:200]),
                        cwe=get_cwe_entry("CWE-798"),
                        recommendation="Move secrets to environment variables or a secrets manager.",
                        confidence="MEDIUM",
                    )
                )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _map_semgrep_severity(sev: str) -> Severity:
    return {
        "ERROR": Severity.HIGH,
        "WARNING": Severity.MEDIUM,
        "INFO": Severity.LOW,
    }.get(sev.upper(), Severity.MEDIUM)


def _map_bandit_severity(sev: str) -> Severity:
    return {
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
    }.get(sev.upper(), Severity.MEDIUM)


def _redact_value(text: str) -> str:
    """Replace literal secret values with asterisks in evidence."""
    return re.sub(r"""(['"])[^'"]{4,}(['"])""", r"\1****\2", text)



