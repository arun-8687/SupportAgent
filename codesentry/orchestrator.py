"""Scan orchestrator — runs all enabled scanners and merges results."""

from __future__ import annotations

import asyncio
import importlib
import logging
import re
import time
from typing import List, Optional, Tuple, Type

from codesentry.config import ScanConfig, load_config
from codesentry.cwe_mapping import enrich_finding
from codesentry.models import FullScanResult, ScanResult, ScannerType, Finding
from codesentry.project_detector import ProjectInfo, detect_project

logger = logging.getLogger(__name__)


def sanitize_error_message(error_msg: str) -> str:
    """Sanitize potentially sensitive information from error messages."""
    # Redact common patterns for API keys, tokens, passwords, connection strings
    patterns = [
        (r'(api[_-]?key[\'"]?\s*[:=]\s*[\'"]?)([^\'")\s]+)', r'\1***REDACTED***'),
        (r'(token[\'"]?\s*[:=]\s*[\'"]?)([^\'")\s]+)', r'\1***REDACTED***'),
        (r'(password[\'"]?\s*[:=]\s*[\'"]?)([^\'")\s]+)', r'\1***REDACTED***'),
        (r'(secret[\'"]?\s*[:=]\s*[\'"]?)([^\'")\s]+)', r'\1***REDACTED***'),
        (r'(postgresql://[^:]+:)([^@]+)(@)', r'\1***REDACTED***\3'),
        (r'(AccountKey=)([^;]+)', r'\1***REDACTED***'),
    ]

    sanitized = error_msg
    for pattern, replacement in patterns:
        sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)

    return sanitized

# Maps lowercase scanner keys to (module_path, class_name, ScannerType).
# Compliance is intentionally excluded — it runs after all others.
_SCANNER_MAP = {
    "code": ("codesentry.scanners.code_scanner", "CodeScanner", ScannerType.CODE),
    "dependency": (
        "codesentry.scanners.dependency_scanner",
        "DependencyScanner",
        ScannerType.DEPENDENCY,
    ),
    "secret": (
        "codesentry.scanners.secret_scanner",
        "SecretScanner",
        ScannerType.SECRET,
    ),
    "iac": ("codesentry.scanners.iac_scanner", "IaCScanner", ScannerType.IAC),
    "container": (
        "codesentry.scanners.container_scanner",
        "ContainerScanner",
        ScannerType.CONTAINER,
    ),
    "license": (
        "codesentry.scanners.license_scanner",
        "LicenseScanner",
        ScannerType.LICENSE,
    ),
    "dast": ("codesentry.scanners.dast_scanner", "DASTScanner", ScannerType.DAST),
    "api": ("codesentry.scanners.api_scanner", "APIScanner", ScannerType.API),
    "supply_chain": (
        "codesentry.scanners.supply_chain_scanner",
        "SupplyChainScanner",
        ScannerType.SUPPLY_CHAIN,
    ),
}


class ScanOrchestrator:
    """Runs all enabled scanners and merges results."""

    def __init__(self, config: Optional[ScanConfig] = None) -> None:
        self.config = config

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    async def scan(
        self,
        path: str,
        config: Optional[ScanConfig] = None,
    ) -> FullScanResult:
        """Run a full security scan on the given *path*."""
        cfg = config or self.config or load_config(project_path=path)
        start = time.time()

        project = detect_project(path)
        scanners = self._get_enabled_scanners(cfg, project)

        # Run all scanners concurrently.
        raw_results = await asyncio.gather(
            *[self._run_scanner(cls, scanner_type, path, cfg) for cls, scanner_type in scanners],
            return_exceptions=True,
        )

        scan_results: List[ScanResult] = []
        for result in raw_results:
            if isinstance(result, ScanResult):
                result.findings = [enrich_finding(f) for f in result.findings]
                scan_results.append(result)
            elif isinstance(result, Exception):
                sanitized_error = sanitize_error_message(str(result))
                logger.warning("Scanner failed: %s", sanitized_error)
                scan_results.append(
                    ScanResult(scanner=ScannerType.CODE, errors=[sanitized_error])
                )

        # Compliance scanner runs last — it needs the combined findings.
        if cfg.scanners.get("COMPLIANCE", False):
            all_findings: List[Finding] = []
            for sr in scan_results:
                all_findings.extend(sr.findings)
            try:
                from codesentry.scanners.compliance_scanner import ComplianceScanner

                comp = ComplianceScanner({})
                comp_result = await comp.scan(path, existing_findings=all_findings)
                comp_result.findings = [
                    enrich_finding(f) for f in comp_result.findings
                ]
                scan_results.append(comp_result)
            except Exception as exc:
                sanitized_error = sanitize_error_message(str(exc))
                logger.warning("Compliance scanner failed: %s", sanitized_error)
                scan_results.append(
                    ScanResult(
                        scanner=ScannerType.COMPLIANCE,
                        errors=[sanitized_error],
                    )
                )

        duration = time.time() - start
        return FullScanResult(
            scan_results=scan_results,
            project_path=path,
            scan_duration_seconds=round(duration, 2),
            config_used=cfg.model_dump() if hasattr(cfg, "model_dump") else {},
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_enabled_scanners(
        self,
        cfg: ScanConfig,
        project: ProjectInfo,
    ) -> List[Tuple[Type, ScannerType]]:
        """Return *(scanner_class, scanner_type)* pairs for enabled scanners."""
        scanners: List[Tuple[Type, ScannerType]] = []

        for key, (module_path, class_name, scanner_type) in _SCANNER_MAP.items():
            config_key = key.upper()
            enabled = cfg.scanners.get(config_key, self._default_enabled(key, project))
            if not enabled:
                continue
            try:
                mod = importlib.import_module(module_path)
                cls = getattr(mod, class_name)
                scanners.append((cls, scanner_type))
            except (ImportError, AttributeError) as exc:
                error_type = type(exc).__name__
                logger.debug("Scanner %s unavailable (%s)", key, error_type)

        return scanners

    @staticmethod
    def _default_enabled(scanner_key: str, project: ProjectInfo) -> bool:
        """Decide if a scanner should be on by default based on project info."""
        if scanner_key in ("code", "secret"):
            return True
        if scanner_key == "dependency":
            return bool(project.ecosystems)
        if scanner_key == "iac":
            return bool(project.iac_frameworks)
        if scanner_key == "api":
            return bool(project.api_specs)
        return False

    @staticmethod
    async def _run_scanner(
        cls: Type,
        scanner_type: ScannerType,
        path: str,
        cfg: ScanConfig,
    ) -> ScanResult:
        """Instantiate and run a single scanner."""
        try:
            scanner = cls({})
            return await scanner.scan(path, exclude_paths=cfg.exclude_paths)
        except Exception as exc:
            sanitized_error = sanitize_error_message(str(exc))
            return ScanResult(scanner=scanner_type, errors=[sanitized_error])
