"""CodeSentry public API."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import List, Optional

from codesentry.config import ScanConfig, load_config
from codesentry.models import FullScanResult
from codesentry.orchestrator import ScanOrchestrator
from codesentry.report_generator import generate_report as _generate_report


def scan(
    path: str = ".",
    config: Optional[ScanConfig] = None,
    scanners: Optional[List[str]] = None,
) -> FullScanResult:
    """Scan a project for security vulnerabilities.

    Args:
        path: Path to project directory.
        config: Optional :class:`ScanConfig` override.
        scanners: Optional list of scanner names to enable (e.g.
            ``["code", "secret"]``).  When provided, only these scanners
            run; all others are disabled.

    Returns:
        :class:`FullScanResult` with all findings.
    """
    cfg = config or load_config(project_path=path)

    if scanners:
        requested = {s.upper().replace("-", "_") for s in scanners}
        for key in list(cfg.scanners):
            cfg.scanners[key] = key in requested

    orchestrator = ScanOrchestrator(cfg)
    return asyncio.run(orchestrator.scan(str(Path(path).resolve())))


def report(
    result: FullScanResult,
    fmt: str = "json",
    output_path: Optional[str] = None,
) -> str:
    """Generate a report from a :class:`FullScanResult`.

    Args:
        result: The scan result to render.
        fmt: Output format — ``json``, ``sarif``, ``markdown``, or ``text``.
        output_path: If given, write the report to this file and return the
            path.  Otherwise return the report string.

    Returns:
        Report content or path to the written file.
    """
    return _generate_report(result, fmt, output_path)
