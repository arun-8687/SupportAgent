"""Click-based CLI for CodeSentry."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import click


@click.group()
@click.version_option(version="0.1.0", prog_name="codesentry")
def main() -> None:
    """CodeSentry — Local code security scanner with CWE/OWASP mapping."""


@main.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option(
    "--format",
    "-f",
    "output_format",
    default="text",
    type=click.Choice(["text", "json", "sarif", "markdown"]),
    help="Report output format.",
)
@click.option(
    "--output",
    "-o",
    "output_file",
    default=None,
    type=click.Path(),
    help="Write report to this file instead of stdout.",
)
@click.option(
    "--severity",
    "-s",
    default="medium",
    type=click.Choice(["critical", "high", "medium", "low", "info"]),
    help="Minimum severity threshold for exit-code failure.",
)
@click.option(
    "--scanners",
    default=None,
    help="Comma-separated list of scanners to enable (e.g. code,secret,dependency).",
)
@click.option(
    "--config",
    "-c",
    "config_file",
    default=None,
    type=click.Path(),
    help="Path to a codesentry.yaml configuration file.",
)
def scan(
    path: str,
    output_format: str,
    output_file: str | None,
    severity: str,
    scanners: str | None,
    config_file: str | None,
) -> None:
    """Scan a project for security vulnerabilities."""
    asyncio.run(
        _run_scan(path, output_format, output_file, severity, scanners, config_file)
    )


async def _run_scan(
    path: str,
    output_format: str,
    output_file: str | None,
    severity: str,
    scanners: str | None,
    config_file: str | None,
) -> None:
    from codesentry.config import load_config
    from codesentry.orchestrator import ScanOrchestrator
    from codesentry.report_generator import generate_report

    # Banner
    click.echo(
        click.style("🔒 CodeSentry Security Scanner v0.1.0", fg="cyan", bold=True)
    )
    click.echo(f"   Scanning: {Path(path).resolve()}")
    click.echo()

    # Load config
    config = load_config(config_path=config_file, project_path=path)

    # Override enabled scanners when --scanners is given.
    if scanners:
        requested = {s.strip().upper().replace("-", "_") for s in scanners.split(",")}
        for key in list(config.scanners):
            config.scanners[key] = key in requested

    # Override severity threshold.
    config.severity_threshold = severity.upper()

    # Run scan with a simple progress indicator.
    orchestrator = ScanOrchestrator(config)
    with click.progressbar(length=100, label="Scanning") as bar:
        bar.update(10)
        result = await orchestrator.scan(str(Path(path).resolve()))
        bar.update(90)

    click.echo()

    # Generate report.
    report = generate_report(result, output_format, output_file)

    if output_file:
        click.echo(f"📄 Report saved to: {output_file}")
    else:
        click.echo(report)

    # Summary
    total = result.total_findings
    by_sev = result.findings_by_severity

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

    click.echo()
    click.echo(click.style(f"{'=' * 50}", fg="cyan"))
    click.echo(f"  Total findings: {total}")
    if by_sev.get("CRITICAL", 0):
        click.echo(
            click.style(f"  🔴 Critical: {by_sev['CRITICAL']}", fg="red", bold=True)
        )
    if by_sev.get("HIGH", 0):
        click.echo(click.style(f"  🟠 High: {by_sev['HIGH']}", fg="red"))
    if by_sev.get("MEDIUM", 0):
        click.echo(click.style(f"  🟡 Medium: {by_sev['MEDIUM']}", fg="yellow"))
    if by_sev.get("LOW", 0):
        click.echo(click.style(f"  🔵 Low: {by_sev['LOW']}", fg="blue"))
    if by_sev.get("INFO", 0):
        click.echo(f"  ℹ️  Info: {by_sev['INFO']}")
    click.echo(click.style(f"{'=' * 50}", fg="cyan"))
    click.echo(f"  Scan completed in {result.scan_duration_seconds:.1f}s")

    # Non-zero exit code when findings meet the severity threshold.
    threshold = severity_order.get(severity.upper(), 2)
    above_threshold = sum(
        count
        for sev, count in by_sev.items()
        if severity_order.get(sev, 4) <= threshold
    )
    if above_threshold > 0:
        sys.exit(1)

