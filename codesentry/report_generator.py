"""Report generator — JSON, SARIF, Markdown, and plain-text output."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from codesentry.models import FullScanResult, Finding

logger = logging.getLogger(__name__)

_CODESENTRY_VERSION = "0.1.0"

# Severity → SARIF level mapping
_SARIF_LEVEL: Dict[str, str] = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}

# Severity → text prefix for coloured terminal output
_TEXT_PREFIX: Dict[str, str] = {
    "CRITICAL": "🔴 CRITICAL",
    "HIGH": "🟠 HIGH",
    "MEDIUM": "🟡 MEDIUM",
    "LOW": "🔵 LOW",
    "INFO": "ℹ️  INFO",
}

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


# ------------------------------------------------------------------
# Public entry point
# ------------------------------------------------------------------


def generate_report(
    result: FullScanResult,
    fmt: str = "json",
    output_path: Optional[str] = None,
) -> str:
    """Generate a security-scan report in the requested *fmt*.

    Supported formats: ``json``, ``sarif``, ``markdown``, ``text``.
    When *output_path* is given the report is written to that file and the
    file path is returned; otherwise the report string is returned directly.
    """
    generators = {
        "json": _generate_json,
        "sarif": _generate_sarif,
        "markdown": _generate_markdown,
        "text": _generate_text,
    }

    gen = generators.get(fmt.lower())
    if gen is None:
        raise ValueError(
            f"Unsupported report format '{fmt}'. "
            f"Choose from: {', '.join(generators)}"
        )

    report = gen(result)

    if output_path:
        Path(output_path).write_text(report, encoding="utf-8")
        return output_path

    return report


# ------------------------------------------------------------------
# JSON
# ------------------------------------------------------------------


def _generate_json(result: FullScanResult) -> str:
    return json.dumps(result.model_dump(mode="json"), indent=2)


# ------------------------------------------------------------------
# SARIF v2.1.0
# ------------------------------------------------------------------


def _generate_sarif(result: FullScanResult) -> str:
    rules: List[Dict[str, Any]] = []
    results: List[Dict[str, Any]] = []
    seen_rules: Dict[str, int] = {}

    for finding in result.all_findings:
        rule_id = finding.rule_id or finding.id
        if rule_id not in seen_rules:
            seen_rules[rule_id] = len(rules)
            rule_entry: Dict[str, Any] = {
                "id": rule_id,
                "shortDescription": {"text": finding.title},
            }
            if finding.description:
                rule_entry["fullDescription"] = {"text": finding.description}
            props: Dict[str, Any] = {}
            if finding.cwe:
                props["cwe"] = finding.cwe.id if isinstance(finding.cwe, dict) is False else finding.cwe.get("id", "")
            if props:
                rule_entry["properties"] = props
            rules.append(rule_entry)

        sarif_result = _finding_to_sarif_result(finding, rule_id)
        results.append(sarif_result)

    sarif_doc = {
        "$schema": (
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
            "main/sarif-2.1/schema/sarif-schema-2.1.0.json"
        ),
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CodeSentry",
                        "version": _CODESENTRY_VERSION,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif_doc, indent=2)


def _finding_to_sarif_result(
    finding: Finding,
    rule_id: str,
) -> Dict[str, Any]:
    severity = finding.severity if isinstance(finding.severity, str) else finding.severity.value
    level = _SARIF_LEVEL.get(severity, "note")

    message_text = finding.title
    if finding.description:
        message_text = f"{finding.title}: {finding.description}"

    sarif_result: Dict[str, Any] = {
        "ruleId": rule_id,
        "level": level,
        "message": {"text": message_text},
    }

    # Location
    if finding.file_path:
        location: Dict[str, Any] = {
            "physicalLocation": {
                "artifactLocation": {"uri": finding.file_path},
            }
        }
        if finding.line_start is not None:
            region: Dict[str, Any] = {"startLine": finding.line_start}
            if finding.line_end is not None:
                region["endLine"] = finding.line_end
            location["physicalLocation"]["region"] = region
        sarif_result["locations"] = [location]

    # Extra properties (CWE, OWASP, CVE)
    props: Dict[str, Any] = {}
    if finding.cwe:
        cwe_obj = finding.cwe
        cwe_id = cwe_obj.id if hasattr(cwe_obj, "id") else cwe_obj.get("id", "")
        props["cwe"] = cwe_id
    if finding.owasp:
        owasp_obj = finding.owasp
        owasp_id = owasp_obj.id if hasattr(owasp_obj, "id") else owasp_obj.get("id", "")
        owasp_name = owasp_obj.name if hasattr(owasp_obj, "name") else owasp_obj.get("name", "")
        props["owasp"] = f"{owasp_id} — {owasp_name}"
    if finding.cve_id:
        props["cve"] = finding.cve_id
    if props:
        sarif_result["properties"] = props

    return sarif_result


# ------------------------------------------------------------------
# Markdown
# ------------------------------------------------------------------


def _generate_markdown(result: FullScanResult) -> str:
    try:
        return _generate_markdown_jinja(result)
    except Exception:
        logger.debug("Jinja2 template not available, using built-in markdown.")
        return _generate_markdown_builtin(result)


def _generate_markdown_jinja(result: FullScanResult) -> str:
    """Render Markdown via the Jinja2 template shipped with the package."""
    import jinja2

    template_dir = Path(__file__).parent / "templates"
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(template_dir)),
        autoescape=False,
    )
    template = env.get_template("report.md.jinja2")
    return template.render(result=result)


def _generate_markdown_builtin(result: FullScanResult) -> str:
    """Pure-Python Markdown fallback (no Jinja2 dependency)."""
    lines: List[str] = []
    lines.append("# CodeSentry Security Report\n")
    lines.append(f"**Project:** {result.project_path}  ")
    lines.append(
        f"**Scanned at:** {result.scanned_at.strftime('%Y-%m-%d %H:%M:%S')}  "
    )
    lines.append(f"**Duration:** {result.scan_duration_seconds}s\n")
    lines.append("## Summary\n")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev, count in result.findings_by_severity.items():
        lines.append(f"| {sev} | {count} |")
    lines.append(f"| **Total** | **{result.total_findings}** |\n")

    findings = sorted(
        result.all_findings,
        key=lambda f: _SEVERITY_ORDER.get(
            f.severity if isinstance(f.severity, str) else f.severity.value, 4
        ),
    )

    if findings:
        lines.append("## Findings\n")
        for f in findings:
            sev = f.severity if isinstance(f.severity, str) else f.severity.value
            lines.append(f"### {sev} — {f.title}\n")
            lines.append(f"- **Scanner:** {f.scanner}")
            loc = f.file_path or "N/A"
            if f.line_start:
                loc += f" (line {f.line_start})"
            lines.append(f"- **File:** {loc}")
            cwe_text = f"{f.cwe.id} — {f.cwe.name}" if f.cwe else "N/A"
            lines.append(f"- **CWE:** {cwe_text}")
            owasp_text = f"{f.owasp.id} — {f.owasp.name}" if f.owasp else "N/A"
            lines.append(f"- **OWASP:** {owasp_text}")
            if f.cve_id:
                lines.append(f"- **CVE:** {f.cve_id}")
            if f.recommendation:
                lines.append(f"- **Fix:** {f.recommendation}")
            lines.append("")

    return "\n".join(lines)


# ------------------------------------------------------------------
# Plain text (terminal)
# ------------------------------------------------------------------


def _generate_text(result: FullScanResult) -> str:
    lines: List[str] = []

    findings = sorted(
        result.all_findings,
        key=lambda f: _SEVERITY_ORDER.get(
            f.severity if isinstance(f.severity, str) else f.severity.value, 4
        ),
    )

    if not findings:
        lines.append("✅ No security findings detected.")
        return "\n".join(lines)

    # Group by scanner
    by_scanner: Dict[str, List[Finding]] = {}
    for f in findings:
        scanner_name = f.scanner if isinstance(f.scanner, str) else f.scanner.value
        by_scanner.setdefault(scanner_name, []).append(f)

    for scanner_name, scanner_findings in by_scanner.items():
        lines.append(f"─── {scanner_name} ───")
        for f in scanner_findings:
            sev = f.severity if isinstance(f.severity, str) else f.severity.value
            prefix = _TEXT_PREFIX.get(sev, sev)
            loc = ""
            if f.file_path:
                loc = f"  {f.file_path}"
                if f.line_start:
                    loc += f":{f.line_start}"
            lines.append(f"  {prefix}  {f.title}{loc}")
            if f.cwe:
                cwe_id = f.cwe.id if hasattr(f.cwe, "id") else f.cwe.get("id", "")
                lines.append(f"           CWE: {cwe_id}")
            if f.recommendation:
                lines.append(f"           Fix: {f.recommendation}")
        lines.append("")

    return "\n".join(lines)
