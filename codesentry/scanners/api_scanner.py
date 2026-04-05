"""API Security scanner — spec analysis + optional Spectral."""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import yaml

from codesentry.cwe_mapping import enrich_finding, get_cwe_entry, get_owasp_for_cwe
from codesentry.models import (
    Finding,
    OWASPCategory,
    ScannerType,
    ScanResult,
    Severity,
)
from codesentry.scanners.base_scanner import BaseScanner

logger = logging.getLogger(__name__)

# OpenAPI spec file names to look for
_SPEC_FILENAMES: Set[str] = {
    "openapi.yaml",
    "openapi.yml",
    "openapi.json",
    "swagger.yaml",
    "swagger.yml",
    "swagger.json",
}

# OWASP API Top 10 (2023) mapping
_OWASP_API_TOP10: Dict[str, OWASPCategory] = {
    "API1": OWASPCategory(id="API1", year=2023, name="Broken Object Level Authorization"),
    "API2": OWASPCategory(id="API2", year=2023, name="Broken Authentication"),
    "API3": OWASPCategory(id="API3", year=2023, name="Broken Object Property Level Authorization"),
    "API4": OWASPCategory(id="API4", year=2023, name="Unrestricted Resource Consumption"),
    "API5": OWASPCategory(id="API5", year=2023, name="Broken Function Level Authorization"),
    "API6": OWASPCategory(id="API6", year=2023, name="Unrestricted Access to Sensitive Business Flows"),
    "API7": OWASPCategory(id="API7", year=2023, name="Server Side Request Forgery"),
    "API8": OWASPCategory(id="API8", year=2023, name="Security Misconfiguration"),
    "API9": OWASPCategory(id="API9", year=2023, name="Improper Inventory Management"),
    "API10": OWASPCategory(id="API10", year=2023, name="Unsafe Consumption of APIs"),
}

# Sensitive parameter name patterns
_SENSITIVE_PARAM_NAMES: Set[str] = {
    "password", "passwd", "pwd", "secret", "token",
    "api_key", "apikey", "auth", "credential",
    "ssn", "credit_card", "card_number",
}

# HTTP methods that should require authentication
_AUTH_REQUIRED_METHODS: Set[str] = {"post", "put", "delete", "patch"}


class APIScanner(BaseScanner):
    """Scan OpenAPI/Swagger specs for security anti-patterns."""

    scanner_type = ScannerType.API

    async def scan(self, path: str, **kwargs) -> ScanResult:
        result = self._create_result()
        start = time.time()

        try:
            spec_files = self._find_specs(path)
            if not spec_files:
                result.errors.append("[warning] No OpenAPI/Swagger specification files found.")
            else:
                for spec_path in spec_files:
                    spec = self._load_spec(spec_path, result)
                    if spec is None:
                        continue
                    result.scanned_files += 1
                    self._analyse_spec(spec, str(spec_path), result)

                    # Optionally run Spectral
                    if self._check_tool_available("spectral"):
                        await self._run_spectral(str(spec_path), result)
        except Exception as exc:
            result.errors.append(f"API scan error: {exc}")
            logger.exception("API scan failed")

        result.duration_seconds = round(time.time() - start, 3)
        result.findings = [enrich_finding(f) for f in result.findings]
        return result

    # -- Spec discovery and parsing ----------------------------------------

    def _find_specs(self, path: str) -> List[Path]:
        root = Path(path)
        specs: List[Path] = []
        if root.is_file():
            specs.append(root)
        else:
            for name in _SPEC_FILENAMES:
                candidate = root / name
                if candidate.exists():
                    specs.append(candidate)
            # Also search subdirectories (one level)
            for child in root.iterdir():
                if child.is_dir() and not self._is_excluded(str(child)):
                    for name in _SPEC_FILENAMES:
                        candidate = child / name
                        if candidate.exists():
                            specs.append(candidate)
        return specs

    def _load_spec(
        self, spec_path: Path, result: ScanResult
    ) -> Optional[Dict[str, Any]]:
        try:
            content = spec_path.read_text(encoding="utf-8")
        except OSError as exc:
            result.errors.append(f"Cannot read {spec_path}: {exc}")
            return None

        try:
            if spec_path.suffix == ".json":
                return json.loads(content)
            else:
                return yaml.safe_load(content)
        except Exception as exc:
            result.errors.append(f"Cannot parse {spec_path}: {exc}")
            return None

    # -- Spec analysis -----------------------------------------------------

    def _analyse_spec(
        self,
        spec: Dict[str, Any],
        file_path: str,
        result: ScanResult,
    ) -> None:
        global_security = spec.get("security", [])
        security_schemes = (
            spec.get("components", {}).get("securitySchemes", {})
            or spec.get("securityDefinitions", {})
        )

        # 1 — Missing authentication schemes
        if not security_schemes:
            result.findings.append(
                Finding(
                    scanner=ScannerType.API,
                    rule_id="API-NO-AUTH-SCHEME",
                    title="No authentication schemes defined",
                    description="The API spec does not define any securitySchemes.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    cwe=get_cwe_entry("CWE-306"),
                    owasp=_OWASP_API_TOP10["API2"],
                    recommendation="Define securitySchemes in components and reference them in security.",
                    confidence="HIGH",
                )
            )

        paths = spec.get("paths", {})
        for endpoint, methods in paths.items():
            if not isinstance(methods, dict):
                continue

            for method, operation in methods.items():
                if method.startswith("x-") or not isinstance(operation, dict):
                    continue

                method_lower = method.lower()
                op_security = operation.get("security", global_security)

                # 2 — Mutating methods without security
                if method_lower in _AUTH_REQUIRED_METHODS and not op_security:
                    result.findings.append(
                        Finding(
                            scanner=ScannerType.API,
                            rule_id="API-NO-AUTH-MUTATING",
                            title=f"No auth on {method.upper()} {endpoint}",
                            description=f"{method.upper()} {endpoint} has no security requirement.",
                            severity=Severity.HIGH,
                            file_path=file_path,
                            cwe=get_cwe_entry("CWE-862"),
                            owasp=_OWASP_API_TOP10["API5"],
                            recommendation="Add a security requirement to this operation.",
                            confidence="HIGH",
                            metadata={"endpoint": endpoint, "method": method},
                        )
                    )

                # 3 — Missing input validation (no request body schema)
                request_body = operation.get("requestBody", {})
                if request_body and isinstance(request_body, dict):
                    content = request_body.get("content", {})
                    for media, media_obj in content.items():
                        if isinstance(media_obj, dict) and not media_obj.get("schema"):
                            result.findings.append(
                                Finding(
                                    scanner=ScannerType.API,
                                    rule_id="API-NO-REQUEST-SCHEMA",
                                    title=f"Missing request body schema on {method.upper()} {endpoint}",
                                    description="Request body has no schema, preventing input validation.",
                                    severity=Severity.MEDIUM,
                                    file_path=file_path,
                                    cwe=get_cwe_entry("CWE-20"),
                                    owasp=_OWASP_API_TOP10["API3"],
                                    recommendation="Define a schema for the request body.",
                                    confidence="HIGH",
                                    metadata={"endpoint": endpoint, "method": method},
                                )
                            )

                # 4 — Missing response schemas
                responses = operation.get("responses", {})
                for status_code, resp_obj in responses.items():
                    if not isinstance(resp_obj, dict):
                        continue
                    resp_content = resp_obj.get("content", {})
                    if resp_content:
                        for media, media_obj in resp_content.items():
                            if isinstance(media_obj, dict) and not media_obj.get("schema"):
                                result.findings.append(
                                    Finding(
                                        scanner=ScannerType.API,
                                        rule_id="API-NO-RESPONSE-SCHEMA",
                                        title=f"Missing response schema on {method.upper()} {endpoint} ({status_code})",
                                        description="Response has no schema, risking information exposure.",
                                        severity=Severity.LOW,
                                        file_path=file_path,
                                        cwe=get_cwe_entry("CWE-209"),
                                        recommendation="Define a response schema.",
                                        confidence="MEDIUM",
                                        metadata={"endpoint": endpoint, "method": method, "status": status_code},
                                    )
                                )

                # 5 — Sensitive data in query parameters
                parameters = operation.get("parameters", [])
                for param in parameters:
                    if not isinstance(param, dict):
                        continue
                    if param.get("in") == "query":
                        param_name = param.get("name", "").lower()
                        if param_name in _SENSITIVE_PARAM_NAMES:
                            result.findings.append(
                                Finding(
                                    scanner=ScannerType.API,
                                    rule_id="API-SENSITIVE-QUERY-PARAM",
                                    title=f"Sensitive data in query param '{param.get('name')}' on {endpoint}",
                                    description="Sensitive data in query strings is logged in server logs and browser history.",
                                    severity=Severity.HIGH,
                                    file_path=file_path,
                                    cwe=get_cwe_entry("CWE-598"),
                                    owasp=_OWASP_API_TOP10["API3"],
                                    recommendation="Move sensitive parameters to request headers or body.",
                                    confidence="HIGH",
                                    metadata={"endpoint": endpoint, "param": param.get("name")},
                                )
                            )

                # 6 — Deprecated endpoints
                if operation.get("deprecated"):
                    result.findings.append(
                        Finding(
                            scanner=ScannerType.API,
                            rule_id="API-DEPRECATED-ACTIVE",
                            title=f"Deprecated endpoint still active: {method.upper()} {endpoint}",
                            description="Deprecated endpoints may lack maintenance and security updates.",
                            severity=Severity.LOW,
                            file_path=file_path,
                            cwe=get_cwe_entry("CWE-477"),
                            owasp=_OWASP_API_TOP10["API9"],
                            recommendation="Remove or sunset deprecated endpoints.",
                            confidence="HIGH",
                            metadata={"endpoint": endpoint, "method": method},
                        )
                    )

        # 7 — Rate limiting (check for x-ratelimit in responses)
        has_rate_limit = self._spec_has_rate_limiting(spec)
        if not has_rate_limit:
            result.findings.append(
                Finding(
                    scanner=ScannerType.API,
                    rule_id="API-NO-RATE-LIMIT",
                    title="No rate limiting defined in API spec",
                    description="The spec does not reference rate-limiting headers or extensions.",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    cwe=get_cwe_entry("CWE-770"),
                    owasp=_OWASP_API_TOP10["API4"],
                    recommendation="Document rate limits using x-ratelimit headers or an extension.",
                    confidence="MEDIUM",
                )
            )

        # 8 — Overly permissive CORS (if defined via extensions)
        self._check_cors(spec, file_path, result)

    def _spec_has_rate_limiting(self, spec: Dict[str, Any]) -> bool:
        """Heuristic: search entire spec for rate-limit references."""
        spec_str = json.dumps(spec).lower()
        return any(
            tok in spec_str
            for tok in ("x-ratelimit", "x-rate-limit", "ratelimit", "rate_limit", "throttl")
        )

    def _check_cors(
        self, spec: Dict[str, Any], file_path: str, result: ScanResult
    ) -> None:
        spec_str = json.dumps(spec).lower()
        if '"access-control-allow-origin": "*"' in spec_str or "'*'" in spec_str:
            result.findings.append(
                Finding(
                    scanner=ScannerType.API,
                    rule_id="API-CORS-WILDCARD",
                    title="Overly permissive CORS (wildcard origin)",
                    description="Allowing all origins (*) in CORS can lead to cross-origin attacks.",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    cwe=get_cwe_entry("CWE-346"),
                    owasp=_OWASP_API_TOP10["API8"],
                    recommendation="Restrict Access-Control-Allow-Origin to trusted domains.",
                    confidence="MEDIUM",
                )
            )

    # -- Spectral integration ----------------------------------------------

    async def _run_spectral(self, spec_file: str, result: ScanResult) -> None:
        cmd = ["spectral", "lint", spec_file, "--format", "json"]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
        except (FileNotFoundError, OSError) as exc:
            result.errors.append(f"Failed to run spectral: {exc}")
            return

        if proc.returncode not in (0, 1):
            result.errors.append(
                f"spectral exited {proc.returncode}: "
                f"{stderr.decode(errors='replace')[:500]}"
            )
            return

        try:
            items = json.loads(stdout.decode(errors="replace"))
        except json.JSONDecodeError:
            return

        if not isinstance(items, list):
            return

        seen_rules = {f.rule_id for f in result.findings}
        for item in items:
            code = item.get("code", "spectral")
            if code in seen_rules:
                continue
            sev = _map_spectral_severity(item.get("severity", 1))
            result.findings.append(
                Finding(
                    scanner=ScannerType.API,
                    rule_id=str(code),
                    title=item.get("message", "Spectral finding")[:120],
                    description=item.get("message", ""),
                    severity=sev,
                    file_path=item.get("source", spec_file),
                    line_start=item.get("range", {}).get("start", {}).get("line"),
                    confidence="MEDIUM",
                )
            )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _map_spectral_severity(sev: int) -> Severity:
    # Spectral: 0=error, 1=warning, 2=info, 3=hint
    return {0: Severity.HIGH, 1: Severity.MEDIUM, 2: Severity.LOW, 3: Severity.INFO}.get(
        sev, Severity.MEDIUM
    )



