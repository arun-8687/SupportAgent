"""Supply chain and malware detection scanner."""

from __future__ import annotations

import asyncio
import json
import logging
import math
import re
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

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
# Popular packages for typosquatting detection
# ---------------------------------------------------------------------------

_POPULAR_PYTHON: Set[str] = {
    "requests", "flask", "django", "numpy", "pandas", "boto3",
    "urllib3", "setuptools", "pip", "wheel", "six", "pyyaml",
    "cryptography", "certifi", "idna", "charset-normalizer",
    "jinja2", "markupsafe", "click", "pillow", "scipy",
    "sqlalchemy", "pydantic", "fastapi", "uvicorn", "gunicorn",
    "celery", "redis", "psycopg2", "pymongo", "httpx",
    "aiohttp", "beautifulsoup4", "lxml", "paramiko", "fabric",
    "scrapy", "tensorflow", "torch", "keras", "scikit-learn",
    "matplotlib", "seaborn", "plotly", "pytest", "tox",
    "black", "ruff", "mypy", "pylint", "flake8",
}

_POPULAR_NPM: Set[str] = {
    "express", "react", "lodash", "axios", "moment",
    "webpack", "babel", "typescript", "eslint", "prettier",
    "next", "vue", "angular", "jquery", "underscore",
    "chalk", "commander", "yargs", "debug", "dotenv",
    "mongoose", "sequelize", "knex", "pg", "mysql2",
    "socket.io", "cors", "helmet", "morgan", "passport",
    "jsonwebtoken", "bcrypt", "uuid", "date-fns", "rxjs",
}

# Suspicious patterns in setup.py / install scripts
_SUSPICIOUS_SETUP_PATTERNS: List[Dict[str, Any]] = [
    {
        "id": "SC-SETUP-NETWORK",
        "pattern": re.compile(r"\b(urllib|requests|socket|http\.client|urlopen)\b"),
        "title": "Network call in setup script",
        "description": "setup.py makes network calls which may download malicious payloads.",
        "severity": Severity.HIGH,
    },
    {
        "id": "SC-SETUP-EXEC",
        "pattern": re.compile(r"\b(os\.system|subprocess|Popen|exec|eval)\s*\("),
        "title": "Shell execution in setup script",
        "description": "setup.py executes shell commands which may be malicious.",
        "severity": Severity.CRITICAL,
    },
    {
        "id": "SC-SETUP-BASE64",
        "pattern": re.compile(r"\b(base64\.b64decode|b64decode|atob)\b"),
        "title": "Base64 decoding in setup script",
        "description": "setup.py decodes Base64 data which may hide malicious payloads.",
        "severity": Severity.HIGH,
    },
    {
        "id": "SC-SETUP-OBFUSCATION",
        "pattern": re.compile(r"(\\x[0-9a-fA-F]{2}){8,}|chr\(\d+\)\s*\+\s*chr\("),
        "title": "Obfuscated code in setup script",
        "description": "setup.py contains obfuscated code patterns.",
        "severity": Severity.HIGH,
    },
]


class SupplyChainScanner(BaseScanner):
    """Detect supply chain attacks and malicious packages."""

    scanner_type = ScannerType.SUPPLY_CHAIN

    async def scan(self, path: str, **kwargs) -> ScanResult:
        result = self._create_result()
        start = time.time()

        root = Path(path)
        try:
            # Python ecosystem
            req_file = root / "requirements.txt"
            if req_file.exists():
                deps = self._parse_requirements(req_file)
                self._check_typosquatting(deps, "python", str(req_file), result)

                # Check if guarddog is available
                if self._check_tool_available("guarddog"):
                    for pkg_name, _ in deps:
                        await self._run_guarddog(pkg_name, result)

            # Check setup.py
            setup_py = root / "setup.py"
            if setup_py.exists():
                self._check_install_script(setup_py, result)

            # Check setup.cfg
            setup_cfg = root / "setup.cfg"
            if setup_cfg.exists():
                self._check_install_script(setup_cfg, result)

            # JavaScript ecosystem
            pkg_json = root / "package.json"
            if pkg_json.exists():
                self._check_npm_packages(pkg_json, result)
        except Exception as exc:
            result.errors.append(f"Supply chain scan error: {exc}")
            logger.exception("Supply chain scan failed")

        result.duration_seconds = round(time.time() - start, 3)
        result.findings = [enrich_finding(f) for f in result.findings]
        return result

    # -- Typosquatting detection --------------------------------------------

    def _check_typosquatting(
        self,
        deps: List[tuple],
        ecosystem: str,
        file_path: str,
        result: ScanResult,
    ) -> None:
        popular = _POPULAR_PYTHON if ecosystem == "python" else _POPULAR_NPM
        for pkg_name, _ in deps:
            name_lower = pkg_name.lower().replace("-", "_").replace(".", "_")
            if name_lower in {p.lower().replace("-", "_") for p in popular}:
                continue

            for pop in popular:
                pop_norm = pop.lower().replace("-", "_")
                dist = _levenshtein(name_lower, pop_norm)
                if 1 <= dist <= 2:
                    result.findings.append(
                        Finding(
                            scanner=ScannerType.SUPPLY_CHAIN,
                            rule_id="SC-TYPOSQUAT",
                            title=f"Possible typosquatting: '{pkg_name}' ≈ '{pop}'",
                            description=(
                                f"Package '{pkg_name}' has Levenshtein distance {dist} "
                                f"from popular package '{pop}'. This could be a typosquatting attack."
                            ),
                            severity=Severity.HIGH,
                            file_path=file_path,
                            cwe=get_cwe_entry("CWE-829"),
                            recommendation=f"Verify that '{pkg_name}' is the intended package (not '{pop}').",
                            confidence="MEDIUM",
                            metadata={
                                "package": pkg_name,
                                "similar_to": pop,
                                "distance": dist,
                            },
                        )
                    )
                    break  # One match per package is enough

    # -- Install script analysis -------------------------------------------

    def _check_install_script(self, script_path: Path, result: ScanResult) -> None:
        try:
            content = script_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return

        result.scanned_files += 1
        rel = str(script_path)

        for rule in _SUSPICIOUS_SETUP_PATTERNS:
            matches = list(rule["pattern"].finditer(content))
            for match in matches:
                lineno = content[:match.start()].count("\n") + 1
                result.findings.append(
                    Finding(
                        scanner=ScannerType.SUPPLY_CHAIN,
                        rule_id=rule["id"],
                        title=rule["title"],
                        description=rule["description"],
                        severity=rule["severity"],
                        file_path=rel,
                        line_start=lineno,
                        evidence=match.group(0)[:100],
                        cwe=get_cwe_entry("CWE-506"),
                        recommendation="Review the setup script for malicious intent.",
                        confidence="MEDIUM",
                    )
                )

        # High-entropy string detection (possible obfuscation)
        for lineno, line in enumerate(content.splitlines(), start=1):
            strings = re.findall(r"""['"]([A-Za-z0-9+/=]{40,})['"]""", line)
            for s in strings:
                entropy = _shannon_entropy(s)
                if entropy > 4.5:
                    result.findings.append(
                        Finding(
                            scanner=ScannerType.SUPPLY_CHAIN,
                            rule_id="SC-SETUP-HIGH-ENTROPY",
                            title="High-entropy string in setup script",
                            description=f"A string with Shannon entropy {entropy:.2f} was found, possibly obfuscated code.",
                            severity=Severity.MEDIUM,
                            file_path=rel,
                            line_start=lineno,
                            evidence=s[:60] + "..." if len(s) > 60 else s,
                            cwe=get_cwe_entry("CWE-506"),
                            recommendation="Investigate whether this string contains encoded malicious content.",
                            confidence="LOW",
                        )
                    )

    # -- npm install script checks -----------------------------------------

    def _check_npm_packages(self, pkg_json: Path, result: ScanResult) -> None:
        try:
            data = json.loads(pkg_json.read_text(encoding="utf-8"))
        except Exception:
            return

        result.scanned_files += 1
        rel = str(pkg_json)

        # Check lifecycle scripts
        scripts = data.get("scripts", {})
        risky_hooks = ["preinstall", "postinstall", "preuninstall", "postuninstall"]
        for hook in risky_hooks:
            script_cmd = scripts.get(hook, "")
            if not script_cmd:
                continue
            suspicious = any(
                tok in script_cmd.lower()
                for tok in [
                    "curl ", "wget ", "powershell", "cmd /c",
                    "node -e", "eval(", "base64",
                    "/dev/tcp", "nc ", "ncat ",
                ]
            )
            if suspicious:
                result.findings.append(
                    Finding(
                        scanner=ScannerType.SUPPLY_CHAIN,
                        rule_id="SC-NPM-RISKY-HOOK",
                        title=f"Suspicious '{hook}' script in package.json",
                        description=f"The {hook} script contains potentially malicious commands.",
                        severity=Severity.HIGH,
                        file_path=rel,
                        evidence=script_cmd[:200],
                        cwe=get_cwe_entry("CWE-506"),
                        recommendation="Review the lifecycle script for malicious intent.",
                        confidence="MEDIUM",
                    )
                )

        # Typosquatting for npm deps
        all_deps = {
            **data.get("dependencies", {}),
            **data.get("devDependencies", {}),
        }
        dep_tuples = [(name, ver) for name, ver in all_deps.items()]
        self._check_typosquatting(dep_tuples, "npm", rel, result)

    # -- guarddog integration ----------------------------------------------

    async def _run_guarddog(self, package: str, result: ScanResult) -> None:
        cmd = ["guarddog", "pypi", "verify", package]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
        except (FileNotFoundError, OSError) as exc:
            result.errors.append(f"Failed to run guarddog for {package}: {exc}")
            return

        if proc.returncode not in (0, 1):
            result.errors.append(
                f"guarddog exited {proc.returncode} for {package}: "
                f"{stderr.decode(errors='replace')[:300]}"
            )
            return

        # guarddog outputs JSON with results
        try:
            data = json.loads(stdout.decode(errors="replace"))
        except json.JSONDecodeError:
            return

        issues = data.get("issues", data.get("results", []))
        if isinstance(issues, dict):
            for rule_name, details in issues.items():
                if details:
                    result.findings.append(
                        Finding(
                            scanner=ScannerType.SUPPLY_CHAIN,
                            rule_id=f"guarddog-{rule_name}",
                            title=f"guarddog: {rule_name} in {package}",
                            description=str(details)[:500],
                            severity=Severity.HIGH,
                            cwe=get_cwe_entry("CWE-506"),
                            confidence="HIGH",
                            metadata={"package": package},
                        )
                    )

    # -- Helpers -----------------------------------------------------------

    @staticmethod
    def _parse_requirements(req_file: Path) -> List[tuple]:
        results = []
        try:
            for line in req_file.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                m = re.match(r"^([A-Za-z0-9_.\-]+)\s*(?:[=<>!~]+\s*(.+))?", line)
                if m:
                    results.append((m.group(1), m.group(2)))
        except Exception:
            pass
        return results


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def _levenshtein(s1: str, s2: str) -> int:
    """Compute the Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)

    prev_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row

    return prev_row[-1]


def _shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
        if count > 0
    )
