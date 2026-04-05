"""License compliance and SBOM scanner."""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from codesentry.cwe_mapping import enrich_finding
from codesentry.models import (
    Finding,
    ScannerType,
    ScanResult,
    Severity,
)
from codesentry.scanners.base_scanner import BaseScanner

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# License policy
# ---------------------------------------------------------------------------

_DENIED_LICENSES: Set[str] = {
    "GPL-3.0",
    "GPL-3.0-only",
    "GPL-3.0-or-later",
    "AGPL-3.0",
    "AGPL-3.0-only",
    "AGPL-3.0-or-later",
}

_WARNING_LICENSES: Set[str] = {
    "LGPL-2.1",
    "LGPL-2.1-only",
    "LGPL-2.1-or-later",
    "LGPL-3.0",
    "LGPL-3.0-only",
    "LGPL-3.0-or-later",
    "MPL-2.0",
    "EUPL-1.2",
    "CPAL-1.0",
}

_ALLOWED_LICENSES: Set[str] = {
    "MIT",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "0BSD",
    "Unlicense",
    "CC0-1.0",
    "PSF-2.0",
    "Python-2.0",
    "WTFPL",
    "Zlib",
}

# Normalisation helpers
_LICENSE_ALIASES: Dict[str, str] = {
    "mit license": "MIT",
    "mit": "MIT",
    "apache 2.0": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "apache software license": "Apache-2.0",
    "bsd license": "BSD-3-Clause",
    "bsd": "BSD-3-Clause",
    "new bsd license": "BSD-3-Clause",
    "bsd-3-clause license": "BSD-3-Clause",
    "simplified bsd license": "BSD-2-Clause",
    "bsd-2-clause license": "BSD-2-Clause",
    "isc license": "ISC",
    "isc": "ISC",
    "gpl v3": "GPL-3.0",
    "gplv3": "GPL-3.0",
    "gnu general public license v3": "GPL-3.0",
    "gnu gpl v3": "GPL-3.0",
    "lgpl v3": "LGPL-3.0",
    "lgplv3": "LGPL-3.0",
    "agpl v3": "AGPL-3.0",
    "agplv3": "AGPL-3.0",
    "mozilla public license 2.0": "MPL-2.0",
    "mpl 2.0": "MPL-2.0",
    "python software foundation license": "PSF-2.0",
    "psf": "PSF-2.0",
    "the unlicense": "Unlicense",
    "public domain": "Unlicense",
}


class LicenseScanner(BaseScanner):
    """Scan project dependencies for license compliance issues."""

    scanner_type = ScannerType.LICENSE

    async def scan(self, path: str, **kwargs) -> ScanResult:
        result = self._create_result()
        start = time.time()

        try:
            root = Path(path)

            # Python
            req_file = root / "requirements.txt"
            if req_file.exists():
                await self._check_python_licenses(req_file, result)

            # JavaScript
            pkg_json = root / "package.json"
            if pkg_json.exists():
                self._check_js_licenses(pkg_json, result)
        except Exception as exc:
            result.errors.append(f"License scan error: {exc}")
            logger.exception("License scan failed")

        result.duration_seconds = round(time.time() - start, 3)
        return result

    # -- Python license checks ---------------------------------------------

    async def _check_python_licenses(
        self, req_file: Path, result: ScanResult
    ) -> None:
        deps = _parse_requirements(req_file)
        result.scanned_files += 1

        for pkg_name, _version in deps:
            license_name = await self._get_python_license(pkg_name)
            if license_name is None:
                result.errors.append("[warning] Could not determine license for Python package '" + pkg_name + "'.")
                continue

            normalised = _normalise_license(license_name)
            self._evaluate_license(
                pkg_name, normalised, license_name, str(req_file), result
            )

    async def _get_python_license(self, pkg_name: str) -> Optional[str]:
        """Try ``pip show`` to get the license of an installed package."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "pip", "show", pkg_name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
        except (FileNotFoundError, OSError):
            return None

        if proc.returncode != 0:
            return None

        for line in stdout.decode(errors="replace").splitlines():
            if line.lower().startswith("license:"):
                value = line.split(":", 1)[1].strip()
                if value and value.upper() != "UNKNOWN":
                    return value
        return None

    # -- JavaScript license checks -----------------------------------------

    def _check_js_licenses(self, pkg_json: Path, result: ScanResult) -> None:
        try:
            data = json.loads(pkg_json.read_text(encoding="utf-8"))
        except Exception:
            return

        result.scanned_files += 1

        # Also check node_modules for licence metadata if present
        node_modules = pkg_json.parent / "node_modules"
        all_deps = {
            **data.get("dependencies", {}),
            **data.get("devDependencies", {}),
        }

        for pkg_name in all_deps:
            license_name = self._get_js_license(node_modules, pkg_name, data)
            if license_name is None:
                continue

            normalised = _normalise_license(license_name)
            self._evaluate_license(
                pkg_name, normalised, license_name, str(pkg_json), result
            )

    def _get_js_license(
        self,
        node_modules: Path,
        pkg_name: str,
        root_data: Dict[str, Any],
    ) -> Optional[str]:
        # Try node_modules/<pkg>/package.json
        pkg_dir = node_modules / pkg_name / "package.json"
        if pkg_dir.exists():
            try:
                pdata = json.loads(pkg_dir.read_text(encoding="utf-8"))
                lic = pdata.get("license")
                if isinstance(lic, str):
                    return lic
                if isinstance(lic, dict):
                    return lic.get("type")
            except Exception:
                pass
        return None

    # -- Common evaluation -------------------------------------------------

    def _evaluate_license(
        self,
        pkg_name: str,
        normalised: str,
        raw_license: str,
        file_path: str,
        result: ScanResult,
    ) -> None:
        if normalised in _DENIED_LICENSES:
            result.findings.append(
                Finding(
                    scanner=ScannerType.LICENSE,
                    rule_id=f"LICENSE-DENY-{normalised}",
                    title=f"Denied license: {raw_license} ({pkg_name})",
                    description=(
                        f"Package '{pkg_name}' uses license '{raw_license}' "
                        f"(normalised: {normalised}) which is not allowed by policy."
                    ),
                    severity=Severity.HIGH,
                    file_path=file_path,
                    recommendation=(
                        f"Replace '{pkg_name}' with a permissively licensed alternative "
                        "or obtain a commercial license."
                    ),
                    confidence="HIGH",
                    metadata={"license": raw_license, "normalised": normalised},
                )
            )
        elif normalised in _WARNING_LICENSES:
            result.findings.append(
                Finding(
                    scanner=ScannerType.LICENSE,
                    rule_id=f"LICENSE-WARN-{normalised}",
                    title=f"Cautionary license: {raw_license} ({pkg_name})",
                    description=(
                        f"Package '{pkg_name}' uses license '{raw_license}' "
                        f"(normalised: {normalised}) which requires review."
                    ),
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    recommendation="Review the license obligations before using in production.",
                    confidence="HIGH",
                    metadata={"license": raw_license, "normalised": normalised},
                )
            )
        elif normalised not in _ALLOWED_LICENSES and normalised:
            result.findings.append(
                Finding(
                    scanner=ScannerType.LICENSE,
                    rule_id=f"LICENSE-UNKNOWN-{normalised}",
                    title=f"Unknown license: {raw_license} ({pkg_name})",
                    description=(
                        f"Package '{pkg_name}' uses license '{raw_license}' "
                        "which is not in the allow-list."
                    ),
                    severity=Severity.LOW,
                    file_path=file_path,
                    recommendation="Review and classify this license.",
                    confidence="LOW",
                    metadata={"license": raw_license, "normalised": normalised},
                )
            )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_requirements(req_file: Path) -> List[Tuple[str, Optional[str]]]:
    results: List[Tuple[str, Optional[str]]] = []
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


def _normalise_license(raw: str) -> str:
    """Normalise a raw license string to an SPDX-like identifier."""
    lower = raw.strip().lower()
    if lower in _LICENSE_ALIASES:
        return _LICENSE_ALIASES[lower]
    # Check if it already matches an SPDX ID (case-insensitive)
    for spdx in (*_DENIED_LICENSES, *_WARNING_LICENSES, *_ALLOWED_LICENSES):
        if lower == spdx.lower():
            return spdx
    return raw.strip()



