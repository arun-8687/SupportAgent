"""Scan configuration with YAML file + defaults support."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional

import yaml
from pydantic import BaseModel, ConfigDict, Field

from codesentry.models import ScannerType, Severity

# Default directory/file patterns to exclude from scanning.
_DEFAULT_EXCLUDES: List[str] = [
    "node_modules",
    ".venv",
    "venv",
    ".git",
    "__pycache__",
    "vendor",
    "*.min.js",
    ".terraform",
    "dist",
    "build",
    ".tox",
    ".mypy_cache",
]


def _default_scanner_flags() -> Dict[str, bool]:
    """Return a dict with every scanner type enabled by default."""
    return {st.value: True for st in ScannerType}


class ScanConfig(BaseModel):
    """Top-level configuration for a CodeSentry scan."""

    model_config = ConfigDict(use_enum_values=True)

    scanners: Dict[str, bool] = Field(default_factory=_default_scanner_flags)
    severity_threshold: Severity = Severity.MEDIUM
    exclude_paths: List[str] = Field(default_factory=lambda: list(_DEFAULT_EXCLUDES))
    output_format: str = Field(
        default="json",
        description="Output format: json, sarif, markdown, html",
    )
    output_file: Optional[str] = None


def load_config(
    config_path: Optional[str] = None,
    project_path: str = ".",
) -> ScanConfig:
    """Load scan configuration, merging YAML overrides onto defaults.

    Resolution order:
    1. Built-in defaults (all scanners enabled, MEDIUM threshold, etc.)
    2. ``codesentry.yaml`` found in *project_path* (or explicit *config_path*)
    """
    cfg = ScanConfig()

    # Determine which YAML file to read.
    yaml_path: Optional[Path] = None
    if config_path is not None:
        candidate = Path(config_path)
        if candidate.is_file():
            yaml_path = candidate
    else:
        for name in ("codesentry.yaml", "codesentry.yml"):
            candidate = Path(project_path) / name
            if candidate.is_file():
                yaml_path = candidate
                break

    if yaml_path is None:
        return cfg

    try:
        raw = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    except Exception:
        # Gracefully fall back to defaults on any parse error.
        return cfg

    if not isinstance(raw, dict):
        return cfg

    # Merge scanner enable/disable flags.
    if "scanners" in raw and isinstance(raw["scanners"], dict):
        for key, value in raw["scanners"].items():
            key_upper = key.upper()
            if key_upper in cfg.scanners:
                cfg.scanners[key_upper] = bool(value)

    # Severity threshold.
    if "severity_threshold" in raw:
        try:
            cfg.severity_threshold = Severity(raw["severity_threshold"].upper())
        except (ValueError, AttributeError):
            pass

    # Exclude paths (replace, not merge).
    if "exclude_paths" in raw and isinstance(raw["exclude_paths"], list):
        cfg.exclude_paths = [str(p) for p in raw["exclude_paths"]]

    # Output settings.
    if "output_format" in raw:
        cfg.output_format = str(raw["output_format"]).lower()
    if "output_file" in raw:
        cfg.output_file = str(raw["output_file"])

    return cfg
