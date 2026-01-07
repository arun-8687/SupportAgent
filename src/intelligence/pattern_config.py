"""
Error Pattern Configuration Loader.

Loads error patterns from configuration files and provides
matching functionality for error classification.
"""
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml
from pydantic import BaseModel


class ErrorPattern(BaseModel):
    """A single error pattern definition."""
    pattern: str
    category: str
    issue_type: str
    severity: str = "P3"
    remediation_hint: Optional[str] = None
    auto_remediable: bool = False
    details: Dict[str, Any] = {}

    # Compiled regex (excluded from serialization)
    _compiled: Optional[re.Pattern] = None

    class Config:
        underscore_attrs_are_private = True

    def matches(self, text: str) -> bool:
        """Check if this pattern matches the given text."""
        if self._compiled is None:
            self._compiled = re.compile(self.pattern, re.IGNORECASE)
        return bool(self._compiled.search(text))


class RemediationAction(BaseModel):
    """Definition of a remediation action."""
    name: str
    display_name: str
    description: str
    risk_level: str = "low"
    supports_rollback: bool = False
    params: List[Dict[str, Any]] = []


class ErrorPatternConfig:
    """
    Manages error pattern configuration.

    Loads patterns from YAML configuration and provides matching functionality.
    """

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the pattern configuration.

        Args:
            config_path: Path to the configuration file. If None, uses default.
        """
        self._global_patterns: List[ErrorPattern] = []
        self._platform_patterns: Dict[str, List[ErrorPattern]] = {}
        self._remediation_actions: Dict[str, List[RemediationAction]] = {}
        self._loaded = False

        if config_path is None:
            # Default to config/error_patterns.yaml relative to project root
            project_root = Path(__file__).parent.parent.parent
            config_path = project_root / "config" / "error_patterns.yaml"

        self._config_path = Path(config_path)

    def load(self) -> None:
        """Load configuration from file."""
        if not self._config_path.exists():
            # Create empty config if file doesn't exist
            self._loaded = True
            return

        with open(self._config_path, 'r') as f:
            config = yaml.safe_load(f)

        if config is None:
            self._loaded = True
            return

        # Load global patterns
        for pattern_def in config.get('global', []):
            self._global_patterns.append(ErrorPattern(**pattern_def))

        # Load platform-specific patterns
        reserved_keys = {'global', 'version', 'remediation_actions'}
        for platform, patterns in config.items():
            if platform in reserved_keys:
                continue
            if isinstance(patterns, list):
                self._platform_patterns[platform] = [
                    ErrorPattern(**p) for p in patterns
                ]

        # Load remediation actions
        for platform, actions in config.get('remediation_actions', {}).items():
            self._remediation_actions[platform] = [
                RemediationAction(**a) for a in actions
            ]

        self._loaded = True

    def ensure_loaded(self) -> None:
        """Ensure configuration is loaded."""
        if not self._loaded:
            self.load()

    def match_error(
        self,
        error_message: str,
        platform: Optional[str] = None,
        error_code: Optional[str] = None
    ) -> Optional[ErrorPattern]:
        """
        Find the first matching error pattern.

        Args:
            error_message: The error message to match
            platform: Optional platform to check platform-specific patterns first
            error_code: Optional error code to include in matching

        Returns:
            Matching ErrorPattern or None
        """
        self.ensure_loaded()

        # Combine error message and code for matching
        text_to_match = error_message
        if error_code:
            text_to_match = f"{error_code} {error_message}"

        # Check platform-specific patterns first
        if platform and platform in self._platform_patterns:
            for pattern in self._platform_patterns[platform]:
                if pattern.matches(text_to_match):
                    return pattern

        # Check global patterns
        for pattern in self._global_patterns:
            if pattern.matches(text_to_match):
                return pattern

        return None

    def get_all_patterns(self, platform: Optional[str] = None) -> List[ErrorPattern]:
        """
        Get all patterns, optionally filtered by platform.

        Args:
            platform: Optional platform filter

        Returns:
            List of error patterns
        """
        self.ensure_loaded()

        patterns = list(self._global_patterns)

        if platform and platform in self._platform_patterns:
            patterns = self._platform_patterns[platform] + patterns
        elif platform is None:
            for platform_patterns in self._platform_patterns.values():
                patterns.extend(platform_patterns)

        return patterns

    def get_remediation_actions(self, platform: str) -> List[RemediationAction]:
        """
        Get available remediation actions for a platform.

        Args:
            platform: Platform name

        Returns:
            List of remediation actions
        """
        self.ensure_loaded()
        return self._remediation_actions.get(platform, [])

    def add_pattern(
        self,
        pattern: str,
        category: str,
        issue_type: str,
        platform: Optional[str] = None,
        **kwargs
    ) -> ErrorPattern:
        """
        Add a new pattern dynamically.

        Args:
            pattern: Regex pattern string
            category: Error category
            issue_type: Issue type identifier
            platform: Optional platform (None for global)
            **kwargs: Additional pattern attributes

        Returns:
            The created ErrorPattern
        """
        self.ensure_loaded()

        error_pattern = ErrorPattern(
            pattern=pattern,
            category=category,
            issue_type=issue_type,
            **kwargs
        )

        if platform:
            if platform not in self._platform_patterns:
                self._platform_patterns[platform] = []
            self._platform_patterns[platform].append(error_pattern)
        else:
            self._global_patterns.append(error_pattern)

        return error_pattern

    def list_platforms(self) -> List[str]:
        """Get list of platforms with specific patterns."""
        self.ensure_loaded()
        return list(self._platform_patterns.keys())


# Global instance
_config: Optional[ErrorPatternConfig] = None


def get_error_pattern_config() -> ErrorPatternConfig:
    """Get the global error pattern configuration."""
    global _config
    if _config is None:
        _config = ErrorPatternConfig()
    return _config


def match_error_pattern(
    error_message: str,
    platform: Optional[str] = None,
    error_code: Optional[str] = None
) -> Optional[ErrorPattern]:
    """
    Convenience function to match an error against patterns.

    Args:
        error_message: The error message
        platform: Optional platform
        error_code: Optional error code

    Returns:
        Matching ErrorPattern or None
    """
    return get_error_pattern_config().match_error(
        error_message, platform, error_code
    )
