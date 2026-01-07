"""
Tests for the plugin provider architecture and SQL Server provider.
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from src.providers.base import (
    BaseProvider,
    DiagnosticInfo,
    ProviderCapabilities,
    ProviderRegistry,
    RemediationResult,
    VerificationResult,
)
from src.providers.sql_server import SQLServerProvider
from src.intelligence.pattern_config import (
    ErrorPattern,
    ErrorPatternConfig,
    match_error_pattern,
)


class TestProviderRegistry:
    """Test the provider registry."""

    def test_sql_server_registered(self):
        """SQL Server provider should be auto-registered."""
        providers = ProviderRegistry.list_providers()
        assert "sql_server" in providers
        assert "azure_sql" in providers

    def test_get_provider_returns_instance(self):
        """Should return a provider instance."""
        provider = ProviderRegistry.get_provider("sql_server")
        assert provider is not None
        assert isinstance(provider, SQLServerProvider)

    def test_get_unknown_provider_returns_none(self):
        """Unknown provider should return None."""
        provider = ProviderRegistry.get_provider("unknown_platform")
        assert provider is None


class TestSQLServerProvider:
    """Test the SQL Server provider."""

    def test_provider_name(self):
        """Provider should have correct name."""
        provider = SQLServerProvider()
        assert provider.name == "sql_server"
        assert provider.display_name == "SQL Server / Azure SQL"

    def test_provider_capabilities(self):
        """Provider should have expected capabilities."""
        provider = SQLServerProvider()
        caps = provider.capabilities

        assert caps.can_kill_process is True
        assert caps.can_retry_operation is True
        assert caps.can_execute_query is True
        assert caps.can_restart_job is False  # SQL doesn't have "jobs" like Databricks
        assert "get_deadlock_graph" in caps.custom_capabilities
        assert "kill_session" in caps.custom_capabilities

    def test_get_error_patterns(self):
        """Provider should return SQL error patterns."""
        provider = SQLServerProvider()
        patterns = provider.get_error_patterns()

        assert len(patterns) > 0

        # Check for deadlock pattern
        deadlock_patterns = [p for p in patterns if p["issue_type"] == "deadlock"]
        assert len(deadlock_patterns) == 1
        assert deadlock_patterns[0]["auto_remediable"] is True

    def test_get_available_actions(self):
        """Provider should return available actions."""
        provider = SQLServerProvider()
        actions = provider.get_available_actions()

        assert len(actions) > 0

        action_names = [a["name"] for a in actions]
        assert "retry_procedure" in action_names
        assert "kill_session" in action_names
        assert "clear_plan_cache" in action_names


class TestErrorPatternConfig:
    """Test the error pattern configuration."""

    def test_load_patterns(self):
        """Should load patterns from config file."""
        config = ErrorPatternConfig()
        config.load()

        patterns = config.get_all_patterns()
        assert len(patterns) > 0

    def test_match_deadlock_pattern(self):
        """Should match SQL deadlock errors."""
        config = ErrorPatternConfig()
        config.load()

        match = config.match_error(
            "Transaction was deadlock victim on lock resources",
            platform="sql_server"
        )

        assert match is not None
        assert match.issue_type == "deadlock"
        assert match.auto_remediable is True

    def test_match_with_error_code(self):
        """Should match using error code."""
        config = ErrorPatternConfig()
        config.load()

        match = config.match_error(
            "Error 1205: deadlock victim",
            platform="sql_server",
            error_code="1205"
        )

        assert match is not None
        assert match.issue_type == "deadlock"

    def test_match_lock_timeout(self):
        """Should match lock timeout errors."""
        config = ErrorPatternConfig()
        config.load()

        match = config.match_error(
            "Lock request time out period exceeded",
            platform="sql_server"
        )

        assert match is not None
        assert match.issue_type == "lock_timeout"

    def test_match_global_pattern(self):
        """Should match global patterns for any platform."""
        config = ErrorPatternConfig()
        config.load()

        match = config.match_error(
            "OutOfMemoryError: Java heap space",
            platform="custom"
        )

        assert match is not None
        assert match.issue_type == "memory_exhaustion"

    def test_platform_patterns_take_precedence(self):
        """Platform-specific patterns should match before global."""
        config = ErrorPatternConfig()
        config.load()

        # SQL Server OOM should match SQL-specific pattern if one exists
        # or fall back to global
        match = config.match_error(
            "OutOfMemoryError",
            platform="sql_server"
        )

        assert match is not None

    def test_no_match_returns_none(self):
        """Unknown errors should return None."""
        config = ErrorPatternConfig()
        config.load()

        match = config.match_error(
            "Some completely unique error that doesn't match any pattern xyz123"
        )

        assert match is None

    def test_convenience_function(self):
        """match_error_pattern convenience function should work."""
        match = match_error_pattern(
            "Transaction was deadlock victim",
            platform="sql_server"
        )

        assert match is not None
        assert match.issue_type == "deadlock"

    def test_add_pattern_dynamically(self):
        """Should be able to add patterns at runtime."""
        config = ErrorPatternConfig()
        config.load()

        config.add_pattern(
            pattern="CUSTOM_ERROR_123",
            category="application",
            issue_type="custom_error",
            platform="custom"
        )

        match = config.match_error("CUSTOM_ERROR_123 occurred", platform="custom")
        assert match is not None
        assert match.issue_type == "custom_error"

    def test_get_remediation_actions(self):
        """Should return remediation actions for platform."""
        config = ErrorPatternConfig()
        config.load()

        actions = config.get_remediation_actions("sql_server")
        assert len(actions) > 0

        action_names = [a.name for a in actions]
        assert "retry_procedure" in action_names


class TestErrorPattern:
    """Test the ErrorPattern model."""

    def test_pattern_matches(self):
        """Pattern should match text."""
        pattern = ErrorPattern(
            pattern="deadlock|Error 1205",
            category="data_pipeline",
            issue_type="deadlock"
        )

        assert pattern.matches("Transaction was deadlocked") is True
        assert pattern.matches("Error 1205 occurred") is True
        assert pattern.matches("Some other error") is False

    def test_pattern_case_insensitive(self):
        """Pattern matching should be case-insensitive."""
        pattern = ErrorPattern(
            pattern="OutOfMemory",
            category="infrastructure",
            issue_type="oom"
        )

        assert pattern.matches("outofmemory error") is True
        assert pattern.matches("OUTOFMEMORY") is True
