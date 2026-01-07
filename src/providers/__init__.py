"""
Platform Providers Package.

This package contains the plugin architecture for supporting different platforms:
- SQL Server / Azure SQL
- Databricks
- Azure Data Factory
- Azure Functions
- Generic API endpoints
- Custom platforms

Usage:
    from src.providers import ProviderRegistry, get_provider

    # Get a provider by name
    provider = get_provider('sql_server')
    await provider.connect(config)
    result = await provider.diagnose(job_name, error_message)
"""
from .base import (
    BaseProvider,
    DiagnosticInfo,
    ProviderCapabilities,
    ProviderRegistry,
    RemediationResult,
    VerificationResult,
)

# Import providers to register them
from . import sql_server

# Convenience function
def get_provider(name: str, config: dict = None):
    """Get a provider instance by name."""
    return ProviderRegistry.get_provider(name, config)


def list_providers() -> list:
    """List all registered provider names."""
    return ProviderRegistry.list_providers()


__all__ = [
    "BaseProvider",
    "DiagnosticInfo",
    "ProviderCapabilities",
    "ProviderRegistry",
    "RemediationResult",
    "VerificationResult",
    "get_provider",
    "list_providers",
]
