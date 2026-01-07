"""
Base Provider Interface for Platform Plugins.

This module defines the abstract interface that all platform providers must implement.
Providers encapsulate platform-specific logic for:
- Connecting to the platform
- Diagnosing issues
- Executing remediation actions
- Verifying fixes
"""
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Type

from pydantic import BaseModel


class ProviderCapabilities(BaseModel):
    """Describes what a provider can do."""
    can_restart_job: bool = False
    can_kill_process: bool = False
    can_scale_resources: bool = False
    can_clear_cache: bool = False
    can_retry_operation: bool = False
    can_get_logs: bool = False
    can_get_metrics: bool = False
    can_execute_query: bool = False
    can_modify_config: bool = False
    custom_capabilities: List[str] = []


class DiagnosticInfo(BaseModel):
    """Diagnostic information gathered by provider."""
    platform: str
    status: str
    details: Dict[str, Any] = {}
    logs: Optional[str] = None
    metrics: Optional[Dict[str, Any]] = None
    recommendations: List[str] = []
    error: Optional[str] = None


class RemediationResult(BaseModel):
    """Result of a remediation action."""
    success: bool
    action: str
    details: Dict[str, Any] = {}
    error: Optional[str] = None
    rollback_info: Optional[Dict[str, Any]] = None


class VerificationResult(BaseModel):
    """Result of verification check."""
    success: bool
    checks_passed: List[str] = []
    checks_failed: List[str] = []
    evidence: Dict[str, Any] = {}
    confidence: float = 0.0


class BaseProvider(ABC):
    """
    Abstract base class for platform providers.

    Each platform (SQL Server, Databricks, Azure Functions, etc.) implements
    this interface to provide platform-specific functionality.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier for this provider (e.g., 'sql_server', 'databricks')."""
        pass

    @property
    @abstractmethod
    def display_name(self) -> str:
        """Human-readable name for this provider."""
        pass

    @property
    @abstractmethod
    def capabilities(self) -> ProviderCapabilities:
        """What this provider can do."""
        pass

    @abstractmethod
    async def connect(self, config: Dict[str, Any]) -> bool:
        """
        Establish connection to the platform.

        Args:
            config: Platform-specific configuration

        Returns:
            True if connection successful
        """
        pass

    @abstractmethod
    async def disconnect(self) -> None:
        """Close connection to the platform."""
        pass

    @abstractmethod
    async def health_check(self) -> bool:
        """Check if the platform connection is healthy."""
        pass

    @abstractmethod
    async def diagnose(
        self,
        job_name: str,
        error_message: str,
        error_code: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> DiagnosticInfo:
        """
        Gather diagnostic information about a failure.

        Args:
            job_name: Name of the failed job/procedure
            error_message: The error message
            error_code: Optional error code
            context: Additional context

        Returns:
            Diagnostic information
        """
        pass

    @abstractmethod
    async def execute_remediation(
        self,
        action: str,
        params: Dict[str, Any]
    ) -> RemediationResult:
        """
        Execute a remediation action.

        Args:
            action: The action to perform (e.g., 'retry', 'kill_session')
            params: Action-specific parameters

        Returns:
            Result of the remediation
        """
        pass

    @abstractmethod
    async def verify_fix(
        self,
        job_name: str,
        expected_state: str,
        context: Optional[Dict[str, Any]] = None
    ) -> VerificationResult:
        """
        Verify that a fix was successful.

        Args:
            job_name: Name of the job/procedure
            expected_state: Expected state after fix
            context: Additional context

        Returns:
            Verification result
        """
        pass

    @abstractmethod
    def get_error_patterns(self) -> List[Dict[str, Any]]:
        """
        Get error patterns this provider can recognize.

        Returns:
            List of error pattern definitions with:
            - pattern: regex or string pattern
            - category: error category
            - severity: suggested severity
            - remediation_hint: suggested remediation
        """
        pass

    @abstractmethod
    def get_available_actions(self) -> List[Dict[str, Any]]:
        """
        Get available remediation actions.

        Returns:
            List of action definitions with:
            - name: action identifier
            - display_name: human-readable name
            - description: what it does
            - params: required parameters
            - risk_level: low/medium/high
        """
        pass


class ProviderRegistry:
    """
    Registry for platform providers.

    Manages registration and lookup of providers by platform type.
    """

    _providers: Dict[str, Type[BaseProvider]] = {}
    _instances: Dict[str, BaseProvider] = {}

    @classmethod
    def register(cls, provider_class: Type[BaseProvider]) -> Type[BaseProvider]:
        """
        Register a provider class.

        Can be used as a decorator:
            @ProviderRegistry.register
            class MyProvider(BaseProvider):
                ...
        """
        # Create temporary instance to get name
        # This is a bit hacky but avoids requiring class attributes
        instance = object.__new__(provider_class)
        if hasattr(provider_class, 'name') and isinstance(provider_class.name, property):
            # Get name from a temporary minimal init
            try:
                provider_class.__init__(instance)
                name = instance.name
            except:
                # Fallback to class name
                name = provider_class.__name__.lower().replace('provider', '')
        else:
            name = provider_class.__name__.lower().replace('provider', '')

        cls._providers[name] = provider_class
        return provider_class

    @classmethod
    def register_with_name(cls, name: str):
        """
        Register a provider with explicit name.

        Usage:
            @ProviderRegistry.register_with_name('sql_server')
            class SQLServerProvider(BaseProvider):
                ...
        """
        def decorator(provider_class: Type[BaseProvider]) -> Type[BaseProvider]:
            cls._providers[name] = provider_class
            return provider_class
        return decorator

    @classmethod
    def get_provider_class(cls, name: str) -> Optional[Type[BaseProvider]]:
        """Get a provider class by name."""
        return cls._providers.get(name)

    @classmethod
    def get_provider(cls, name: str, config: Optional[Dict[str, Any]] = None) -> Optional[BaseProvider]:
        """
        Get or create a provider instance.

        Args:
            name: Provider name
            config: Optional configuration for new instances

        Returns:
            Provider instance or None if not found
        """
        if name in cls._instances:
            return cls._instances[name]

        provider_class = cls._providers.get(name)
        if provider_class is None:
            return None

        instance = provider_class()
        cls._instances[name] = instance
        return instance

    @classmethod
    def list_providers(cls) -> List[str]:
        """List all registered provider names."""
        return list(cls._providers.keys())

    @classmethod
    def get_all_error_patterns(cls) -> Dict[str, List[Dict[str, Any]]]:
        """Get error patterns from all registered providers."""
        patterns = {}
        for name, provider_class in cls._providers.items():
            try:
                instance = cls.get_provider(name)
                if instance:
                    patterns[name] = instance.get_error_patterns()
            except Exception:
                continue
        return patterns

    @classmethod
    def clear(cls) -> None:
        """Clear all registered providers (mainly for testing)."""
        cls._providers.clear()
        cls._instances.clear()
