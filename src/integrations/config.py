"""
Application configuration settings.

Loads configuration from environment variables with sensible defaults.
"""
import os
from functools import lru_cache
from typing import Optional

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment."""

    # Azure OpenAI
    azure_openai_endpoint: str = ""
    azure_openai_api_key: str = ""
    azure_openai_api_version: str = "2025-11-13"
    azure_openai_deployment: str = "gpt-5.1-codex"  # Code/log analysis optimized
    azure_openai_deployment_name: str = "gpt-5.1-codex"
    azure_openai_fallback_deployment: str = "gpt-5-mini"  # No registration required
    embedding_deployment: str = "text-embedding-3-large"  # Latest embedding model
    azure_openai_embedding_deployment: str = "text-embedding-3-large"

    # Azure AI Search
    azure_search_endpoint: str = ""
    azure_search_api_key: str = ""
    azure_search_index_prefix: str = ""  # Optional prefix for index names

    # Database
    database_url: str = "postgresql://localhost:5432/support_agent"
    database_pool_size: int = 10
    database_max_overflow: int = 20

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # API Security
    api_keys: str = ""  # Comma-separated list of valid API keys

    # Azure Service Bus
    servicebus_connection_string: str = ""
    servicebus_queue_name: str = "job-failures"
    servicebus_topic_name: str = "incident-updates"

    # Azure Application Insights
    appinsights_connection_string: str = ""
    appinsights_app_id: str = ""
    appinsights_api_key: str = ""

    # Azure Log Analytics
    log_analytics_workspace_id: str = ""
    log_analytics_client_id: str = ""
    log_analytics_client_secret: str = ""
    log_analytics_tenant_id: str = ""

    # Databricks
    databricks_host: str = ""
    databricks_token: str = ""

    # SQL Server
    sqlserver_app_connection_string: str = ""
    sqlserver_metadata_connection_string: str = ""

    # ITSM Integration
    itsm_base_url: str = ""
    itsm_username: str = ""
    itsm_password: str = ""
    itsm_client_id: str = ""
    itsm_client_secret: str = ""

    # LangSmith
    langchain_tracing_v2: bool = True
    langchain_endpoint: str = "https://api.smith.langchain.com"
    langchain_api_key: str = ""
    langchain_project: str = "support-agent"

    # Application
    environment: str = "development"
    log_level: str = "INFO"

    # AI Intelligence Settings
    dedup_similarity_threshold: float = 0.85
    dedup_time_window_minutes: int = 15
    event_storm_threshold: int = 10
    correlation_time_window_minutes: int = 30

    # Automation Settings
    auto_fix_enabled: bool = True
    auto_fix_confidence_threshold: float = 0.9
    max_retry_attempts: int = 3
    approval_timeout_minutes: int = 30

    # Severity Thresholds
    severity_p1_threshold: int = 70
    severity_p2_threshold: int = 50
    severity_p3_threshold: int = 30

    class Config:
        env_file = ".env"
        case_sensitive = False


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
