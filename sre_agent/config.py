"""
Configuration for the SRE Agent.

All settings load from environment variables (SRE_AGENT_ prefix for
agent-specific settings; AZURE_OPENAI_* reused from the wider project).
"""
from functools import lru_cache
from pathlib import Path
from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict

PACKAGE_ROOT = Path(__file__).resolve().parent


class SREAgentSettings(BaseSettings):
    """Runtime settings for the SRE Agent."""

    model_config = SettingsConfigDict(
        env_prefix="SRE_AGENT_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Environment ---
    # "production" enables strict behavior: no mock data, durable
    # checkpointer required, verified approver identity required.
    environment: str = "development"

    # --- Service Bus (event-driven trigger) ---
    servicebus_connection_string: Optional[str] = None
    servicebus_topic: str = "sre-incidents"
    servicebus_subscription: str = "sre-agent"
    # Topic used to publish agent outcomes / approval requests
    servicebus_outbound_topic: str = "sre-agent-events"

    # --- LLM (falls back to deterministic heuristics when unset) ---
    azure_openai_endpoint: Optional[str] = None
    azure_openai_api_key: Optional[str] = None
    azure_openai_deployment: str = "gpt-5.1-codex"
    azure_openai_api_version: str = "2025-11-13"
    openai_api_key: Optional[str] = None
    openai_model: str = "gpt-4o-mini"

    # --- Execution behavior ---
    # Reviewed mode (default): every mitigation needs approval unless the
    # permission gate explicitly allows it. Autonomous mode lets the gate
    # auto-approve low-risk actions (never in prod environments).
    autonomous_mode: bool = False
    # Dry-run: skills log the commands they would run instead of executing.
    dry_run: bool = True
    # local: run skill commands on this host; dispatch: publish execution
    # requests to the outbound topic for a separate privileged runner.
    execution_mode: str = "local"
    approval_timeout_seconds: int = 900
    # Require an Entra-verified approver identity (X-MS-CLIENT-PRINCIPAL).
    # Defaults to True in production, False otherwise; override explicitly.
    approval_require_verified_identity: Optional[bool] = None

    # --- Alert intake protection ---
    # Suppress a service+category pair after this many alerts in the window.
    storm_threshold: int = 5
    storm_window_seconds: int = 300

    # --- LLM throttling ---
    llm_max_concurrency: int = 4
    llm_retry_attempts: int = 3
    llm_retry_base_delay_seconds: float = 2.0

    # --- Extension primitive config files ---
    skills_dir: Path = PACKAGE_ROOT / "skills" / "builtin"
    custom_agents_dir: Path = PACKAGE_ROOT / "subagents" / "custom"
    hooks_file: Path = PACKAGE_ROOT / "hooks" / "hooks.yaml"
    gate_policy_file: Path = PACKAGE_ROOT / "gate" / "policies.yaml"
    mcp_servers_file: Path = PACKAGE_ROOT / "mcp" / "servers.yaml"
    # Incident response plan: operator instructions for how the agent
    # should handle incidents in this environment (markdown, optional).
    response_plan_file: Path = PACKAGE_ROOT / "response_plan.md"

    # --- Memory & knowledge ---
    # Base directory for all mutable agent state. On Azure Functions /
    # App Service this MUST point at durable shared storage (an Azure
    # Files mount, e.g. /mounts/sre-data) — instance-local disk is
    # ephemeral and per-instance, so knowledge written there is lost on
    # recycle and invisible to other instances.
    data_dir: Path = Path("data")
    knowledge_path: Optional[Path] = None      # default: data_dir/sre_agent_knowledge.jsonl
    memories_dir: Optional[Path] = None        # default: data_dir/memories
    knowledge_base_dir: Optional[Path] = None  # default: data_dir/knowledge_base

    # --- Ticketing ---
    ticket_platform: str = "console"  # console | servicenow | pagerduty
    servicenow_instance: Optional[str] = None
    servicenow_user: Optional[str] = None
    servicenow_password: Optional[str] = None
    pagerduty_api_key: Optional[str] = None
    pagerduty_service_id: Optional[str] = None

    # --- Checkpointing ---
    database_url: Optional[str] = None  # Postgres checkpointer when set
    checkpoint_retention_days: int = 14

    # Explicit override for mock/synthetic data fallbacks. Defaults to
    # allowed outside production, forbidden in production.
    allow_mock_data: Optional[bool] = None

    def model_post_init(self, __context) -> None:
        if self.knowledge_path is None:
            self.knowledge_path = self.data_dir / "sre_agent_knowledge.jsonl"
        if self.memories_dir is None:
            self.memories_dir = self.data_dir / "memories"
        if self.knowledge_base_dir is None:
            self.knowledge_base_dir = self.data_dir / "knowledge_base"

    @property
    def is_production(self) -> bool:
        return self.environment.strip().lower() in ("production", "prod")

    @property
    def mock_data_allowed(self) -> bool:
        """Synthetic telemetry/heuristic fallbacks: never silently in prod."""
        if self.allow_mock_data is not None:
            return self.allow_mock_data
        return not self.is_production

    @property
    def verified_identity_required(self) -> bool:
        if self.approval_require_verified_identity is not None:
            return self.approval_require_verified_identity
        return self.is_production

    @property
    def llm_configured(self) -> bool:
        return bool(
            (self.azure_openai_endpoint and self.azure_openai_api_key)
            or self.openai_api_key
        )


@lru_cache
def get_settings() -> SREAgentSettings:
    return SREAgentSettings()
