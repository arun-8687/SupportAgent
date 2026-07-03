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
    # auto-approve low-risk actions.
    autonomous_mode: bool = False
    # Dry-run: skills log the commands they would run instead of executing.
    dry_run: bool = True
    approval_timeout_seconds: int = 900

    # --- Extension primitive config files ---
    skills_dir: Path = PACKAGE_ROOT / "skills" / "builtin"
    hooks_file: Path = PACKAGE_ROOT / "hooks" / "hooks.yaml"
    gate_policy_file: Path = PACKAGE_ROOT / "gate" / "policies.yaml"
    mcp_servers_file: Path = PACKAGE_ROOT / "mcp" / "servers.yaml"

    # --- Knowledge store ---
    knowledge_path: Path = Path("data/sre_agent_knowledge.jsonl")

    # --- Ticketing ---
    ticket_platform: str = "console"  # console | servicenow | pagerduty
    servicenow_instance: Optional[str] = None
    servicenow_user: Optional[str] = None
    servicenow_password: Optional[str] = None
    pagerduty_api_key: Optional[str] = None
    pagerduty_service_id: Optional[str] = None

    # --- Checkpointing ---
    database_url: Optional[str] = None  # Postgres checkpointer when set

    @property
    def llm_configured(self) -> bool:
        return bool(
            (self.azure_openai_endpoint and self.azure_openai_api_key)
            or self.openai_api_key
        )


@lru_cache
def get_settings() -> SREAgentSettings:
    return SREAgentSettings()
