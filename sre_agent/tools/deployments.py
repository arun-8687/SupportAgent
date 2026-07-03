"""
Source-control / deployment correlation tool.

Fetches recent deployments and commits for the affected service so the
source-code subagent can correlate the incident with what changed.
Live mode would call the GitHub / Azure DevOps APIs; mock mode returns a
representative deployment two hours before "now".
"""
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sre_agent.tools.observability import _require_mock_allowed

logger = logging.getLogger(__name__)


class DeploymentClient:
    """Recent-change lookup for a service's repositories and pipelines."""

    def __init__(self) -> None:
        self._github_token = os.environ.get("GITHUB_TOKEN")

    async def recent_deployments(
        self,
        service_name: str,
        lookback_hours: int = 6,
        repo: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return deployments in the lookback window, newest first."""
        if self._github_token and repo:
            try:
                import httpx

                async with httpx.AsyncClient(timeout=15) as client:
                    resp = await client.get(
                        f"https://api.github.com/repos/{repo}/deployments",
                        headers={"Authorization": f"Bearer {self._github_token}"},
                        params={"per_page": 10},
                    )
                    resp.raise_for_status()
                    cutoff = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
                    return [
                        {
                            "id": str(d["id"]),
                            "sha": d.get("sha", ""),
                            "environment": d.get("environment", ""),
                            "description": d.get("description") or "",
                            "created_at": d["created_at"],
                        }
                        for d in resp.json()
                        if datetime.fromisoformat(d["created_at"].replace("Z", "+00:00")) > cutoff
                    ]
            except Exception:
                logger.exception("GitHub deployments query failed")
                _require_mock_allowed("recent_deployments")

        _require_mock_allowed("recent_deployments")
        deployed_at = datetime.now(timezone.utc) - timedelta(hours=2)
        return [
            {
                "id": "deploy-4821",
                "sha": "9f2c1ab",
                "environment": "prod",
                "description": f"Deploy {service_name} v2.14.0 - increase batch size for order processing",
                "created_at": deployed_at.isoformat(),
                "author": "ci-bot",
            }
        ]

    async def recent_commits(
        self,
        service_name: str,
        lookback_hours: int = 6,
        repo: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return commits in the lookback window, newest first."""
        _require_mock_allowed("recent_commits")
        committed_at = datetime.now(timezone.utc) - timedelta(hours=2, minutes=20)
        return [
            {
                "sha": "9f2c1ab",
                "message": "perf: increase order batch size from 100 to 5000",
                "author": "dev@example.com",
                "committed_at": committed_at.isoformat(),
                "files": ["src/order_processor.py", "config/batch.yaml"],
            }
        ]
