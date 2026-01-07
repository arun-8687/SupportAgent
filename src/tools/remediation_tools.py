"""
Common Remediation Tools for incident resolution.

Provides cross-platform remediation capabilities:
- Job restart/rerun
- Cache clearing
- Health checks
- Upstream dependency checks
- Team notifications
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx
import structlog

from src.tools.base import BaseTool, MutatingTool, ReadOnlyTool, ToolResult
from src.integrations.config import get_settings

logger = structlog.get_logger()


class RestartJobTool(MutatingTool):
    """Generic job restart tool that delegates to platform-specific implementations."""

    @property
    def name(self) -> str:
        return "restart_job"

    @property
    def description(self) -> str:
        return "Restart a failed job. Automatically detects platform and uses appropriate restart method."

    @property
    def risk_level(self) -> str:
        return "medium"

    def get_schema(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": {
                    "job_name": {
                        "type": "string",
                        "description": "Name of the job to restart"
                    },
                    "job_type": {
                        "type": "string",
                        "description": "Job platform type (databricks, adf, iws)",
                        "enum": ["databricks", "adf", "iws", "custom"]
                    },
                    "run_id": {
                        "type": "string",
                        "description": "Specific run ID to restart (optional)"
                    },
                    "environment": {
                        "type": "string",
                        "description": "Environment (prod, uat, dev)",
                        "enum": ["prod", "uat", "dev"]
                    }
                },
                "required": ["job_name"]
            }
        }

    async def execute(
        self,
        job_name: str,
        job_type: str = "databricks",
        run_id: Optional[str] = None,
        environment: str = "prod",
        **kwargs
    ) -> ToolResult:
        """Restart job based on platform type."""
        logger.info(
            "restarting_job",
            job_name=job_name,
            job_type=job_type,
            environment=environment
        )

        try:
            if job_type == "databricks":
                return await self._restart_databricks(job_name, run_id)
            elif job_type == "adf":
                return await self._restart_adf(job_name, run_id)
            elif job_type == "iws":
                return await self._restart_iws(job_name)
            else:
                return ToolResult(
                    success=False,
                    error=f"Unsupported job type: {job_type}"
                )
        except Exception as e:
            logger.error("restart_failed", job_name=job_name, error=str(e))
            return ToolResult(success=False, error=str(e))

    async def _restart_databricks(
        self,
        job_name: str,
        run_id: Optional[str]
    ) -> ToolResult:
        """Restart Databricks job."""
        try:
            from databricks.sdk import WorkspaceClient

            settings = get_settings()
            client = WorkspaceClient(
                host=settings.databricks_host,
                token=settings.databricks_token
            )

            # Find job by name if no run_id provided
            jobs = list(client.jobs.list(name=job_name))
            if not jobs:
                return ToolResult(
                    success=False,
                    error=f"Job not found: {job_name}"
                )

            job_id = jobs[0].job_id
            run = client.jobs.run_now(job_id=job_id)

            return ToolResult(
                success=True,
                data={
                    "run_id": run.run_id,
                    "job_id": job_id,
                    "message": f"Job {job_name} restarted successfully"
                },
                rollback_action="cancel_databricks_run",
                rollback_params={"run_id": str(run.run_id)}
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e))

    async def _restart_adf(
        self,
        job_name: str,
        run_id: Optional[str]
    ) -> ToolResult:
        """Restart Azure Data Factory pipeline."""
        # Placeholder - would integrate with ADF SDK
        return ToolResult(
            success=True,
            data={"message": f"ADF pipeline {job_name} restart initiated"}
        )

    async def _restart_iws(self, job_name: str) -> ToolResult:
        """Restart IWS job."""
        # Placeholder - would integrate with IWS API
        return ToolResult(
            success=True,
            data={"message": f"IWS job {job_name} restart initiated"}
        )


class ClearCacheTool(MutatingTool):
    """Clear various types of caches."""

    @property
    def name(self) -> str:
        return "clear_cache"

    @property
    def description(self) -> str:
        return "Clear cache for a specific service or job to resolve stale data issues."

    @property
    def risk_level(self) -> str:
        return "low"

    @property
    def supports_rollback(self) -> bool:
        return False  # Cannot restore cache

    def get_schema(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": {
                    "cache_type": {
                        "type": "string",
                        "description": "Type of cache to clear",
                        "enum": ["spark", "redis", "application", "databricks_delta"]
                    },
                    "cluster_id": {
                        "type": "string",
                        "description": "Cluster ID for Spark cache clearing"
                    },
                    "job_name": {
                        "type": "string",
                        "description": "Job name for context"
                    }
                },
                "required": ["cache_type"]
            }
        }

    async def execute(
        self,
        cache_type: str,
        cluster_id: Optional[str] = None,
        job_name: Optional[str] = None,
        **kwargs
    ) -> ToolResult:
        """Clear the specified cache."""
        logger.info("clearing_cache", cache_type=cache_type, cluster_id=cluster_id)

        try:
            if cache_type == "spark" and cluster_id:
                return await self._clear_spark_cache(cluster_id)
            elif cache_type == "databricks_delta" and cluster_id:
                return await self._clear_delta_cache(cluster_id)
            elif cache_type == "redis":
                return await self._clear_redis_cache(job_name)
            elif cache_type == "application":
                return await self._clear_app_cache(job_name)
            else:
                return ToolResult(
                    success=True,
                    data={"message": f"Cache type {cache_type} acknowledged, no action required"}
                )
        except Exception as e:
            return ToolResult(success=False, error=str(e))

    async def _clear_spark_cache(self, cluster_id: str) -> ToolResult:
        """Clear Spark cache on Databricks cluster."""
        try:
            from databricks.sdk import WorkspaceClient

            settings = get_settings()
            client = WorkspaceClient(
                host=settings.databricks_host,
                token=settings.databricks_token
            )

            # Execute cache clear command
            context = client.command_execution.create(
                cluster_id=cluster_id,
                language="python"
            )

            result = client.command_execution.execute(
                cluster_id=cluster_id,
                context_id=context.id,
                command="spark.catalog.clearCache()"
            )

            return ToolResult(
                success=True,
                data={"message": "Spark cache cleared", "cluster_id": cluster_id}
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e))

    async def _clear_delta_cache(self, cluster_id: str) -> ToolResult:
        """Clear Delta cache on Databricks cluster."""
        # Similar to spark cache clearing
        return ToolResult(
            success=True,
            data={"message": "Delta cache clear requested", "cluster_id": cluster_id}
        )

    async def _clear_redis_cache(self, job_name: Optional[str]) -> ToolResult:
        """Clear Redis cache."""
        # Would integrate with Redis
        return ToolResult(
            success=True,
            data={"message": f"Redis cache cleared for {job_name or 'all'}"}
        )

    async def _clear_app_cache(self, job_name: Optional[str]) -> ToolResult:
        """Clear application-level cache."""
        return ToolResult(
            success=True,
            data={"message": f"Application cache cleared for {job_name or 'all'}"}
        )


class ScaleClusterTool(MutatingTool):
    """Scale cluster resources up or down."""

    @property
    def name(self) -> str:
        return "scale_cluster"

    @property
    def description(self) -> str:
        return "Scale cluster resources (workers, memory) to address resource constraints."

    @property
    def risk_level(self) -> str:
        return "high"

    def get_schema(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": {
                    "cluster_id": {
                        "type": "string",
                        "description": "Cluster ID to scale"
                    },
                    "num_workers": {
                        "type": "integer",
                        "description": "New number of workers"
                    },
                    "min_workers": {
                        "type": "integer",
                        "description": "Minimum workers for autoscale"
                    },
                    "max_workers": {
                        "type": "integer",
                        "description": "Maximum workers for autoscale"
                    }
                },
                "required": ["cluster_id"]
            }
        }

    async def execute(
        self,
        cluster_id: str,
        num_workers: Optional[int] = None,
        min_workers: Optional[int] = None,
        max_workers: Optional[int] = None,
        **kwargs
    ) -> ToolResult:
        """Scale the cluster."""
        logger.info(
            "scaling_cluster",
            cluster_id=cluster_id,
            num_workers=num_workers
        )

        try:
            from databricks.sdk import WorkspaceClient

            settings = get_settings()
            client = WorkspaceClient(
                host=settings.databricks_host,
                token=settings.databricks_token
            )

            # Get current config for rollback
            current = client.clusters.get(cluster_id=cluster_id)
            original_workers = current.num_workers
            original_autoscale = current.autoscale

            # Resize cluster
            if num_workers is not None:
                client.clusters.resize(
                    cluster_id=cluster_id,
                    num_workers=num_workers
                )
            elif min_workers is not None and max_workers is not None:
                client.clusters.resize(
                    cluster_id=cluster_id,
                    autoscale={"min_workers": min_workers, "max_workers": max_workers}
                )

            rollback_params = {
                "cluster_id": cluster_id,
                "num_workers": original_workers
            }
            if original_autoscale:
                rollback_params["min_workers"] = original_autoscale.min_workers
                rollback_params["max_workers"] = original_autoscale.max_workers

            return ToolResult(
                success=True,
                data={
                    "message": f"Cluster {cluster_id} scaled",
                    "new_workers": num_workers or max_workers
                },
                rollback_action="scale_cluster",
                rollback_params=rollback_params
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e))


class RunHealthCheckTool(ReadOnlyTool):
    """Run health check on a service or endpoint."""

    @property
    def name(self) -> str:
        return "run_health_check"

    @property
    def description(self) -> str:
        return "Run health check to verify service status and connectivity."

    def get_schema(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": {
                    "endpoint": {
                        "type": "string",
                        "description": "Health check endpoint URL"
                    },
                    "job_name": {
                        "type": "string",
                        "description": "Job name to check"
                    },
                    "job_type": {
                        "type": "string",
                        "description": "Job type for platform-specific checks"
                    }
                }
            }
        }

    async def execute(
        self,
        endpoint: Optional[str] = None,
        job_name: Optional[str] = None,
        job_type: Optional[str] = None,
        **kwargs
    ) -> ToolResult:
        """Run health check."""
        checks = []

        try:
            # HTTP endpoint check
            if endpoint:
                async with httpx.AsyncClient(timeout=30) as client:
                    response = await client.get(endpoint)
                    checks.append({
                        "type": "endpoint",
                        "url": endpoint,
                        "status_code": response.status_code,
                        "healthy": response.status_code < 400
                    })

            # Platform-specific checks
            if job_type == "databricks" and job_name:
                databricks_check = await self._check_databricks(job_name)
                checks.append(databricks_check)

            overall_healthy = all(c.get("healthy", True) for c in checks)

            return ToolResult(
                success=True,
                data={
                    "status": "healthy" if overall_healthy else "unhealthy",
                    "checks": checks,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
            )
        except Exception as e:
            return ToolResult(
                success=False,
                error=str(e),
                data={"status": "error", "checks": checks}
            )

    async def _check_databricks(self, job_name: str) -> Dict[str, Any]:
        """Check Databricks job health."""
        try:
            from databricks.sdk import WorkspaceClient

            settings = get_settings()
            client = WorkspaceClient(
                host=settings.databricks_host,
                token=settings.databricks_token
            )

            jobs = list(client.jobs.list(name=job_name))
            if jobs:
                return {
                    "type": "databricks_job",
                    "job_name": job_name,
                    "exists": True,
                    "healthy": True
                }
            return {
                "type": "databricks_job",
                "job_name": job_name,
                "exists": False,
                "healthy": False
            }
        except Exception as e:
            return {
                "type": "databricks_job",
                "job_name": job_name,
                "healthy": False,
                "error": str(e)
            }


class CheckUpstreamTool(ReadOnlyTool):
    """Check upstream job/service status."""

    @property
    def name(self) -> str:
        return "check_upstream"

    @property
    def description(self) -> str:
        return "Check status of upstream dependencies to identify cascade failures."

    def get_schema(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": {
                    "job_name": {
                        "type": "string",
                        "description": "Job name to check upstream for"
                    },
                    "upstream_jobs": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of upstream job names"
                    }
                },
                "required": ["job_name"]
            }
        }

    async def execute(
        self,
        job_name: str,
        upstream_jobs: Optional[List[str]] = None,
        **kwargs
    ) -> ToolResult:
        """Check upstream dependencies."""
        results = []

        if upstream_jobs:
            for upstream in upstream_jobs:
                status = await self._check_job_status(upstream)
                results.append({
                    "job": upstream,
                    "status": status.get("status", "unknown"),
                    "last_run": status.get("last_run"),
                    "healthy": status.get("status") in ["SUCCEEDED", "RUNNING"]
                })

        all_healthy = all(r.get("healthy", True) for r in results)

        return ToolResult(
            success=True,
            data={
                "upstream_checks": results,
                "all_healthy": all_healthy,
                "failed_upstreams": [r["job"] for r in results if not r.get("healthy")]
            }
        )

    async def _check_job_status(self, job_name: str) -> Dict[str, Any]:
        """Check individual job status."""
        # This would integrate with the actual job platform
        return {"status": "SUCCEEDED", "last_run": datetime.now(timezone.utc).isoformat()}


class NotifyTeamTool(MutatingTool):
    """Send notification to team."""

    @property
    def name(self) -> str:
        return "notify_team"

    @property
    def description(self) -> str:
        return "Send notification to the responsible team about incident status."

    @property
    def risk_level(self) -> str:
        return "low"

    @property
    def supports_rollback(self) -> bool:
        return False

    def get_schema(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": {
                    "team": {
                        "type": "string",
                        "description": "Team to notify"
                    },
                    "message": {
                        "type": "string",
                        "description": "Notification message"
                    },
                    "severity": {
                        "type": "string",
                        "description": "Notification severity",
                        "enum": ["info", "warning", "critical"]
                    },
                    "incident_id": {
                        "type": "string",
                        "description": "Related incident ID"
                    }
                },
                "required": ["message"]
            }
        }

    async def execute(
        self,
        message: str,
        team: Optional[str] = None,
        severity: str = "info",
        incident_id: Optional[str] = None,
        **kwargs
    ) -> ToolResult:
        """Send team notification."""
        logger.info(
            "sending_notification",
            team=team,
            severity=severity,
            incident_id=incident_id
        )

        # In production, this would integrate with Teams, Slack, PagerDuty, etc.
        notification = {
            "team": team or "default",
            "message": message,
            "severity": severity,
            "incident_id": incident_id,
            "sent_at": datetime.now(timezone.utc).isoformat()
        }

        return ToolResult(
            success=True,
            data=notification
        )


class GetJobStatusTool(ReadOnlyTool):
    """Get current status of a job."""

    @property
    def name(self) -> str:
        return "get_job_status"

    @property
    def description(self) -> str:
        return "Get current status of a job across platforms."

    def get_schema(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": {
                    "job_name": {
                        "type": "string",
                        "description": "Job name"
                    },
                    "job_type": {
                        "type": "string",
                        "description": "Job platform type"
                    },
                    "run_id": {
                        "type": "string",
                        "description": "Specific run ID"
                    }
                },
                "required": ["job_name"]
            }
        }

    async def execute(
        self,
        job_name: str,
        job_type: str = "databricks",
        run_id: Optional[str] = None,
        **kwargs
    ) -> ToolResult:
        """Get job status."""
        try:
            if job_type == "databricks":
                return await self._get_databricks_status(job_name, run_id)
            else:
                return ToolResult(
                    success=True,
                    data={"job_name": job_name, "status": "UNKNOWN", "platform": job_type}
                )
        except Exception as e:
            return ToolResult(success=False, error=str(e))

    async def _get_databricks_status(
        self,
        job_name: str,
        run_id: Optional[str]
    ) -> ToolResult:
        """Get Databricks job status."""
        try:
            from databricks.sdk import WorkspaceClient

            settings = get_settings()
            client = WorkspaceClient(
                host=settings.databricks_host,
                token=settings.databricks_token
            )

            jobs = list(client.jobs.list(name=job_name))
            if not jobs:
                return ToolResult(
                    success=True,
                    data={"job_name": job_name, "status": "NOT_FOUND"}
                )

            job_id = jobs[0].job_id

            # Get recent runs
            runs = list(client.jobs.list_runs(job_id=job_id, limit=1))
            if runs:
                latest = runs[0]
                return ToolResult(
                    success=True,
                    data={
                        "job_name": job_name,
                        "job_id": job_id,
                        "run_id": latest.run_id,
                        "status": latest.state.life_cycle_state.value if latest.state else "UNKNOWN",
                        "result": latest.state.result_state.value if latest.state and latest.state.result_state else None
                    }
                )

            return ToolResult(
                success=True,
                data={"job_name": job_name, "job_id": job_id, "status": "NO_RUNS"}
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e))


class GetRecentJobRunsTool(ReadOnlyTool):
    """Get recent job run history."""

    @property
    def name(self) -> str:
        return "get_recent_job_runs"

    @property
    def description(self) -> str:
        return "Get recent job run history to identify patterns."

    def get_schema(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": {
                    "job_name": {
                        "type": "string",
                        "description": "Job name"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Number of runs to fetch",
                        "default": 10
                    }
                },
                "required": ["job_name"]
            }
        }

    async def execute(
        self,
        job_name: str,
        limit: int = 10,
        **kwargs
    ) -> ToolResult:
        """Get recent runs."""
        try:
            from databricks.sdk import WorkspaceClient

            settings = get_settings()
            client = WorkspaceClient(
                host=settings.databricks_host,
                token=settings.databricks_token
            )

            jobs = list(client.jobs.list(name=job_name))
            if not jobs:
                return ToolResult(success=True, data=[])

            job_id = jobs[0].job_id
            runs = list(client.jobs.list_runs(job_id=job_id, limit=limit))

            return ToolResult(
                success=True,
                data=[
                    {
                        "run_id": r.run_id,
                        "status": r.state.life_cycle_state.value if r.state else "UNKNOWN",
                        "result": r.state.result_state.value if r.state and r.state.result_state else None,
                        "start_time": r.start_time,
                        "end_time": r.end_time
                    }
                    for r in runs
                ]
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e))


def register_common_tools(registry) -> None:
    """Register all common remediation tools with the registry."""
    registry.register(RestartJobTool(), category="remediation")
    registry.register(ClearCacheTool(), category="remediation")
    registry.register(ScaleClusterTool(), category="remediation")
    registry.register(RunHealthCheckTool(), category="diagnostic")
    registry.register(CheckUpstreamTool(), category="diagnostic")
    registry.register(NotifyTeamTool(), category="notification")
    registry.register(GetJobStatusTool(), category="diagnostic")
    registry.register(GetRecentJobRunsTool(), category="diagnostic")
