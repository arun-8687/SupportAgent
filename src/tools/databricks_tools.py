"""
Databricks Tools with rollback support.

Provides tools for interacting with Databricks:
- Get job/run details
- Get logs
- Restart jobs
- Check cluster status
"""
from datetime import datetime
from typing import Any, Dict, List, Optional

from src.tools.base import BaseTool, MutatingTool, ReadOnlyTool, ToolResult


class GetJobRunDetailsTool(ReadOnlyTool):
    """Get detailed information about a Databricks job run."""

    @property
    def name(self) -> str:
        return "get_job_run_details"

    @property
    def description(self) -> str:
        return "Get detailed information about a Databricks job run including status, duration, and error messages."

    def get_schema(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": {
                    "run_id": {
                        "type": "string",
                        "description": "The Databricks run ID"
                    }
                },
                "required": ["run_id"]
            }
        }

    async def execute(self, run_id: str) -> ToolResult:
        """Get job run details from Databricks API."""
        try:
            from databricks.sdk import WorkspaceClient
            from src.integrations.config import get_settings

            settings = get_settings()
            client = WorkspaceClient(
                host=settings.databricks_host,
                token=settings.databricks_token
            )

            run = client.jobs.get_run(run_id=int(run_id))

            return ToolResult(
                success=True,
                data={
                    "run_id": run.run_id,
                    "job_id": run.job_id,
                    "state": run.state.life_cycle_state.value if run.state else None,
                    "result_state": run.state.result_state.value if run.state and run.state.result_state else None,
                    "state_message": run.state.state_message if run.state else None,
                    "start_time": run.start_time,
                    "end_time": run.end_time,
                    "setup_duration": run.setup_duration,
                    "execution_duration": run.execution_duration,
                    "cleanup_duration": run.cleanup_duration,
                    "cluster_instance": run.cluster_instance.cluster_id if run.cluster_instance else None,
                    "error_message": run.state.state_message if run.state else None
                }
            )

        except Exception as e:
            return ToolResult(
                success=False,
                error=str(e)
            )


class GetJobRunLogsTool(ReadOnlyTool):
    """Fetch driver and executor logs for a job run."""

    @property
    def name(self) -> str:
        return "get_job_run_logs"

    @property
    def description(self) -> str:
        return "Fetch driver logs and error output for a Databricks job run."

    def get_schema(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": {
                    "run_id": {
                        "type": "string",
                        "description": "The Databricks run ID"
                    },
                    "cluster_id": {
                        "type": "string",
                        "description": "The cluster ID (optional)"
                    }
                },
                "required": ["run_id"]
            }
        }

    async def execute(
        self,
        run_id: str,
        cluster_id: Optional[str] = None
    ) -> ToolResult:
        """Get logs from Databricks."""
        try:
            from databricks.sdk import WorkspaceClient
            from src.integrations.config import get_settings

            settings = get_settings()
            client = WorkspaceClient(
                host=settings.databricks_host,
                token=settings.databricks_token
            )

            output = client.jobs.get_run_output(run_id=int(run_id))

            logs = {
                "error": output.error if output.error else None,
                "error_trace": output.error_trace if output.error_trace else None,
            }

            # Try to get notebook output if available
            if output.notebook_output:
                logs["notebook_result"] = output.notebook_output.result

            return ToolResult(
                success=True,
                data=logs
            )

        except Exception as e:
            return ToolResult(
                success=False,
                error=str(e)
            )


class GetClusterStatusTool(ReadOnlyTool):
    """Get current cluster state and resources."""

    @property
    def name(self) -> str:
        return "get_cluster_status"

    @property
    def description(self) -> str:
        return "Get current state, resources, and recent events for a Databricks cluster."

    def get_schema(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": {
                    "cluster_id": {
                        "type": "string",
                        "description": "The Databricks cluster ID"
                    }
                },
                "required": ["cluster_id"]
            }
        }

    async def execute(self, cluster_id: str) -> ToolResult:
        """Get cluster status from Databricks."""
        try:
            from databricks.sdk import WorkspaceClient
            from src.integrations.config import get_settings

            settings = get_settings()
            client = WorkspaceClient(
                host=settings.databricks_host,
                token=settings.databricks_token
            )

            cluster = client.clusters.get(cluster_id=cluster_id)

            return ToolResult(
                success=True,
                data={
                    "cluster_id": cluster.cluster_id,
                    "cluster_name": cluster.cluster_name,
                    "state": cluster.state.value if cluster.state else None,
                    "state_message": cluster.state_message,
                    "num_workers": cluster.num_workers,
                    "autoscale": {
                        "min_workers": cluster.autoscale.min_workers,
                        "max_workers": cluster.autoscale.max_workers
                    } if cluster.autoscale else None,
                    "driver_node_type": cluster.driver_node_type_id,
                    "node_type": cluster.node_type_id,
                    "spark_version": cluster.spark_version,
                    "start_time": cluster.start_time,
                    "terminated_time": cluster.terminated_time,
                    "termination_reason": cluster.termination_reason.code.value if cluster.termination_reason else None
                }
            )

        except Exception as e:
            return ToolResult(
                success=False,
                error=str(e)
            )


class RestartDatabricksJobTool(MutatingTool):
    """Restart a failed Databricks job with rollback support."""

    @property
    def name(self) -> str:
        return "restart_databricks_job"

    @property
    def description(self) -> str:
        return "Restart a Databricks job, creating a new run. Supports rollback via cancellation."

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
                    "job_id": {
                        "type": "string",
                        "description": "The Databricks job ID to restart"
                    },
                    "notebook_params": {
                        "type": "object",
                        "description": "Optional notebook parameters to override"
                    }
                },
                "required": ["job_id"]
            }
        }

    async def execute(
        self,
        job_id: str,
        notebook_params: Optional[Dict[str, str]] = None
    ) -> ToolResult:
        """Start a new run of the job."""
        try:
            from databricks.sdk import WorkspaceClient
            from src.integrations.config import get_settings

            settings = get_settings()
            client = WorkspaceClient(
                host=settings.databricks_host,
                token=settings.databricks_token
            )

            # Start new run
            run = client.jobs.run_now(
                job_id=int(job_id),
                notebook_params=notebook_params
            )

            return ToolResult(
                success=True,
                data={
                    "run_id": run.run_id,
                    "number_in_job": run.number_in_job
                },
                rollback_action="cancel_databricks_run",
                rollback_params={"run_id": str(run.run_id)}
            )

        except Exception as e:
            return ToolResult(
                success=False,
                error=str(e)
            )

    async def rollback(self, run_id: str) -> ToolResult:
        """Cancel the restarted job."""
        try:
            from databricks.sdk import WorkspaceClient
            from src.integrations.config import get_settings

            settings = get_settings()
            client = WorkspaceClient(
                host=settings.databricks_host,
                token=settings.databricks_token
            )

            client.jobs.cancel_run(run_id=int(run_id))

            return ToolResult(
                success=True,
                data={"cancelled_run_id": run_id}
            )

        except Exception as e:
            return ToolResult(
                success=False,
                error=str(e)
            )


class CancelDatabricksRunTool(MutatingTool):
    """Cancel a running Databricks job."""

    @property
    def name(self) -> str:
        return "cancel_databricks_run"

    @property
    def description(self) -> str:
        return "Cancel a running Databricks job run."

    @property
    def supports_rollback(self) -> bool:
        return False  # Cannot un-cancel

    def get_schema(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": {
                    "run_id": {
                        "type": "string",
                        "description": "The run ID to cancel"
                    }
                },
                "required": ["run_id"]
            }
        }

    async def execute(self, run_id: str) -> ToolResult:
        """Cancel the run."""
        try:
            from databricks.sdk import WorkspaceClient
            from src.integrations.config import get_settings

            settings = get_settings()
            client = WorkspaceClient(
                host=settings.databricks_host,
                token=settings.databricks_token
            )

            client.jobs.cancel_run(run_id=int(run_id))

            return ToolResult(
                success=True,
                data={"cancelled_run_id": run_id}
            )

        except Exception as e:
            return ToolResult(
                success=False,
                error=str(e)
            )


class GetJobDetailsTool(ReadOnlyTool):
    """Get job configuration details."""

    @property
    def name(self) -> str:
        return "get_job_details"

    @property
    def description(self) -> str:
        return "Get configuration details for a Databricks job including default parameters."

    def get_schema(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": {
                    "job_id": {
                        "type": "string",
                        "description": "The Databricks job ID"
                    }
                },
                "required": ["job_id"]
            }
        }

    async def execute(self, job_id: str) -> ToolResult:
        """Get job configuration."""
        try:
            from databricks.sdk import WorkspaceClient
            from src.integrations.config import get_settings

            settings = get_settings()
            client = WorkspaceClient(
                host=settings.databricks_host,
                token=settings.databricks_token
            )

            job = client.jobs.get(job_id=int(job_id))

            return ToolResult(
                success=True,
                data={
                    "job_id": job.job_id,
                    "name": job.settings.name if job.settings else None,
                    "max_concurrent_runs": job.settings.max_concurrent_runs if job.settings else None,
                    "timeout_seconds": job.settings.timeout_seconds if job.settings else None,
                    "default_params": job.settings.notebook_task.base_parameters if job.settings and job.settings.notebook_task else None
                }
            )

        except Exception as e:
            return ToolResult(
                success=False,
                error=str(e)
            )


def register_databricks_tools(registry) -> None:
    """Register all Databricks tools with the registry."""
    registry.register(GetJobRunDetailsTool(), category="databricks")
    registry.register(GetJobRunLogsTool(), category="databricks")
    registry.register(GetClusterStatusTool(), category="databricks")
    registry.register(RestartDatabricksJobTool(), category="databricks")
    registry.register(CancelDatabricksRunTool(), category="databricks")
    registry.register(GetJobDetailsTool(), category="databricks")
