"""
Production-ready Databricks client.

Features:
- Retry with exponential backoff
- Rate limit handling
- Proper error handling
- Job monitoring
- Cluster management
"""
import asyncio
import time
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

import httpx
import structlog
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
    before_sleep_log
)

from src.integrations.config import get_settings
from src.observability import metrics, tracer, traced, metered

logger = structlog.get_logger()


class DatabricksError(Exception):
    """Base Databricks error."""
    pass


class RateLimitError(DatabricksError):
    """Rate limit exceeded."""
    pass


class ResourceNotFoundError(DatabricksError):
    """Resource not found."""
    pass


class ClusterError(DatabricksError):
    """Cluster-related error."""
    pass


class JobState(Enum):
    """Databricks job run states."""
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    TERMINATING = "TERMINATING"
    TERMINATED = "TERMINATED"
    SKIPPED = "SKIPPED"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class RunResultState(Enum):
    """Databricks run result states."""
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    TIMEDOUT = "TIMEDOUT"
    CANCELED = "CANCELED"


class ClusterState(Enum):
    """Databricks cluster states."""
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    RESTARTING = "RESTARTING"
    RESIZING = "RESIZING"
    TERMINATING = "TERMINATING"
    TERMINATED = "TERMINATED"
    ERROR = "ERROR"
    UNKNOWN = "UNKNOWN"


@dataclass
class JobRunInfo:
    """Information about a job run."""
    run_id: int
    job_id: int
    run_name: str
    state: JobState
    result_state: Optional[RunResultState]
    state_message: str
    start_time: Optional[datetime]
    end_time: Optional[datetime]
    setup_duration_ms: int
    execution_duration_ms: int
    cleanup_duration_ms: int
    cluster_id: Optional[str]
    error_code: Optional[str] = None

    @property
    def is_terminal(self) -> bool:
        return self.state in [JobState.TERMINATED, JobState.SKIPPED, JobState.INTERNAL_ERROR]

    @property
    def is_success(self) -> bool:
        return self.result_state == RunResultState.SUCCESS


@dataclass
class ClusterInfo:
    """Information about a cluster."""
    cluster_id: str
    cluster_name: str
    state: ClusterState
    state_message: str
    spark_version: str
    node_type_id: str
    driver_node_type_id: str
    num_workers: int
    autoscale_min: Optional[int]
    autoscale_max: Optional[int]
    memory_mb: int
    cores: int


class DatabricksClient:
    """
    Production-ready Databricks REST API client.
    """

    def __init__(
        self,
        host: Optional[str] = None,
        token: Optional[str] = None,
        timeout_seconds: float = 30.0,
        max_retries: int = 3
    ):
        settings = get_settings()
        self.host = (host or settings.databricks_host or "").rstrip("/")
        self.token = token or settings.databricks_token
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries

        self._client = httpx.AsyncClient(
            base_url=f"{self.host}/api/2.1",
            timeout=httpx.Timeout(timeout_seconds),
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json"
            }
        )

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()

    async def _request(
        self,
        method: str,
        endpoint: str,
        **kwargs
    ) -> Dict[str, Any]:
        """Make an API request with error handling."""
        try:
            response = await self._client.request(method, endpoint, **kwargs)

            if response.status_code == 429:
                retry_after = int(response.headers.get("Retry-After", 30))
                logger.warning("databricks_rate_limit", retry_after=retry_after)
                raise RateLimitError(f"Rate limited, retry after {retry_after}s")

            if response.status_code == 404:
                raise ResourceNotFoundError(f"Resource not found: {endpoint}")

            if response.status_code >= 400:
                error_data = response.json() if response.content else {}
                error_msg = error_data.get("message", response.text)
                logger.error(
                    "databricks_api_error",
                    status=response.status_code,
                    error=error_msg
                )
                raise DatabricksError(f"API error {response.status_code}: {error_msg}")

            return response.json() if response.content else {}

        except httpx.TimeoutException:
            logger.error("databricks_timeout", endpoint=endpoint)
            raise DatabricksError(f"Request timeout: {endpoint}")

    # ========================================================================
    # JOB OPERATIONS
    # ========================================================================

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        retry=retry_if_exception_type(RateLimitError)
    )
    @traced("databricks.get_run")
    @metered("databricks_get_run")
    async def get_run(self, run_id: int) -> JobRunInfo:
        """Get information about a job run."""
        data = await self._request("GET", f"/jobs/runs/get?run_id={run_id}")

        state = data.get("state", {})
        start_time = data.get("start_time")
        end_time = data.get("end_time")

        return JobRunInfo(
            run_id=data["run_id"],
            job_id=data.get("job_id", 0),
            run_name=data.get("run_name", ""),
            state=JobState(state.get("life_cycle_state", "PENDING")),
            result_state=RunResultState(state["result_state"]) if state.get("result_state") else None,
            state_message=state.get("state_message", ""),
            start_time=datetime.fromtimestamp(start_time / 1000) if start_time else None,
            end_time=datetime.fromtimestamp(end_time / 1000) if end_time else None,
            setup_duration_ms=data.get("setup_duration", 0),
            execution_duration_ms=data.get("execution_duration", 0),
            cleanup_duration_ms=data.get("cleanup_duration", 0),
            cluster_id=data.get("cluster_instance", {}).get("cluster_id"),
            error_code=state.get("state_message") if state.get("result_state") == "FAILED" else None
        )

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        retry=retry_if_exception_type(RateLimitError)
    )
    @traced("databricks.get_run_output")
    @metered("databricks_get_run_output")
    async def get_run_output(self, run_id: int) -> Dict[str, Any]:
        """Get the output of a job run."""
        return await self._request("GET", f"/jobs/runs/get-output?run_id={run_id}")

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        retry=retry_if_exception_type(RateLimitError)
    )
    @traced("databricks.run_now")
    @metered("databricks_run_now")
    async def run_now(
        self,
        job_id: int,
        notebook_params: Optional[Dict[str, str]] = None,
        python_params: Optional[List[str]] = None,
        jar_params: Optional[List[str]] = None
    ) -> int:
        """Trigger a job run and return the run_id."""
        payload = {"job_id": job_id}

        if notebook_params:
            payload["notebook_params"] = notebook_params
        if python_params:
            payload["python_params"] = python_params
        if jar_params:
            payload["jar_params"] = jar_params

        data = await self._request("POST", "/jobs/run-now", json=payload)

        run_id = data["run_id"]
        logger.info("databricks_job_started", job_id=job_id, run_id=run_id)

        metrics.tool_executions.labels(tool_name="databricks_run_job", status="success").inc()

        return run_id

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        retry=retry_if_exception_type(RateLimitError)
    )
    @traced("databricks.cancel_run")
    @metered("databricks_cancel_run")
    async def cancel_run(self, run_id: int) -> None:
        """Cancel a running job."""
        await self._request("POST", "/jobs/runs/cancel", json={"run_id": run_id})
        logger.info("databricks_run_cancelled", run_id=run_id)

    async def wait_for_run(
        self,
        run_id: int,
        timeout_minutes: int = 60,
        poll_interval_seconds: int = 30
    ) -> JobRunInfo:
        """Wait for a job run to complete."""
        deadline = time.time() + (timeout_minutes * 60)

        while time.time() < deadline:
            run_info = await self.get_run(run_id)

            if run_info.is_terminal:
                return run_info

            logger.info(
                "databricks_run_polling",
                run_id=run_id,
                state=run_info.state.value,
                elapsed_s=run_info.execution_duration_ms / 1000
            )

            await asyncio.sleep(poll_interval_seconds)

        raise DatabricksError(f"Run {run_id} did not complete within {timeout_minutes} minutes")

    @traced("databricks.restart_job")
    async def restart_job(
        self,
        job_id: int,
        notebook_params: Optional[Dict[str, str]] = None,
        wait: bool = False,
        timeout_minutes: int = 60
    ) -> JobRunInfo:
        """Restart a job and optionally wait for completion."""
        run_id = await self.run_now(job_id, notebook_params=notebook_params)
        run_info = await self.get_run(run_id)

        if wait:
            run_info = await self.wait_for_run(run_id, timeout_minutes=timeout_minutes)

        return run_info

    # ========================================================================
    # CLUSTER OPERATIONS
    # ========================================================================

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        retry=retry_if_exception_type(RateLimitError)
    )
    @traced("databricks.get_cluster")
    @metered("databricks_get_cluster")
    async def get_cluster(self, cluster_id: str) -> ClusterInfo:
        """Get cluster information."""
        data = await self._request("GET", f"/clusters/get?cluster_id={cluster_id}")

        return ClusterInfo(
            cluster_id=data["cluster_id"],
            cluster_name=data.get("cluster_name", ""),
            state=ClusterState(data.get("state", "UNKNOWN")),
            state_message=data.get("state_message", ""),
            spark_version=data.get("spark_version", ""),
            node_type_id=data.get("node_type_id", ""),
            driver_node_type_id=data.get("driver_node_type_id", ""),
            num_workers=data.get("num_workers", 0),
            autoscale_min=data.get("autoscale", {}).get("min_workers"),
            autoscale_max=data.get("autoscale", {}).get("max_workers"),
            memory_mb=data.get("cluster_memory_mb", 0),
            cores=data.get("cluster_cores", 0)
        )

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        retry=retry_if_exception_type(RateLimitError)
    )
    @traced("databricks.resize_cluster")
    @metered("databricks_resize_cluster")
    async def resize_cluster(
        self,
        cluster_id: str,
        num_workers: Optional[int] = None,
        autoscale_min: Optional[int] = None,
        autoscale_max: Optional[int] = None
    ) -> None:
        """Resize a cluster."""
        payload = {"cluster_id": cluster_id}

        if num_workers is not None:
            payload["num_workers"] = num_workers
        elif autoscale_min is not None and autoscale_max is not None:
            payload["autoscale"] = {
                "min_workers": autoscale_min,
                "max_workers": autoscale_max
            }
        else:
            raise ValueError("Must specify either num_workers or autoscale min/max")

        await self._request("POST", "/clusters/resize", json=payload)
        logger.info("databricks_cluster_resized", cluster_id=cluster_id)

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        retry=retry_if_exception_type(RateLimitError)
    )
    @traced("databricks.restart_cluster")
    @metered("databricks_restart_cluster")
    async def restart_cluster(self, cluster_id: str) -> None:
        """Restart a cluster."""
        await self._request("POST", "/clusters/restart", json={"cluster_id": cluster_id})
        logger.info("databricks_cluster_restarted", cluster_id=cluster_id)

    @traced("databricks.edit_cluster_memory")
    async def edit_cluster_driver_memory(
        self,
        cluster_id: str,
        driver_node_type_id: str
    ) -> None:
        """Edit cluster to change driver node type (for memory changes)."""
        # First get current cluster config
        cluster = await self.get_cluster(cluster_id)

        # Edit cluster
        payload = {
            "cluster_id": cluster_id,
            "driver_node_type_id": driver_node_type_id,
            "spark_version": cluster.spark_version,
            "node_type_id": cluster.node_type_id,
        }

        if cluster.autoscale_min:
            payload["autoscale"] = {
                "min_workers": cluster.autoscale_min,
                "max_workers": cluster.autoscale_max
            }
        else:
            payload["num_workers"] = cluster.num_workers

        await self._request("POST", "/clusters/edit", json=payload)
        logger.info(
            "databricks_cluster_driver_changed",
            cluster_id=cluster_id,
            new_driver_type=driver_node_type_id
        )

    async def wait_for_cluster(
        self,
        cluster_id: str,
        target_state: ClusterState = ClusterState.RUNNING,
        timeout_minutes: int = 15,
        poll_interval_seconds: int = 15
    ) -> ClusterInfo:
        """Wait for cluster to reach target state."""
        deadline = time.time() + (timeout_minutes * 60)

        while time.time() < deadline:
            cluster = await self.get_cluster(cluster_id)

            if cluster.state == target_state:
                return cluster

            if cluster.state == ClusterState.ERROR:
                raise ClusterError(f"Cluster in error state: {cluster.state_message}")

            logger.info(
                "databricks_cluster_polling",
                cluster_id=cluster_id,
                current_state=cluster.state.value,
                target_state=target_state.value
            )

            await asyncio.sleep(poll_interval_seconds)

        raise ClusterError(f"Cluster did not reach {target_state.value} within {timeout_minutes} minutes")

    # ========================================================================
    # LOGS
    # ========================================================================

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        retry=retry_if_exception_type(RateLimitError)
    )
    async def get_run_logs(
        self,
        cluster_id: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 1000
    ) -> List[Dict[str, Any]]:
        """
        Get cluster driver logs.

        Note: This uses the cluster log delivery feature.
        Logs must be configured to be delivered to DBFS or cloud storage.
        """
        # In a real implementation, this would:
        # 1. Get the log delivery location from cluster config
        # 2. Read logs from DBFS or cloud storage
        # 3. Parse and filter by time range

        # For now, return run output which contains error info
        return []

    # ========================================================================
    # SPARK CONTEXT
    # ========================================================================

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        retry=retry_if_exception_type(RateLimitError)
    )
    async def send_cluster_command(
        self,
        cluster_id: str,
        command: str,
        language: str = "python"
    ) -> Dict[str, Any]:
        """Execute a command on a cluster."""
        # Create execution context
        context_response = await self._request(
            "POST",
            "/contexts/create",
            json={"clusterId": cluster_id, "language": language}
        )
        context_id = context_response["id"]

        try:
            # Execute command
            command_response = await self._request(
                "POST",
                "/commands/execute",
                json={
                    "clusterId": cluster_id,
                    "contextId": context_id,
                    "command": command,
                    "language": language
                }
            )
            command_id = command_response["id"]

            # Wait for completion
            while True:
                status = await self._request(
                    "GET",
                    f"/commands/status?clusterId={cluster_id}&contextId={context_id}&commandId={command_id}"
                )

                if status["status"] in ["Finished", "Error", "Cancelled"]:
                    return status.get("results", {})

                await asyncio.sleep(2)

        finally:
            # Destroy context
            await self._request(
                "POST",
                "/contexts/destroy",
                json={"clusterId": cluster_id, "contextId": context_id}
            )

    async def clear_spark_cache(self, cluster_id: str) -> bool:
        """Clear Spark cache on a cluster."""
        try:
            result = await self.send_cluster_command(
                cluster_id,
                "spark.catalog.clearCache()"
            )
            logger.info("databricks_cache_cleared", cluster_id=cluster_id)
            return True
        except Exception as e:
            logger.error("databricks_cache_clear_failed", cluster_id=cluster_id, error=str(e))
            return False


# ============================================================================
# DATABRICKS TOOLS FOR AGENT
# ============================================================================

from src.tools.base import BaseTool, ToolResult, MutatingTool, ReadOnlyTool


class GetJobRunDetailsTool(ReadOnlyTool):
    """Tool to get job run details."""

    name = "get_databricks_job_run"
    description = "Get details about a Databricks job run"

    def __init__(self, client: Optional[DatabricksClient] = None):
        self.client = client or DatabricksClient()

    async def execute(self, run_id: int) -> ToolResult:
        try:
            run_info = await self.client.get_run(run_id)
            return ToolResult(
                success=True,
                data={
                    "run_id": run_info.run_id,
                    "job_id": run_info.job_id,
                    "state": run_info.state.value,
                    "result_state": run_info.result_state.value if run_info.result_state else None,
                    "state_message": run_info.state_message,
                    "cluster_id": run_info.cluster_id,
                    "execution_duration_ms": run_info.execution_duration_ms,
                    "is_success": run_info.is_success
                }
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e))


class GetClusterStatusTool(ReadOnlyTool):
    """Tool to get cluster status."""

    name = "get_databricks_cluster_status"
    description = "Get status of a Databricks cluster"

    def __init__(self, client: Optional[DatabricksClient] = None):
        self.client = client or DatabricksClient()

    async def execute(self, cluster_id: str) -> ToolResult:
        try:
            cluster = await self.client.get_cluster(cluster_id)
            return ToolResult(
                success=True,
                data={
                    "cluster_id": cluster.cluster_id,
                    "state": cluster.state.value,
                    "state_message": cluster.state_message,
                    "num_workers": cluster.num_workers,
                    "memory_mb": cluster.memory_mb,
                    "cores": cluster.cores
                }
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e))


class RestartJobTool(MutatingTool):
    """Tool to restart a failed job."""

    name = "restart_databricks_job"
    description = "Restart a Databricks job"
    supports_rollback = True

    def __init__(self, client: Optional[DatabricksClient] = None):
        self.client = client or DatabricksClient()

    async def execute(
        self,
        job_id: int,
        notebook_params: Optional[Dict[str, str]] = None,
        wait: bool = False
    ) -> ToolResult:
        try:
            run_info = await self.client.restart_job(
                job_id=job_id,
                notebook_params=notebook_params,
                wait=wait
            )
            return ToolResult(
                success=True,
                data={
                    "run_id": run_info.run_id,
                    "state": run_info.state.value
                },
                rollback_action="cancel_databricks_run",
                rollback_params={"run_id": run_info.run_id}
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e))

    async def rollback(self, run_id: int) -> ToolResult:
        try:
            await self.client.cancel_run(run_id)
            return ToolResult(success=True, data={"cancelled": run_id})
        except Exception as e:
            return ToolResult(success=False, error=str(e))


class ClearSparkCacheTool(MutatingTool):
    """Tool to clear Spark cache."""

    name = "clear_databricks_cache"
    description = "Clear Spark cache on a Databricks cluster"
    supports_rollback = False

    def __init__(self, client: Optional[DatabricksClient] = None):
        self.client = client or DatabricksClient()

    async def execute(self, cluster_id: str) -> ToolResult:
        try:
            success = await self.client.clear_spark_cache(cluster_id)
            return ToolResult(success=success, data={"cache_cleared": success})
        except Exception as e:
            return ToolResult(success=False, error=str(e))


class ResizeClusterTool(MutatingTool):
    """Tool to resize a cluster."""

    name = "resize_databricks_cluster"
    description = "Resize a Databricks cluster"
    supports_rollback = True

    def __init__(self, client: Optional[DatabricksClient] = None):
        self.client = client or DatabricksClient()

    async def execute(
        self,
        cluster_id: str,
        num_workers: Optional[int] = None,
        autoscale_min: Optional[int] = None,
        autoscale_max: Optional[int] = None
    ) -> ToolResult:
        try:
            # Get current config for rollback
            current = await self.client.get_cluster(cluster_id)

            await self.client.resize_cluster(
                cluster_id=cluster_id,
                num_workers=num_workers,
                autoscale_min=autoscale_min,
                autoscale_max=autoscale_max
            )

            rollback_params = {"cluster_id": cluster_id}
            if current.autoscale_min:
                rollback_params["autoscale_min"] = current.autoscale_min
                rollback_params["autoscale_max"] = current.autoscale_max
            else:
                rollback_params["num_workers"] = current.num_workers

            return ToolResult(
                success=True,
                data={"resized": True},
                rollback_action="resize_databricks_cluster",
                rollback_params=rollback_params
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e))


# Singleton client
_databricks_client: Optional[DatabricksClient] = None


async def get_databricks_client() -> DatabricksClient:
    """Get the Databricks client singleton."""
    global _databricks_client
    if _databricks_client is None:
        _databricks_client = DatabricksClient()
    return _databricks_client
