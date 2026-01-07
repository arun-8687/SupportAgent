"""
Support Agent SDK Client.

SDK for applications to report job failures to the Support Agent
via Azure Service Bus.
"""
from datetime import datetime
from typing import Any, Dict, List, Literal, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


class JobFailureEvent(BaseModel):
    """
    Schema for job failure events published to Service Bus.

    This is the standard format for reporting failures to the
    Support Agent system.
    """
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    # Job identification
    job_name: str
    job_type: Literal["iws", "databricks", "adf", "webapp", "api", "custom"]
    job_run_id: Optional[str] = None
    source_system: str = "unknown"

    # Failure details
    status: Literal["failed", "timeout", "error"] = "failed"
    error_message: str
    error_code: Optional[str] = None
    stack_trace: Optional[str] = None

    # Context
    environment: Literal["prod", "uat", "dev"] = "prod"
    cluster_id: Optional[str] = None
    notebook_path: Optional[str] = None
    workstation: Optional[str] = None

    # Optional enrichment
    affected_tables: Optional[List[str]] = None
    upstream_jobs: Optional[List[str]] = None
    owner_team: Optional[str] = None
    priority_hint: Optional[Literal["P1", "P2", "P3", "P4"]] = None

    # Additional metadata
    metadata: Dict[str, Any] = Field(default_factory=dict)


class SupportAgentClient:
    """
    SDK client for applications to report job failures to the Support Agent.

    Example usage:
        client = SupportAgentClient(connection_string="...")

        # Report a Databricks job failure
        incident_id = client.report_databricks_failure(
            job_id="my-etl-job",
            run_id="run-12345",
            error="SparkException: Job aborted",
            cluster_id="cluster-abc",
            owner_team="data-engineering"
        )

        print(f"Incident reported: {incident_id}")
    """

    def __init__(
        self,
        connection_string: str,
        queue_name: str = "job-failures"
    ):
        """
        Initialize the SDK client.

        Args:
            connection_string: Azure Service Bus connection string
            queue_name: Name of the queue to send messages to
        """
        self.connection_string = connection_string
        self.queue_name = queue_name
        self._client = None

    def _get_client(self):
        """Get or create Service Bus client."""
        if self._client is None:
            from azure.servicebus import ServiceBusClient
            self._client = ServiceBusClient.from_connection_string(
                self.connection_string
            )
        return self._client

    def report_failure(
        self,
        job_name: str,
        job_type: str,
        error_message: str,
        **kwargs
    ) -> str:
        """
        Report a job failure to the Support Agent.

        Args:
            job_name: Name of the failed job
            job_type: Type of job (iws, databricks, adf, etc.)
            error_message: Error message or description
            **kwargs: Additional fields (see JobFailureEvent)

        Returns:
            The event_id for tracking the incident
        """
        from azure.servicebus import ServiceBusMessage

        event = JobFailureEvent(
            job_name=job_name,
            job_type=job_type,
            error_message=error_message,
            **kwargs
        )

        client = self._get_client()

        with client.get_queue_sender(self.queue_name) as sender:
            message = ServiceBusMessage(
                body=event.model_dump_json(),
                content_type="application/json",
                subject=f"job-failure:{job_name}",
                message_id=event.event_id
            )
            sender.send_messages(message)

        return event.event_id

    async def report_failure_async(
        self,
        job_name: str,
        job_type: str,
        error_message: str,
        **kwargs
    ) -> str:
        """
        Async version of report_failure.

        Args:
            job_name: Name of the failed job
            job_type: Type of job
            error_message: Error message
            **kwargs: Additional fields

        Returns:
            The event_id for tracking
        """
        from azure.servicebus.aio import ServiceBusClient as AsyncServiceBusClient
        from azure.servicebus import ServiceBusMessage

        event = JobFailureEvent(
            job_name=job_name,
            job_type=job_type,
            error_message=error_message,
            **kwargs
        )

        async with AsyncServiceBusClient.from_connection_string(
            self.connection_string
        ) as client:
            async with client.get_queue_sender(self.queue_name) as sender:
                message = ServiceBusMessage(
                    body=event.model_dump_json(),
                    content_type="application/json",
                    subject=f"job-failure:{job_name}",
                    message_id=event.event_id
                )
                await sender.send_messages(message)

        return event.event_id

    # =========================================================================
    # Convenience Methods for Specific Job Types
    # =========================================================================

    def report_databricks_failure(
        self,
        job_id: str,
        run_id: str,
        error: str,
        cluster_id: Optional[str] = None,
        notebook_path: Optional[str] = None,
        **kwargs
    ) -> str:
        """
        Report a Databricks notebook/job failure.

        Args:
            job_id: Databricks job ID
            run_id: Job run ID
            error: Error message
            cluster_id: Cluster ID (optional)
            notebook_path: Path to notebook (optional)
            **kwargs: Additional fields

        Returns:
            The event_id for tracking
        """
        return self.report_failure(
            job_name=job_id,
            job_type="databricks",
            job_run_id=run_id,
            error_message=error,
            cluster_id=cluster_id,
            notebook_path=notebook_path,
            **kwargs
        )

    def report_iws_failure(
        self,
        job_name: str,
        workstation: str,
        error: str,
        **kwargs
    ) -> str:
        """
        Report an IBM IWS job failure.

        Args:
            job_name: IWS job name
            workstation: IWS workstation
            error: Error message
            **kwargs: Additional fields

        Returns:
            The event_id for tracking
        """
        return self.report_failure(
            job_name=job_name,
            job_type="iws",
            workstation=workstation,
            error_message=error,
            source_system="DXC",
            **kwargs
        )

    def report_adf_failure(
        self,
        pipeline_name: str,
        run_id: str,
        error: str,
        activity_name: Optional[str] = None,
        **kwargs
    ) -> str:
        """
        Report an Azure Data Factory pipeline failure.

        Args:
            pipeline_name: ADF pipeline name
            run_id: Pipeline run ID
            error: Error message
            activity_name: Failed activity name (optional)
            **kwargs: Additional fields

        Returns:
            The event_id for tracking
        """
        return self.report_failure(
            job_name=pipeline_name,
            job_type="adf",
            job_run_id=run_id,
            error_message=error,
            metadata={"activity_name": activity_name} if activity_name else {},
            **kwargs
        )

    def report_webapp_error(
        self,
        app_name: str,
        error: str,
        error_code: Optional[str] = None,
        stack_trace: Optional[str] = None,
        **kwargs
    ) -> str:
        """
        Report a web application error.

        Args:
            app_name: Application name
            error: Error message
            error_code: Error code (optional)
            stack_trace: Stack trace (optional)
            **kwargs: Additional fields

        Returns:
            The event_id for tracking
        """
        return self.report_failure(
            job_name=app_name,
            job_type="webapp",
            error_message=error,
            error_code=error_code,
            stack_trace=stack_trace,
            **kwargs
        )

    def report_api_failure(
        self,
        api_name: str,
        endpoint: str,
        error: str,
        status_code: Optional[int] = None,
        **kwargs
    ) -> str:
        """
        Report an API integration failure.

        Args:
            api_name: API or service name
            endpoint: Failed endpoint
            error: Error message
            status_code: HTTP status code (optional)
            **kwargs: Additional fields

        Returns:
            The event_id for tracking
        """
        return self.report_failure(
            job_name=f"{api_name}:{endpoint}",
            job_type="api",
            error_message=error,
            metadata={"endpoint": endpoint, "status_code": status_code},
            **kwargs
        )

    def close(self):
        """Close the Service Bus client."""
        if self._client:
            self._client.close()
            self._client = None

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()


# =============================================================================
# Usage Examples
# =============================================================================

def example_databricks_usage():
    """Example: Report failure from a Databricks notebook."""
    import traceback

    # In a Databricks notebook:
    # connection_string = dbutils.secrets.get("keyvault", "servicebus-connection")

    connection_string = "your-connection-string"
    client = SupportAgentClient(connection_string=connection_string)

    try:
        # Your ETL logic here
        raise Exception("SparkException: Job aborted due to stage failure")

    except Exception as e:
        incident_id = client.report_databricks_failure(
            job_id="etl-daily-sales",
            run_id="run-12345",
            error=str(e),
            stack_trace=traceback.format_exc(),
            cluster_id="cluster-abc-123",
            notebook_path="/Users/team/etl/daily_sales",
            affected_tables=["sales.daily_summary"],
            owner_team="data-engineering",
            environment="prod"
        )
        print(f"Incident reported: {incident_id}")
        raise


def example_iws_usage():
    """Example: Report failure from an IWS job wrapper script."""
    connection_string = "your-connection-string"

    with SupportAgentClient(connection_string=connection_string) as client:
        incident_id = client.report_iws_failure(
            job_name="DAILY_BATCH_LOAD",
            workstation="PROD_WS01",
            error="Job failed with return code 8",
            error_code="RC8",
            upstream_jobs=["DAILY_EXTRACT", "DAILY_TRANSFORM"],
            owner_team="batch-operations",
            priority_hint="P2"
        )
        print(f"Incident reported: {incident_id}")
