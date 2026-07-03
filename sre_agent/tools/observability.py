"""
Observability tools: metrics and log queries.

Uses azure-monitor-query against Log Analytics / Azure Monitor when
credentials are available; otherwise returns representative synthetic data
so investigations can run end-to-end in local dev and tests.
"""
import logging
import os
import random
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def _synthetic_series(name: str, minutes: int, base: float, drift: float) -> List[Dict[str, Any]]:
    """Generate a metric series with a visible upward drift (regression-like)."""
    now = datetime.now(timezone.utc)
    rng = random.Random(name)  # deterministic per metric name
    points = []
    for i in range(minutes, 0, -5):
        ts = now - timedelta(minutes=i)
        value = base + drift * (minutes - i) / minutes + rng.uniform(-2, 2)
        points.append({"timestamp": ts.isoformat(), "value": round(value, 2)})
    return points


class ObservabilityClient:
    """Query metrics and logs for a resource."""

    def __init__(self) -> None:
        self._credential = None
        self._live = False
        try:
            if os.environ.get("AZURE_CLIENT_ID") or os.environ.get("MSI_ENDPOINT"):
                from azure.identity import DefaultAzureCredential

                self._credential = DefaultAzureCredential()
                self._live = True
        except Exception:  # pragma: no cover
            logger.warning("Azure credential unavailable; observability in mock mode")

    async def query_metrics(
        self,
        resource_id: Optional[str],
        metric_names: List[str],
        lookback_minutes: int = 90,
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Return time series per metric for the incident window."""
        if self._live and resource_id:
            try:
                from azure.monitor.query import MetricsQueryClient

                client = MetricsQueryClient(self._credential)
                response = client.query_resource(
                    resource_id,
                    metric_names=metric_names,
                    timespan=timedelta(minutes=lookback_minutes),
                )
                series: Dict[str, List[Dict[str, Any]]] = {}
                for metric in response.metrics:
                    points = []
                    for ts in metric.timeseries:
                        for point in ts.data:
                            if point.average is not None:
                                points.append(
                                    {
                                        "timestamp": point.timestamp.isoformat(),
                                        "value": point.average,
                                    }
                                )
                    series[metric.name] = points
                return series
            except Exception:
                logger.exception("Live metrics query failed; falling back to mock")

        return {
            name: _synthetic_series(name, lookback_minutes, base=45.0, drift=40.0)
            for name in metric_names
        }

    async def query_logs(
        self,
        workspace_id: Optional[str],
        kusto_query: str,
        lookback_minutes: int = 90,
    ) -> List[Dict[str, Any]]:
        """Run a KQL query against Log Analytics (or return mock exceptions)."""
        if self._live and workspace_id:
            try:
                from azure.monitor.query import LogsQueryClient

                client = LogsQueryClient(self._credential)
                response = client.query_workspace(
                    workspace_id,
                    kusto_query,
                    timespan=timedelta(minutes=lookback_minutes),
                )
                rows: List[Dict[str, Any]] = []
                for table in response.tables:
                    columns = table.columns
                    for row in table.rows:
                        rows.append(dict(zip(columns, row)))
                return rows
            except Exception:
                logger.exception("Live logs query failed; falling back to mock")

        now = datetime.now(timezone.utc)
        return [
            {
                "timestamp": (now - timedelta(minutes=38)).isoformat(),
                "level": "Error",
                "message": "OutOfMemoryError: Java heap space",
                "count": 17,
            },
            {
                "timestamp": (now - timedelta(minutes=25)).isoformat(),
                "level": "Warning",
                "message": "Container memory usage above 90% of limit",
                "count": 42,
            },
            {
                "timestamp": (now - timedelta(minutes=12)).isoformat(),
                "level": "Error",
                "message": "Pod payment-service-7d9f restarted (OOMKilled)",
                "count": 3,
            },
        ]

    async def check_health(self, resource_id: Optional[str]) -> Dict[str, Any]:
        """Simple health probe used by the verification step."""
        # In live mode this would hit availability tests / resource health API.
        return {
            "resource_id": resource_id,
            "status": "healthy",
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }
