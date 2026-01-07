"""
Intelligent Correlation Engine.

Correlates incidents across systems to find common root causes:
- Temporal correlation (what else failed around the same time?)
- Dependency correlation (upstream/downstream impact)
- Infrastructure correlation (shared resources)
- Change correlation (recent deployments/changes)
"""
import asyncio
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

from src.graph.state import Correlation, CorrelationResult, Incident


class DependencyInfo(BaseModel):
    """Information about a system dependency."""
    name: str
    type: str  # "database", "api", "job", "service", etc.
    direction: str  # "upstream" or "downstream"
    criticality: str = "medium"  # "high", "medium", "low"


class ChangeRecord(BaseModel):
    """A change/deployment record from change management."""
    id: str
    title: str
    description: str
    affected_systems: List[str]
    change_type: str  # "deployment", "config", "patch", etc.
    completed_at: datetime
    implemented_by: Optional[str] = None
    rollback_available: bool = False


class DependencyGraph:
    """
    System dependency graph for correlation analysis.

    In production, this would integrate with CMDB or service mesh
    discovery. For now, uses a configurable mapping.
    """

    def __init__(self, dependency_config: Optional[Dict[str, Any]] = None):
        """
        Initialize dependency graph.

        Args:
            dependency_config: Optional dependency configuration
        """
        self._dependencies = dependency_config or {}
        self._job_patterns = self._build_job_patterns()

    def _build_job_patterns(self) -> Dict[str, List[str]]:
        """Build common job dependency patterns."""
        # Common patterns for job dependencies
        return {
            "etl_": ["source_db", "target_db", "landing_zone"],
            "load_": ["source_system", "data_warehouse"],
            "export_": ["source_db", "sftp", "storage"],
            "sync_": ["source_api", "target_db"],
        }

    async def get_dependencies(
        self,
        job_name: str
    ) -> Dict[str, List[DependencyInfo]]:
        """
        Get upstream and downstream dependencies for a job.

        Args:
            job_name: Name of the job

        Returns:
            Dict with "upstream" and "downstream" lists
        """
        dependencies = {
            "upstream": [],
            "downstream": []
        }

        # Check configured dependencies
        if job_name in self._dependencies:
            config = self._dependencies[job_name]
            dependencies["upstream"] = [
                DependencyInfo(**dep, direction="upstream")
                for dep in config.get("upstream", [])
            ]
            dependencies["downstream"] = [
                DependencyInfo(**dep, direction="downstream")
                for dep in config.get("downstream", [])
            ]

        # Infer from job name patterns
        for pattern, deps in self._job_patterns.items():
            if pattern in job_name.lower():
                for dep in deps:
                    dependencies["upstream"].append(
                        DependencyInfo(
                            name=f"{job_name}_{dep}",
                            type="inferred",
                            direction="upstream",
                            criticality="medium"
                        )
                    )

        return dependencies

    async def get_related_jobs(
        self,
        job_name: str
    ) -> List[str]:
        """Get jobs that are related to this job."""
        related = []

        # Jobs with same prefix (likely same workflow)
        prefix = job_name.split("_")[0] if "_" in job_name else job_name[:5]

        # In production, query CMDB or job scheduler
        # For now, return pattern-based suggestions
        related.extend([
            f"{prefix}_stage1",
            f"{prefix}_stage2",
            f"{prefix}_final"
        ])

        return related


class ITSMClient:
    """
    Client for ITSM integration (ServiceNow, etc.).

    Provides access to:
    - Recent incidents
    - Change records
    - Known errors
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None
    ):
        """Initialize ITSM client."""
        self.base_url = base_url
        self.username = username
        self.password = password
        # In production, initialize actual client

    async def get_recent_incidents(
        self,
        systems: List[str],
        time_range: timedelta
    ) -> List[Dict[str, Any]]:
        """Get recent incidents for specified systems."""
        # In production, query ITSM API
        # Placeholder implementation
        return []

    async def get_recent_changes(
        self,
        affected_systems: List[str],
        time_range: timedelta
    ) -> List[ChangeRecord]:
        """Get recent changes that might affect the systems."""
        # In production, query ITSM change management
        # Placeholder implementation
        return []

    async def get_incident(
        self,
        incident_id: str
    ) -> Optional[Dict[str, Any]]:
        """Get full incident details."""
        # Placeholder
        return None


class CorrelationEngine:
    """
    Correlate incidents across systems to find common root causes.

    Performs multiple types of correlation:
    1. Temporal - what else failed around the same time?
    2. Dependency - check upstream/downstream systems
    3. Infrastructure - shared infrastructure issues?
    4. Change - any recent deployments/changes?
    """

    def __init__(
        self,
        dependency_graph: Optional[DependencyGraph] = None,
        itsm_client: Optional[ITSMClient] = None,
        time_window_minutes: int = 30
    ):
        """
        Initialize correlation engine.

        Args:
            dependency_graph: Graph of system dependencies
            itsm_client: Client for ITSM queries
            time_window_minutes: Time window for correlation
        """
        self.dependency_graph = dependency_graph or DependencyGraph()
        self.itsm_client = itsm_client or ITSMClient()
        self.time_correlation_window = timedelta(minutes=time_window_minutes)

    async def correlate_incident(
        self,
        incident: Incident,
        recent_incidents: Optional[List[Dict[str, Any]]] = None
    ) -> CorrelationResult:
        """
        Find related failures across the system landscape.

        Args:
            incident: The incident to correlate
            recent_incidents: Optional list of recent incidents (if already fetched)

        Returns:
            CorrelationResult with findings
        """
        correlations: List[Correlation] = []

        # Run correlation analyses in parallel
        results = await asyncio.gather(
            self._find_temporal_correlations(incident, recent_incidents),
            self._find_dependency_correlations(incident),
            self._find_infrastructure_correlations(incident),
            self._find_change_correlations(incident),
            return_exceptions=True
        )

        # Collect results
        for result in results:
            if isinstance(result, list):
                correlations.extend(result)
            elif isinstance(result, Exception):
                # Log error but continue
                pass

        # Analyze correlations to find likely root cause
        root_cause_hypothesis = await self._analyze_correlations(
            incident,
            correlations
        )

        # Estimate blast radius
        blast_radius = self._estimate_blast_radius(correlations)

        # Calculate overall confidence
        confidence = self._calculate_confidence(correlations, root_cause_hypothesis)

        return CorrelationResult(
            correlations=correlations,
            root_cause_hypothesis=root_cause_hypothesis,
            blast_radius=blast_radius,
            confidence=confidence
        )

    async def _find_temporal_correlations(
        self,
        incident: Incident,
        recent_incidents: Optional[List[Dict[str, Any]]] = None
    ) -> List[Correlation]:
        """
        Find incidents that occurred around the same time.

        Temporal proximity suggests common cause.
        """
        correlations = []

        # Get recent incidents if not provided
        if recent_incidents is None:
            recent_incidents = await self.itsm_client.get_recent_incidents(
                systems=[incident.job_name],
                time_range=self.time_correlation_window
            )

        for recent in recent_incidents:
            # Skip self
            if recent.get("incident_id") == incident.incident_id:
                continue

            # Calculate time difference
            recent_time = recent.get("failure_timestamp", datetime.utcnow())
            if isinstance(recent_time, str):
                recent_time = datetime.fromisoformat(recent_time)

            time_diff = abs(
                (incident.failure_timestamp - recent_time).total_seconds()
            )

            # Calculate confidence based on time proximity
            max_seconds = self.time_correlation_window.total_seconds()
            confidence = max(0.0, 1.0 - (time_diff / max_seconds))

            if confidence > 0.3:  # Minimum threshold
                correlations.append(Correlation(
                    type="TEMPORAL",
                    related_incident_id=recent.get("incident_id"),
                    relationship=f"Failed within {int(time_diff / 60)} minutes",
                    confidence=confidence,
                    details={
                        "job_name": recent.get("job_name"),
                        "error_message": recent.get("error_message", "")[:200],
                        "time_diff_seconds": time_diff
                    }
                ))

        return correlations

    async def _find_dependency_correlations(
        self,
        incident: Incident
    ) -> List[Correlation]:
        """
        Check dependency chain for related failures.

        If upstream failed → current failure is likely downstream impact
        If downstream failed → current failure caused downstream impact
        """
        correlations = []

        # Get dependency graph for this job
        deps = await self.dependency_graph.get_dependencies(incident.job_name)

        # Check upstream dependencies
        for upstream in deps.get("upstream", []):
            upstream_incidents = await self.itsm_client.get_recent_incidents(
                systems=[upstream.name],
                time_range=self.time_correlation_window
            )

            if upstream_incidents:
                # Confidence based on criticality
                criticality_scores = {"high": 0.9, "medium": 0.7, "low": 0.5}
                confidence = criticality_scores.get(upstream.criticality, 0.7)

                correlations.append(Correlation(
                    type="UPSTREAM_FAILURE",
                    related_incident_id=upstream_incidents[0].get("incident_id"),
                    relationship=f"{incident.job_name} depends on {upstream.name}",
                    confidence=confidence,
                    details={
                        "dependency_type": upstream.type,
                        "criticality": upstream.criticality,
                        "upstream_error": upstream_incidents[0].get("error_message", "")[:200]
                    }
                ))

        # Check downstream dependencies
        for downstream in deps.get("downstream", []):
            downstream_incidents = await self.itsm_client.get_recent_incidents(
                systems=[downstream.name],
                time_range=self.time_correlation_window
            )

            if downstream_incidents:
                correlations.append(Correlation(
                    type="DOWNSTREAM_IMPACT",
                    related_incident_id=downstream_incidents[0].get("incident_id"),
                    relationship=f"{downstream.name} depends on {incident.job_name}",
                    confidence=0.6,  # Lower confidence for downstream impact
                    details={
                        "dependency_type": downstream.type,
                        "affected_system": downstream.name
                    }
                ))

        return correlations

    async def _find_infrastructure_correlations(
        self,
        incident: Incident
    ) -> List[Correlation]:
        """
        Check for shared infrastructure issues.

        Common infrastructure problems:
        - Shared database
        - Shared cluster
        - Network issues
        - Storage issues
        """
        correlations = []

        # Check for infrastructure-related error patterns
        infra_patterns = {
            "cluster": ["cluster", "node", "executor", "worker"],
            "database": ["connection", "timeout", "deadlock", "sql"],
            "network": ["network", "connection refused", "unreachable"],
            "storage": ["disk", "storage", "quota", "space"],
            "memory": ["memory", "oom", "heap", "outofmemory"]
        }

        error_lower = incident.error_message.lower()

        for infra_type, patterns in infra_patterns.items():
            matches = [p for p in patterns if p in error_lower]
            if matches:
                # Get related incidents with similar infrastructure issues
                related_incidents = await self.itsm_client.get_recent_incidents(
                    systems=[],  # All systems
                    time_range=self.time_correlation_window
                )

                # Filter to those with similar infrastructure patterns
                infra_related = [
                    inc for inc in related_incidents
                    if any(
                        p in inc.get("error_message", "").lower()
                        for p in patterns
                    )
                ]

                if len(infra_related) > 1:  # Multiple incidents = likely infra issue
                    correlations.append(Correlation(
                        type="INFRASTRUCTURE",
                        related_incident_id=None,  # General infrastructure issue
                        relationship=f"Possible {infra_type} issue affecting multiple systems",
                        confidence=min(0.9, 0.5 + len(infra_related) * 0.1),
                        details={
                            "infrastructure_type": infra_type,
                            "pattern_matches": matches,
                            "affected_count": len(infra_related)
                        }
                    ))

        return correlations

    async def _find_change_correlations(
        self,
        incident: Incident
    ) -> List[Correlation]:
        """
        Correlate with recent changes/deployments.

        Changes in the last 24 hours are suspect for causing issues.
        """
        correlations = []

        # Get recent changes
        recent_changes = await self.itsm_client.get_recent_changes(
            affected_systems=[incident.job_name],
            time_range=timedelta(hours=24)
        )

        for change in recent_changes:
            # Calculate time since change
            time_since_change = incident.failure_timestamp - change.completed_at

            # Confidence based on recency
            hours_since = time_since_change.total_seconds() / 3600
            if hours_since < 1:
                confidence = 0.9
            elif hours_since < 4:
                confidence = 0.7
            elif hours_since < 12:
                confidence = 0.5
            else:
                confidence = 0.3

            correlations.append(Correlation(
                type="RECENT_CHANGE",
                change_record_id=change.id,
                relationship=f"Change {change.id} deployed {hours_since:.1f} hours before failure",
                confidence=confidence,
                details={
                    "change_title": change.title,
                    "change_type": change.change_type,
                    "rollback_available": change.rollback_available,
                    "affected_systems": change.affected_systems
                }
            ))

        return correlations

    async def _analyze_correlations(
        self,
        incident: Incident,
        correlations: List[Correlation]
    ) -> Optional[str]:
        """
        Analyze correlations to form root cause hypothesis.

        Prioritizes:
        1. Recent changes with high confidence
        2. Upstream failures
        3. Infrastructure issues
        4. Temporal patterns
        """
        if not correlations:
            return None

        # Sort by confidence
        sorted_corrs = sorted(correlations, key=lambda x: x.confidence, reverse=True)
        top = sorted_corrs[0]

        # Form hypothesis based on top correlation
        if top.type == "RECENT_CHANGE":
            change_title = top.details.get("change_title", "Unknown change")
            return f"Likely caused by recent change: {change_title}"

        elif top.type == "UPSTREAM_FAILURE":
            upstream = top.details.get("upstream_error", "upstream system")
            return f"Cascade failure from upstream dependency: {upstream[:100]}"

        elif top.type == "INFRASTRUCTURE":
            infra_type = top.details.get("infrastructure_type", "infrastructure")
            count = top.details.get("affected_count", 0)
            return f"Shared {infra_type} issue affecting {count} systems"

        elif top.type == "TEMPORAL":
            job = top.details.get("job_name", "related job")
            return f"Concurrent failure with {job} suggests common cause"

        elif top.type == "DOWNSTREAM_IMPACT":
            return "This incident is causing downstream impact"

        return None

    def _estimate_blast_radius(
        self,
        correlations: List[Correlation]
    ) -> int:
        """Estimate number of affected systems."""
        affected_systems = set()

        for corr in correlations:
            if corr.related_incident_id:
                affected_systems.add(corr.related_incident_id)

            if corr.details:
                # Count affected systems from details
                if "affected_count" in corr.details:
                    return max(len(affected_systems), corr.details["affected_count"])

                if "affected_systems" in corr.details:
                    affected_systems.update(corr.details["affected_systems"])

        return len(affected_systems)

    def _calculate_confidence(
        self,
        correlations: List[Correlation],
        hypothesis: Optional[str]
    ) -> float:
        """Calculate overall confidence in correlation analysis."""
        if not correlations:
            return 0.0

        if not hypothesis:
            return 0.0

        # Weight by type
        type_weights = {
            "RECENT_CHANGE": 1.0,
            "UPSTREAM_FAILURE": 0.9,
            "INFRASTRUCTURE": 0.8,
            "TEMPORAL": 0.6,
            "DOWNSTREAM_IMPACT": 0.5
        }

        # Calculate weighted average confidence
        total_weight = 0.0
        weighted_conf = 0.0

        for corr in correlations:
            weight = type_weights.get(corr.type, 0.5)
            weighted_conf += corr.confidence * weight
            total_weight += weight

        if total_weight == 0:
            return 0.0

        return min(0.95, weighted_conf / total_weight)
