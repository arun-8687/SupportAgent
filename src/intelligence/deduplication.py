"""
Incident Deduplication and Noise Reduction.

Intelligent noise reduction using semantic similarity and temporal clustering.
Detects duplicates, related incidents, and event storms.
"""
import asyncio
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from pydantic import BaseModel, Field

from src.graph.state import DeduplicationAction, DeduplicationResult, Incident
from src.integrations.embedding_client import EmbeddingClient
from src.storage.vector_store import VectorStore


class EventStorm(BaseModel):
    """Represents a detected event storm."""
    storm_id: str
    parent_incident_id: str
    incident_count: int
    common_pattern: str
    likely_cause: Optional[str] = None
    start_time: datetime
    affected_jobs: List[str] = []


class SimilarityMatch(BaseModel):
    """A match from similarity search."""
    incident_id: str
    job_name: str
    error_message: str
    similarity: float
    created_at: datetime


class IncidentDeduplicator:
    """
    Intelligent noise reduction using semantic similarity and temporal clustering.

    Determines if an incoming incident is:
    - NEW: First occurrence, create parent incident
    - DUPLICATE: Exact match, link to parent and suppress
    - RELATED: Similar but distinct, link to parent
    - STORM: Part of event storm, aggregate
    """

    def __init__(
        self,
        embedding_client: EmbeddingClient,
        vector_store: VectorStore,
        similarity_threshold: float = 0.85,
        time_window_minutes: int = 15,
        storm_threshold: int = 10
    ):
        """
        Initialize deduplicator.

        Args:
            embedding_client: Client for generating embeddings
            vector_store: Vector store for similarity search
            similarity_threshold: Threshold for considering incidents similar
            time_window_minutes: Time window for clustering
            storm_threshold: Number of incidents to trigger storm detection
        """
        self.embedding_client = embedding_client
        self.vector_store = vector_store
        self.similarity_threshold = similarity_threshold
        self.time_window = timedelta(minutes=time_window_minutes)
        self.storm_threshold = storm_threshold

    async def process_incoming_incident(
        self,
        incident: Incident
    ) -> DeduplicationResult:
        """
        Process incoming incident for deduplication.

        Determines if incident is:
        - NEW: First occurrence, create parent incident
        - DUPLICATE: Exact match, link to parent and suppress
        - RELATED: Similar but distinct, link to parent
        - STORM: Part of event storm, aggregate

        Args:
            incident: The incoming incident

        Returns:
            DeduplicationResult with action and details
        """
        # 1. Generate embedding for incident
        incident_embedding = await self._get_embedding(incident)

        # 2. Find recent similar incidents (time window)
        recent_incidents = await self._get_recent_incidents(incident)

        # 3. Calculate semantic similarity with recent incidents
        similarities = await self._calculate_similarities(
            incident,
            incident_embedding,
            recent_incidents
        )

        # 4. Check for exact duplicates (same job, same error, high similarity)
        exact_match = self._find_exact_duplicate(incident, similarities)
        if exact_match:
            return DeduplicationResult(
                action=DeduplicationAction.SUPPRESS,
                parent_id=exact_match.incident_id,
                reason=f"Exact duplicate of {exact_match.incident_id} within time window"
            )

        # 5. Check for event storm (too many incidents in short window)
        if len(recent_incidents) >= self.storm_threshold:
            storm = await self._detect_event_storm(incident, recent_incidents)
            if storm:
                return DeduplicationResult(
                    action=DeduplicationAction.STORM,
                    parent_id=storm.parent_incident_id,
                    storm_id=storm.storm_id,
                    reason=f"Event storm detected: {storm.incident_count} incidents - {storm.common_pattern}"
                )

        # 6. Check for related incidents (same root cause pattern)
        related = self._find_related_incidents(incident, similarities)
        if related:
            parent = self._determine_parent(related)
            return DeduplicationResult(
                action=DeduplicationAction.RELATED,
                parent_id=parent.incident_id,
                reason=f"Related to {len(related)} other incidents (similarity: {parent.similarity:.2f})"
            )

        # 7. Get similar past incidents (beyond time window) for context
        similar_past = await self._get_similar_past_incidents(incident_embedding)

        # 8. New incident
        return DeduplicationResult(
            action=DeduplicationAction.NEW,
            parent_id=None,
            reason="New incident - no duplicates or related incidents found",
            similar_past_incidents=[inc.incident_id for inc in similar_past[:5]]
        )

    async def _get_embedding(self, incident: Incident) -> List[float]:
        """Generate embedding from incident context."""
        text = self._create_incident_text(incident)
        return await self.embedding_client.embed(text)

    def _create_incident_text(self, incident: Incident) -> str:
        """Create text representation for embedding."""
        parts = [
            f"Job: {incident.job_name}",
            f"Type: {incident.job_type}",
            f"Error: {incident.error_message}"
        ]

        if incident.error_code:
            parts.append(f"Error Code: {incident.error_code}")

        if incident.stack_trace:
            # Truncate stack trace to avoid token limits
            parts.append(f"Stack Trace: {incident.stack_trace[:1000]}")

        return "\n".join(parts)

    async def _get_recent_incidents(
        self,
        incident: Incident
    ) -> List[Dict[str, Any]]:
        """Get recent incidents within time window."""
        return await self.vector_store.get_recent_incidents(
            job_name=incident.job_name,
            time_window=self.time_window
        )

    async def _calculate_similarities(
        self,
        incident: Incident,
        incident_embedding: List[float],
        recent_incidents: List[Dict[str, Any]]
    ) -> List[SimilarityMatch]:
        """
        Calculate semantic similarity with recent incidents.

        Args:
            incident: Current incident
            incident_embedding: Embedding of current incident
            recent_incidents: List of recent incidents from DB

        Returns:
            List of matches with similarity scores
        """
        if not recent_incidents:
            return []

        # Get embeddings for recent incidents and calculate similarity
        matches = await self.vector_store.find_similar_incidents(
            query_embedding=incident_embedding,
            time_window=self.time_window,
            top_k=20,
            min_similarity=0.5
        )

        return [
            SimilarityMatch(
                incident_id=m.id,
                job_name=m.metadata.get("job_name", ""),
                error_message=m.metadata.get("error_message", ""),
                similarity=m.similarity,
                created_at=m.metadata.get("created_at", datetime.utcnow())
            )
            for m in matches
        ]

    def _find_exact_duplicate(
        self,
        incident: Incident,
        similarities: List[SimilarityMatch]
    ) -> Optional[SimilarityMatch]:
        """
        Find exact duplicate based on multiple criteria.

        Criteria for exact duplicate:
        - High similarity (> 0.95)
        - Same job name
        - Same error code (if present)
        """
        for match in similarities:
            if (
                match.similarity > 0.95 and
                match.job_name == incident.job_name
            ):
                return match

        return None

    def _find_related_incidents(
        self,
        incident: Incident,
        similarities: List[SimilarityMatch]
    ) -> List[SimilarityMatch]:
        """
        Find related incidents that share common root cause.

        Related incidents have:
        - Similarity above threshold but not exact
        - Same or related job names
        """
        related = []

        for match in similarities:
            if (
                self.similarity_threshold <= match.similarity < 0.95 and
                (
                    match.job_name == incident.job_name or
                    self._are_jobs_related(incident.job_name, match.job_name)
                )
            ):
                related.append(match)

        return related

    def _are_jobs_related(self, job1: str, job2: str) -> bool:
        """
        Check if two jobs are related (part of same workflow).

        Simple heuristic: share common prefix or suffix.
        """
        # Remove common suffixes/prefixes
        j1_parts = job1.lower().replace("_", "-").split("-")
        j2_parts = job2.lower().replace("_", "-").split("-")

        # Check for common root
        common = set(j1_parts) & set(j2_parts)
        return len(common) >= 2

    def _determine_parent(
        self,
        related: List[SimilarityMatch]
    ) -> SimilarityMatch:
        """Determine parent incident from related incidents."""
        # Parent is the earliest incident with highest similarity
        sorted_related = sorted(
            related,
            key=lambda x: (x.created_at, -x.similarity)
        )
        return sorted_related[0]

    async def _detect_event_storm(
        self,
        incident: Incident,
        recent_incidents: List[Dict[str, Any]]
    ) -> Optional[EventStorm]:
        """
        Detect if incidents form a storm pattern.

        Event storm criteria:
        - Many incidents in short time window
        - High semantic similarity between incidents
        - Common pattern/root cause
        """
        if len(recent_incidents) < self.storm_threshold:
            return None

        # Get embeddings for all recent incidents
        embeddings = []
        for inc in recent_incidents[:20]:  # Limit for performance
            content = f"Job: {inc.get('job_name', '')} Error: {inc.get('error_message', '')}"
            emb = await self.embedding_client.embed(content)
            embeddings.append(emb)

        # Calculate average pairwise similarity
        if len(embeddings) >= 2:
            avg_similarity = self._calculate_avg_pairwise_similarity(embeddings)

            if avg_similarity > 0.7:  # High similarity indicates storm
                # Find common pattern
                common_pattern = self._extract_common_pattern(recent_incidents)

                # Find or create parent incident
                parent_id = recent_incidents[0].get("incident_id", str(hash(incident.job_name)))

                return EventStorm(
                    storm_id=f"STORM-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                    parent_incident_id=parent_id,
                    incident_count=len(recent_incidents),
                    common_pattern=common_pattern,
                    likely_cause=f"Event storm: {common_pattern}",
                    start_time=datetime.utcnow() - self.time_window,
                    affected_jobs=list(set(
                        inc.get("job_name", "") for inc in recent_incidents
                    ))
                )

        return None

    def _calculate_avg_pairwise_similarity(
        self,
        embeddings: List[List[float]]
    ) -> float:
        """Calculate average pairwise cosine similarity."""
        if len(embeddings) < 2:
            return 0.0

        # Convert to numpy for efficient calculation
        emb_array = np.array(embeddings)

        # Normalize for cosine similarity
        norms = np.linalg.norm(emb_array, axis=1, keepdims=True)
        normalized = emb_array / (norms + 1e-10)

        # Calculate pairwise similarities
        similarity_matrix = np.dot(normalized, normalized.T)

        # Get upper triangle (excluding diagonal)
        n = len(embeddings)
        upper_triangle = similarity_matrix[np.triu_indices(n, k=1)]

        return float(np.mean(upper_triangle))

    def _extract_common_pattern(
        self,
        incidents: List[Dict[str, Any]]
    ) -> str:
        """Extract common error pattern from incidents."""
        # Find most common job name
        job_counts: Dict[str, int] = {}
        for inc in incidents:
            job_name = inc.get("job_name", "unknown")
            job_counts[job_name] = job_counts.get(job_name, 0) + 1

        most_common_job = max(job_counts, key=job_counts.get)

        # Find common error code
        error_codes = [
            inc.get("error_code", "") for inc in incidents
            if inc.get("error_code")
        ]
        common_code = max(set(error_codes), key=error_codes.count) if error_codes else ""

        if common_code:
            return f"{most_common_job} - {common_code}"
        return most_common_job

    async def _get_similar_past_incidents(
        self,
        embedding: List[float],
        top_k: int = 5
    ) -> List[SimilarityMatch]:
        """Get similar past incidents (beyond time window) for context."""
        matches = await self.vector_store.find_similar_incidents(
            query_embedding=embedding,
            status="resolved",  # Only resolved incidents
            top_k=top_k,
            min_similarity=0.6
        )

        return [
            SimilarityMatch(
                incident_id=m.id,
                job_name=m.metadata.get("job_name", ""),
                error_message=m.metadata.get("error_message", ""),
                similarity=m.similarity,
                created_at=m.metadata.get("created_at", datetime.utcnow())
            )
            for m in matches
        ]


class EventStormDetector:
    """
    Detect and aggregate event storms using time-window clustering.

    Complementary to IncidentDeduplicator for more sophisticated
    storm detection and pattern analysis.
    """

    def __init__(
        self,
        embedding_client: EmbeddingClient,
        window_minutes: int = 5,
        threshold: int = 10
    ):
        """
        Initialize storm detector.

        Args:
            embedding_client: Client for embeddings
            window_minutes: Time window for clustering
            threshold: Minimum incidents to consider a storm
        """
        self.embedding_client = embedding_client
        self.window_minutes = window_minutes
        self.threshold = threshold

    async def detect_storm(
        self,
        incidents: List[Incident]
    ) -> Optional[EventStorm]:
        """
        Detect if incidents form a storm pattern.

        Uses time-window clustering + semantic similarity.

        Args:
            incidents: List of recent incidents

        Returns:
            EventStorm if detected, None otherwise
        """
        if len(incidents) < self.threshold:
            return None

        # Cluster by time
        time_clusters = self._cluster_by_time(incidents)

        for cluster in time_clusters:
            if len(cluster) >= self.threshold:
                # Verify semantic similarity within cluster
                embeddings = await self._get_embeddings(cluster)
                avg_similarity = self._avg_pairwise_similarity(embeddings)

                if avg_similarity > 0.7:
                    return EventStorm(
                        storm_id=f"STORM-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                        parent_incident_id=cluster[0].incident_id,
                        incident_count=len(cluster),
                        common_pattern=self._extract_pattern(cluster),
                        likely_cause=await self._infer_storm_cause(cluster),
                        start_time=min(i.failure_timestamp for i in cluster),
                        affected_jobs=list(set(i.job_name for i in cluster))
                    )

        return None

    def _cluster_by_time(
        self,
        incidents: List[Incident]
    ) -> List[List[Incident]]:
        """Cluster incidents by time proximity."""
        if not incidents:
            return []

        # Sort by timestamp
        sorted_incidents = sorted(incidents, key=lambda x: x.failure_timestamp)

        clusters: List[List[Incident]] = []
        current_cluster: List[Incident] = [sorted_incidents[0]]

        window = timedelta(minutes=self.window_minutes)

        for inc in sorted_incidents[1:]:
            if inc.failure_timestamp - current_cluster[-1].failure_timestamp <= window:
                current_cluster.append(inc)
            else:
                clusters.append(current_cluster)
                current_cluster = [inc]

        if current_cluster:
            clusters.append(current_cluster)

        return clusters

    async def _get_embeddings(
        self,
        incidents: List[Incident]
    ) -> List[List[float]]:
        """Get embeddings for incidents."""
        texts = [
            f"Job: {i.job_name}\nError: {i.error_message}"
            for i in incidents
        ]
        return await self.embedding_client.embed_batch(texts)

    def _avg_pairwise_similarity(
        self,
        embeddings: List[List[float]]
    ) -> float:
        """Calculate average pairwise cosine similarity."""
        if len(embeddings) < 2:
            return 1.0

        emb_array = np.array(embeddings)
        norms = np.linalg.norm(emb_array, axis=1, keepdims=True)
        normalized = emb_array / (norms + 1e-10)

        similarity_matrix = np.dot(normalized, normalized.T)
        n = len(embeddings)
        upper_triangle = similarity_matrix[np.triu_indices(n, k=1)]

        return float(np.mean(upper_triangle))

    def _extract_pattern(self, incidents: List[Incident]) -> str:
        """Extract common pattern from incident cluster."""
        job_names = [i.job_name for i in incidents]
        most_common = max(set(job_names), key=job_names.count)
        return f"Multiple failures: {most_common} ({len(incidents)} incidents)"

    async def _infer_storm_cause(
        self,
        incidents: List[Incident]
    ) -> str:
        """Infer likely cause of event storm."""
        # Analyze common elements
        error_codes = [i.error_code for i in incidents if i.error_code]
        if error_codes:
            common_code = max(set(error_codes), key=error_codes.count)
            return f"Common error code: {common_code}"

        # Check for common error keywords
        error_keywords = ["timeout", "connection", "memory", "disk", "permission"]
        for keyword in error_keywords:
            matches = sum(
                1 for i in incidents
                if keyword.lower() in i.error_message.lower()
            )
            if matches > len(incidents) * 0.5:
                return f"Common issue: {keyword}"

        return "Multiple related failures detected"
