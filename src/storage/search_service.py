"""
Unified Search Service - Coordinates Azure AI Search and PostgreSQL.

Design:
- PostgreSQL: System of record (writes, transactions, audit)
- Azure AI Search: Search index (reads, semantic search, hybrid queries)

Write path: PostgreSQL → Sync to Azure AI Search
Read path: Azure AI Search (with PostgreSQL fallback)
"""
import asyncio
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import uuid4

import structlog

from src.integrations.config import get_settings
from src.integrations.search_client import (
    AzureSearchClient,
    SearchMode,
    SearchResult,
    SearchResponse,
    get_search_client
)
from src.storage.database import (
    DatabasePool,
    VectorStore,
    get_database_pool,
    get_vector_store
)

logger = structlog.get_logger()


@dataclass
class IncidentMatch:
    """Matched incident with resolution info."""
    incident_id: str
    job_name: str
    job_type: str
    error_message: str
    similarity_score: float
    resolution_summary: Optional[str] = None
    resolution_verified: bool = False
    source: str = "search"  # "search" or "database"


@dataclass
class KnownErrorMatch:
    """Matched known error."""
    error_id: str
    title: str
    error_pattern: str
    root_cause: Optional[str]
    workaround: Optional[str]
    permanent_fix: Optional[str]
    confidence: float
    success_count: int = 0


@dataclass
class RunbookMatch:
    """Matched runbook."""
    runbook_id: str
    name: str
    description: Optional[str]
    content: str
    relevance_score: float
    success_rate: float = 0.0


class SearchService:
    """
    Unified search service coordinating Azure AI Search and PostgreSQL.

    Responsibilities:
    - Write operations go to PostgreSQL first, then sync to Search
    - Read operations use Azure AI Search (with PostgreSQL fallback)
    - Handles index synchronization
    - Provides hybrid search capabilities
    """

    def __init__(
        self,
        search_client: Optional[AzureSearchClient] = None,
        vector_store: Optional[VectorStore] = None,
        use_search_for_reads: bool = True
    ):
        self._search_client = search_client
        self._vector_store = vector_store
        self.use_search_for_reads = use_search_for_reads
        self._initialized = False

    async def initialize(self) -> None:
        """Initialize both search and database connections."""
        if self._initialized:
            return

        # Initialize both in parallel
        search_task = get_search_client() if self._search_client is None else asyncio.sleep(0)
        db_task = get_vector_store() if self._vector_store is None else asyncio.sleep(0)

        results = await asyncio.gather(search_task, db_task, return_exceptions=True)

        if self._search_client is None and not isinstance(results[0], Exception):
            self._search_client = results[0]
        if self._vector_store is None and not isinstance(results[1], Exception):
            self._vector_store = results[1]

        self._initialized = True
        logger.info("search_service_initialized")

    # =========================================================================
    # Write Operations (PostgreSQL → Azure AI Search)
    # =========================================================================

    async def store_incident(
        self,
        incident_id: str,
        job_name: str,
        job_type: str,
        error_message: str,
        embedding: List[float],
        **kwargs
    ) -> str:
        """
        Store incident in PostgreSQL and sync to Azure AI Search.

        PostgreSQL is the source of truth; Search is updated async.
        """
        await self.initialize()

        # 1. Write to PostgreSQL (synchronous, must succeed)
        await self._vector_store.store_incident(
            incident_id=incident_id,
            job_name=job_name,
            job_type=job_type,
            error_message=error_message,
            embedding=embedding,
            **kwargs
        )

        # 2. Sync to Azure AI Search (async, best effort)
        try:
            search_doc = {
                "id": str(uuid4()),
                "incident_id": incident_id,
                "job_name": job_name,
                "job_type": job_type,
                "error_message": error_message,
                "stack_trace": kwargs.get("stack_trace"),
                "environment": kwargs.get("environment"),
                "severity": kwargs.get("severity"),
                "category": kwargs.get("category"),
                "status": "open",
                "created_at": datetime.utcnow().isoformat(),
                "embedding": embedding
            }
            await self._search_client.index_incident(search_doc)
        except Exception as e:
            # Log but don't fail - PostgreSQL write succeeded
            logger.warning(
                "search_index_sync_failed",
                incident_id=incident_id,
                error=str(e)
            )

        return incident_id

    async def update_incident_resolution(
        self,
        incident_id: str,
        resolution_summary: str,
        resolution_verified: bool = False
    ) -> None:
        """Update incident resolution in both stores."""
        await self.initialize()

        # 1. Update PostgreSQL
        await self._vector_store.update_incident_resolution(
            incident_id=incident_id,
            resolution_summary=resolution_summary,
            resolution_verified=resolution_verified
        )

        # 2. Update Search index (would need to fetch and re-index)
        # For now, rely on periodic sync job
        logger.info(
            "incident_resolution_updated",
            incident_id=incident_id,
            verified=resolution_verified
        )

    async def store_known_error(
        self,
        error_id: str,
        title: str,
        error_pattern: str,
        embedding: List[float],
        **kwargs
    ) -> str:
        """Store known error in PostgreSQL and sync to Search."""
        await self.initialize()

        # Write to PostgreSQL first
        async with self._vector_store.pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO known_errors (
                    error_id, title, error_pattern, root_cause, workaround,
                    permanent_fix, embedding, job_types, active
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, TRUE)
                ON CONFLICT (error_id) DO UPDATE SET
                    title = EXCLUDED.title,
                    error_pattern = EXCLUDED.error_pattern,
                    root_cause = EXCLUDED.root_cause,
                    workaround = EXCLUDED.workaround,
                    permanent_fix = EXCLUDED.permanent_fix,
                    embedding = EXCLUDED.embedding,
                    updated_at = NOW()
            """,
                error_id,
                title,
                error_pattern,
                kwargs.get("root_cause"),
                kwargs.get("workaround"),
                kwargs.get("permanent_fix"),
                embedding,
                kwargs.get("job_types", [])
            )

        # Sync to Search
        try:
            search_doc = {
                "id": str(uuid4()),
                "error_id": error_id,
                "title": title,
                "error_pattern": error_pattern,
                "root_cause": kwargs.get("root_cause"),
                "workaround": kwargs.get("workaround"),
                "permanent_fix": kwargs.get("permanent_fix"),
                "job_types": kwargs.get("job_types", []),
                "active": True,
                "success_count": 0,
                "failure_count": 0,
                "embedding": embedding
            }
            await self._search_client.index_known_error(search_doc)
        except Exception as e:
            logger.warning("known_error_search_sync_failed", error_id=error_id, error=str(e))

        return error_id

    # =========================================================================
    # Read Operations (Azure AI Search with PostgreSQL fallback)
    # =========================================================================

    async def find_similar_incidents(
        self,
        embedding: List[float],
        query_text: Optional[str] = None,
        job_type: Optional[str] = None,
        environment: Optional[str] = None,
        exclude_id: Optional[str] = None,
        min_score: float = 0.7,
        limit: int = 10,
        use_hybrid: bool = True
    ) -> List[IncidentMatch]:
        """
        Find similar incidents using hybrid search.

        Uses Azure AI Search if available, falls back to PostgreSQL.
        """
        await self.initialize()

        if self.use_search_for_reads and self._search_client:
            try:
                # Use hybrid search (vector + keyword)
                mode = SearchMode.HYBRID if use_hybrid and query_text else SearchMode.VECTOR

                results = await self._search_client.find_similar_incidents(
                    embedding=embedding,
                    exclude_id=exclude_id,
                    environment=environment,
                    job_type=job_type,
                    min_score=min_score,
                    top=limit
                )

                return [
                    IncidentMatch(
                        incident_id=r.document.get("incident_id"),
                        job_name=r.document.get("job_name"),
                        job_type=r.document.get("job_type"),
                        error_message=r.document.get("error_message"),
                        similarity_score=r.score,
                        resolution_summary=r.document.get("resolution_summary"),
                        resolution_verified=r.document.get("resolution_verified", False),
                        source="search"
                    )
                    for r in results
                ]
            except Exception as e:
                logger.warning("search_failed_falling_back_to_db", error=str(e))

        # Fallback to PostgreSQL
        results = await self._vector_store.find_similar_incidents(
            embedding=embedding,
            limit=limit,
            threshold=min_score,
            job_type=job_type,
            exclude_incident_id=exclude_id
        )

        return [
            IncidentMatch(
                incident_id=r["incident_id"],
                job_name=r["job_name"],
                job_type=r["job_type"],
                error_message=r["error_message"],
                similarity_score=r.get("similarity", 0.0),
                resolution_summary=r.get("resolution_summary"),
                resolution_verified=r.get("resolution_verified", False),
                source="database"
            )
            for r in results
        ]

    async def search_known_errors(
        self,
        embedding: List[float],
        query_text: Optional[str] = None,
        job_type: Optional[str] = None,
        limit: int = 5
    ) -> List[KnownErrorMatch]:
        """Search known error database."""
        await self.initialize()

        if self.use_search_for_reads and self._search_client:
            try:
                response = await self._search_client.search_known_errors(
                    query=query_text,
                    embedding=embedding,
                    job_type=job_type,
                    top=limit
                )

                return [
                    KnownErrorMatch(
                        error_id=r.document.get("error_id"),
                        title=r.document.get("title"),
                        error_pattern=r.document.get("error_pattern"),
                        root_cause=r.document.get("root_cause"),
                        workaround=r.document.get("workaround"),
                        permanent_fix=r.document.get("permanent_fix"),
                        confidence=r.score,
                        success_count=r.document.get("success_count", 0)
                    )
                    for r in response.results
                ]
            except Exception as e:
                logger.warning("known_errors_search_failed", error=str(e))

        # Fallback to PostgreSQL
        results = await self._vector_store.search_known_errors(
            embedding=embedding,
            limit=limit,
            job_type=job_type
        )

        return [
            KnownErrorMatch(
                error_id=r["error_id"],
                title=r["title"],
                error_pattern=r["error_pattern"],
                root_cause=r.get("root_cause"),
                workaround=r.get("workaround"),
                permanent_fix=r.get("permanent_fix"),
                confidence=r.get("match_confidence", 0.0),
                success_count=r.get("success_count", 0)
            )
            for r in results
        ]

    async def search_runbooks(
        self,
        embedding: List[float],
        query_text: Optional[str] = None,
        job_type: Optional[str] = None,
        limit: int = 3
    ) -> List[RunbookMatch]:
        """Search runbooks."""
        await self.initialize()

        if self.use_search_for_reads and self._search_client:
            try:
                response = await self._search_client.search_runbooks(
                    query=query_text,
                    embedding=embedding,
                    job_type=job_type,
                    top=limit
                )

                return [
                    RunbookMatch(
                        runbook_id=r.document.get("runbook_id"),
                        name=r.document.get("name"),
                        description=r.document.get("description"),
                        content=r.document.get("content"),
                        relevance_score=r.score,
                        success_rate=r.document.get("success_rate", 0.0)
                    )
                    for r in response.results
                ]
            except Exception as e:
                logger.warning("runbooks_search_failed", error=str(e))

        # Fallback to PostgreSQL
        results = await self._vector_store.search_runbooks(
            embedding=embedding,
            limit=limit,
            job_type=job_type
        )

        return [
            RunbookMatch(
                runbook_id=r["runbook_id"],
                name=r["name"],
                description=r.get("description"),
                content=r["content"],
                relevance_score=r.get("relevance", 0.0),
                success_rate=r.get("success_rate", 0.0)
            )
            for r in results
        ]

    async def hybrid_search(
        self,
        query_text: str,
        embedding: List[float],
        job_type: Optional[str] = None,
        environment: Optional[str] = None,
        limit: int = 10
    ) -> Dict[str, Any]:
        """
        Perform hybrid search across all indexes.

        Returns incidents, known errors, and runbooks in a single call.
        """
        await self.initialize()

        # Run all searches in parallel
        incidents_task = self.find_similar_incidents(
            embedding=embedding,
            query_text=query_text,
            job_type=job_type,
            environment=environment,
            limit=limit,
            use_hybrid=True
        )

        known_errors_task = self.search_known_errors(
            embedding=embedding,
            query_text=query_text,
            job_type=job_type,
            limit=5
        )

        runbooks_task = self.search_runbooks(
            embedding=embedding,
            query_text=query_text,
            job_type=job_type,
            limit=3
        )

        incidents, known_errors, runbooks = await asyncio.gather(
            incidents_task,
            known_errors_task,
            runbooks_task,
            return_exceptions=True
        )

        return {
            "similar_incidents": incidents if not isinstance(incidents, Exception) else [],
            "known_errors": known_errors if not isinstance(known_errors, Exception) else [],
            "runbooks": runbooks if not isinstance(runbooks, Exception) else [],
        }


# Singleton instance
_search_service: Optional[SearchService] = None


async def get_search_service() -> SearchService:
    """Get the search service singleton."""
    global _search_service
    if _search_service is None:
        _search_service = SearchService()
        await _search_service.initialize()
    return _search_service
