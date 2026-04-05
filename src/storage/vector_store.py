"""
Vector Store implementation using PostgreSQL with pgvector.

Provides semantic similarity search for:
- Incident deduplication
- Known error matching
- Past incident retrieval
- Runbook/documentation search
"""
import asyncio
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

import asyncpg
from pydantic import BaseModel

from src.integrations.embedding_client import EmbeddingClient


class SimilarityMatch(BaseModel):
    """Result of a similarity search."""
    id: str
    content: str
    metadata: Dict[str, Any]
    similarity: float
    collection: str


class VectorStore:
    """
    PostgreSQL + pgvector based vector store for semantic search.

    Supports multiple collections:
    - incidents: Historical incidents with embeddings
    - known_errors: Known Error Database (KEDB)
    - runbooks: Runbook documentation
    - knowledge: General knowledge base
    """

    def __init__(
        self,
        connection_string: str,
        embedding_client: EmbeddingClient,
        embedding_dimension: int = 3072
    ):
        """
        Initialize vector store.

        Args:
            connection_string: PostgreSQL connection string
            embedding_client: Client for generating embeddings
            embedding_dimension: Dimension of embedding vectors (3072 for text-embedding-3-large)
        """
        self.connection_string = connection_string
        self.embedding_client = embedding_client
        self.embedding_dimension = embedding_dimension
        self._pool: Optional[asyncpg.Pool] = None

    async def initialize(self) -> None:
        """Initialize connection pool and create tables if needed."""
        self._pool = await asyncpg.create_pool(
            self.connection_string,
            min_size=5,
            max_size=20
        )
        await self._ensure_tables()

    async def close(self) -> None:
        """Close connection pool."""
        if self._pool:
            await self._pool.close()

    async def _ensure_tables(self) -> None:
        """Create tables and indexes if they don't exist."""
        async with self._pool.acquire() as conn:
            # Enable pgvector extension
            await conn.execute("CREATE EXTENSION IF NOT EXISTS vector;")

            # Incidents table with vector embeddings
            await conn.execute(f"""
                CREATE TABLE IF NOT EXISTS incident_embeddings (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    incident_id VARCHAR(100) UNIQUE NOT NULL,
                    job_name VARCHAR(255) NOT NULL,
                    job_type VARCHAR(50) NOT NULL,
                    error_message TEXT,
                    error_code VARCHAR(100),
                    content TEXT NOT NULL,
                    embedding vector({self.embedding_dimension}),
                    status VARCHAR(50) DEFAULT 'open',
                    resolution_summary TEXT,
                    resolved_at TIMESTAMPTZ,
                    metadata JSONB DEFAULT '{{}}',
                    created_at TIMESTAMPTZ DEFAULT NOW(),
                    updated_at TIMESTAMPTZ DEFAULT NOW()
                );
            """)

            # Known errors table
            await conn.execute(f"""
                CREATE TABLE IF NOT EXISTS known_error_embeddings (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    kedb_id VARCHAR(100) UNIQUE NOT NULL,
                    title VARCHAR(500) NOT NULL,
                    error_pattern TEXT NOT NULL,
                    root_cause TEXT,
                    workaround TEXT,
                    permanent_fix TEXT,
                    linked_runbook VARCHAR(255),
                    content TEXT NOT NULL,
                    embedding vector({self.embedding_dimension}),
                    active BOOLEAN DEFAULT TRUE,
                    metadata JSONB DEFAULT '{{}}',
                    created_at TIMESTAMPTZ DEFAULT NOW(),
                    updated_at TIMESTAMPTZ DEFAULT NOW()
                );
            """)

            # Runbooks table
            await conn.execute(f"""
                CREATE TABLE IF NOT EXISTS runbook_embeddings (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    runbook_id VARCHAR(100) UNIQUE NOT NULL,
                    name VARCHAR(255) NOT NULL,
                    description TEXT,
                    issue_type VARCHAR(100),
                    content TEXT NOT NULL,
                    embedding vector({self.embedding_dimension}),
                    file_path VARCHAR(500),
                    active BOOLEAN DEFAULT TRUE,
                    metadata JSONB DEFAULT '{{}}',
                    created_at TIMESTAMPTZ DEFAULT NOW()
                );
            """)

            # General knowledge base
            await conn.execute(f"""
                CREATE TABLE IF NOT EXISTS knowledge_embeddings (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    doc_id VARCHAR(100) UNIQUE NOT NULL,
                    title VARCHAR(500) NOT NULL,
                    doc_type VARCHAR(100),
                    content TEXT NOT NULL,
                    embedding vector({self.embedding_dimension}),
                    source VARCHAR(255),
                    metadata JSONB DEFAULT '{{}}',
                    created_at TIMESTAMPTZ DEFAULT NOW()
                );
            """)

            # Create indexes for vector similarity search (IVFFlat)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS incident_embedding_idx
                ON incident_embeddings
                USING ivfflat (embedding vector_cosine_ops)
                WITH (lists = 100);
            """)

            await conn.execute("""
                CREATE INDEX IF NOT EXISTS known_error_embedding_idx
                ON known_error_embeddings
                USING ivfflat (embedding vector_cosine_ops)
                WITH (lists = 100);
            """)

            await conn.execute("""
                CREATE INDEX IF NOT EXISTS runbook_embedding_idx
                ON runbook_embeddings
                USING ivfflat (embedding vector_cosine_ops)
                WITH (lists = 100);
            """)

            # Create indexes for filtering
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS incident_job_name_idx
                ON incident_embeddings (job_name);
            """)

            await conn.execute("""
                CREATE INDEX IF NOT EXISTS incident_created_at_idx
                ON incident_embeddings (created_at DESC);
            """)

    # =========================================================================
    # Incident Operations
    # =========================================================================

    async def store_incident(
        self,
        incident_id: str,
        job_name: str,
        job_type: str,
        error_message: str,
        error_code: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Store an incident with its embedding.

        Args:
            incident_id: Unique incident identifier
            job_name: Name of the failed job
            job_type: Type of job (iws, databricks, etc.)
            error_message: Error message
            error_code: Optional error code
            metadata: Additional metadata

        Returns:
            UUID of stored record
        """
        # Create content for embedding
        content = self._create_incident_content(
            job_name, job_type, error_message, error_code
        )

        # Generate embedding
        embedding = await self.embedding_client.embed(content)

        async with self._pool.acquire() as conn:
            row = await conn.fetchrow("""
                INSERT INTO incident_embeddings
                    (incident_id, job_name, job_type, error_message, error_code,
                     content, embedding, metadata)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                ON CONFLICT (incident_id) DO UPDATE SET
                    error_message = EXCLUDED.error_message,
                    content = EXCLUDED.content,
                    embedding = EXCLUDED.embedding,
                    metadata = EXCLUDED.metadata,
                    updated_at = NOW()
                RETURNING id;
            """, incident_id, job_name, job_type, error_message, error_code,
                content, embedding, metadata or {})

            return str(row["id"])

    async def update_incident_resolution(
        self,
        incident_id: str,
        resolution_summary: str,
        status: str = "resolved"
    ) -> None:
        """Update incident with resolution information."""
        async with self._pool.acquire() as conn:
            await conn.execute("""
                UPDATE incident_embeddings
                SET status = $2,
                    resolution_summary = $3,
                    resolved_at = NOW(),
                    updated_at = NOW()
                WHERE incident_id = $1;
            """, incident_id, status, resolution_summary)

    async def find_similar_incidents(
        self,
        query_text: Optional[str] = None,
        query_embedding: Optional[List[float]] = None,
        job_name: Optional[str] = None,
        job_type: Optional[str] = None,
        status: Optional[str] = None,
        time_window: Optional[timedelta] = None,
        top_k: int = 10,
        min_similarity: float = 0.5
    ) -> List[SimilarityMatch]:
        """
        Find similar incidents using vector similarity.

        Args:
            query_text: Text to search for (will be embedded)
            query_embedding: Pre-computed embedding
            job_name: Filter by job name
            job_type: Filter by job type
            status: Filter by status (open, resolved)
            time_window: Only search within this time window
            top_k: Number of results to return
            min_similarity: Minimum similarity threshold

        Returns:
            List of similar incidents with similarity scores
        """
        # Get embedding
        if query_embedding is None and query_text:
            query_embedding = await self.embedding_client.embed(query_text)
        elif query_embedding is None:
            raise ValueError("Either query_text or query_embedding required")

        # Build query with filters
        conditions = []
        params = [query_embedding, top_k]
        param_idx = 3

        if job_name:
            conditions.append(f"job_name = ${param_idx}")
            params.append(job_name)
            param_idx += 1

        if job_type:
            conditions.append(f"job_type = ${param_idx}")
            params.append(job_type)
            param_idx += 1

        if status:
            conditions.append(f"status = ${param_idx}")
            params.append(status)
            param_idx += 1

        if time_window:
            conditions.append(f"created_at > NOW() - INTERVAL '{time_window.total_seconds()} seconds'")

        where_clause = "WHERE " + " AND ".join(conditions) if conditions else ""

        query = f"""
            SELECT
                incident_id as id,
                content,
                metadata,
                1 - (embedding <=> $1) as similarity
            FROM incident_embeddings
            {where_clause}
            ORDER BY embedding <=> $1
            LIMIT $2;
        """

        async with self._pool.acquire() as conn:
            rows = await conn.fetch(query, *params)

        results = []
        for row in rows:
            if row["similarity"] >= min_similarity:
                results.append(SimilarityMatch(
                    id=row["id"],
                    content=row["content"],
                    metadata=dict(row["metadata"]) if row["metadata"] else {},
                    similarity=row["similarity"],
                    collection="incidents"
                ))

        return results

    async def get_recent_incidents(
        self,
        job_name: Optional[str] = None,
        time_window: timedelta = timedelta(minutes=15)
    ) -> List[Dict[str, Any]]:
        """Get recent incidents within time window."""
        async with self._pool.acquire() as conn:
            if job_name:
                rows = await conn.fetch("""
                    SELECT incident_id, job_name, job_type, error_message,
                           error_code, status, created_at, metadata
                    FROM incident_embeddings
                    WHERE job_name = $1
                      AND created_at > NOW() - INTERVAL '$2 seconds'
                    ORDER BY created_at DESC;
                """, job_name, time_window.total_seconds())
            else:
                rows = await conn.fetch("""
                    SELECT incident_id, job_name, job_type, error_message,
                           error_code, status, created_at, metadata
                    FROM incident_embeddings
                    WHERE created_at > NOW() - INTERVAL '$1 seconds'
                    ORDER BY created_at DESC;
                """, time_window.total_seconds())

        return [dict(row) for row in rows]

    # =========================================================================
    # Known Error Operations
    # =========================================================================

    async def store_known_error(
        self,
        kedb_id: str,
        title: str,
        error_pattern: str,
        root_cause: Optional[str] = None,
        workaround: Optional[str] = None,
        permanent_fix: Optional[str] = None,
        linked_runbook: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """Store a known error with its embedding."""
        content = f"""
        Title: {title}
        Error Pattern: {error_pattern}
        Root Cause: {root_cause or 'N/A'}
        Workaround: {workaround or 'N/A'}
        """

        embedding = await self.embedding_client.embed(content)

        async with self._pool.acquire() as conn:
            row = await conn.fetchrow("""
                INSERT INTO known_error_embeddings
                    (kedb_id, title, error_pattern, root_cause, workaround,
                     permanent_fix, linked_runbook, content, embedding, metadata)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                ON CONFLICT (kedb_id) DO UPDATE SET
                    title = EXCLUDED.title,
                    error_pattern = EXCLUDED.error_pattern,
                    root_cause = EXCLUDED.root_cause,
                    workaround = EXCLUDED.workaround,
                    permanent_fix = EXCLUDED.permanent_fix,
                    linked_runbook = EXCLUDED.linked_runbook,
                    content = EXCLUDED.content,
                    embedding = EXCLUDED.embedding,
                    metadata = EXCLUDED.metadata,
                    updated_at = NOW()
                RETURNING id;
            """, kedb_id, title, error_pattern, root_cause, workaround,
                permanent_fix, linked_runbook, content, embedding, metadata or {})

            return str(row["id"])

    async def search_known_errors(
        self,
        query_text: Optional[str] = None,
        query_embedding: Optional[List[float]] = None,
        error_code: Optional[str] = None,
        top_k: int = 5,
        min_similarity: float = 0.6
    ) -> List[Dict[str, Any]]:
        """
        Search known errors by similarity and/or error code.

        Returns full known error records with similarity scores.
        """
        results = []

        # Vector similarity search
        if query_text or query_embedding:
            if query_embedding is None:
                query_embedding = await self.embedding_client.embed(query_text)

            async with self._pool.acquire() as conn:
                rows = await conn.fetch("""
                    SELECT
                        kedb_id, title, error_pattern, root_cause,
                        workaround, permanent_fix, linked_runbook,
                        1 - (embedding <=> $1) as similarity
                    FROM known_error_embeddings
                    WHERE active = TRUE
                    ORDER BY embedding <=> $1
                    LIMIT $2;
                """, query_embedding, top_k)

            for row in rows:
                if row["similarity"] >= min_similarity:
                    results.append({
                        "id": row["kedb_id"],
                        "title": row["title"],
                        "error_pattern": row["error_pattern"],
                        "root_cause": row["root_cause"],
                        "workaround": row["workaround"],
                        "permanent_fix": row["permanent_fix"],
                        "linked_runbook": row["linked_runbook"],
                        "similarity": row["similarity"]
                    })

        # Keyword search by error code
        if error_code:
            async with self._pool.acquire() as conn:
                rows = await conn.fetch("""
                    SELECT kedb_id, title, error_pattern, root_cause,
                           workaround, permanent_fix, linked_runbook
                    FROM known_error_embeddings
                    WHERE active = TRUE
                      AND error_pattern ILIKE $1;
                """, f"%{error_code}%")

            for row in rows:
                # Avoid duplicates
                if not any(r["id"] == row["kedb_id"] for r in results):
                    results.append({
                        "id": row["kedb_id"],
                        "title": row["title"],
                        "error_pattern": row["error_pattern"],
                        "root_cause": row["root_cause"],
                        "workaround": row["workaround"],
                        "permanent_fix": row["permanent_fix"],
                        "linked_runbook": row["linked_runbook"],
                        "similarity": 0.95  # High score for exact match
                    })

        return results

    # =========================================================================
    # Runbook Operations
    # =========================================================================

    async def store_runbook(
        self,
        runbook_id: str,
        name: str,
        description: str,
        issue_type: str,
        file_path: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """Store a runbook with its embedding."""
        content = f"""
        Runbook: {name}
        Description: {description}
        Issue Type: {issue_type}
        """

        embedding = await self.embedding_client.embed(content)

        async with self._pool.acquire() as conn:
            row = await conn.fetchrow("""
                INSERT INTO runbook_embeddings
                    (runbook_id, name, description, issue_type, content,
                     embedding, file_path, metadata)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                ON CONFLICT (runbook_id) DO UPDATE SET
                    name = EXCLUDED.name,
                    description = EXCLUDED.description,
                    issue_type = EXCLUDED.issue_type,
                    content = EXCLUDED.content,
                    embedding = EXCLUDED.embedding,
                    file_path = EXCLUDED.file_path,
                    metadata = EXCLUDED.metadata
                RETURNING id;
            """, runbook_id, name, description, issue_type, content,
                embedding, file_path, metadata or {})

            return str(row["id"])

    async def search_runbooks(
        self,
        query_text: Optional[str] = None,
        query_embedding: Optional[List[float]] = None,
        issue_type: Optional[str] = None,
        top_k: int = 3,
        min_similarity: float = 0.5
    ) -> List[Dict[str, Any]]:
        """Search for applicable runbooks."""
        if query_embedding is None and query_text:
            query_embedding = await self.embedding_client.embed(query_text)
        elif query_embedding is None:
            raise ValueError("Either query_text or query_embedding required")

        conditions = ["active = TRUE"]
        params = [query_embedding, top_k]

        if issue_type:
            conditions.append("issue_type = $3")
            params.append(issue_type)

        where_clause = " AND ".join(conditions)

        async with self._pool.acquire() as conn:
            rows = await conn.fetch(f"""
                SELECT
                    runbook_id, name, description, issue_type, file_path,
                    1 - (embedding <=> $1) as similarity
                FROM runbook_embeddings
                WHERE {where_clause}
                ORDER BY embedding <=> $1
                LIMIT $2;
            """, *params)

        results = []
        for row in rows:
            if row["similarity"] >= min_similarity:
                results.append({
                    "id": row["runbook_id"],
                    "name": row["name"],
                    "description": row["description"],
                    "issue_type": row["issue_type"],
                    "file_path": row["file_path"],
                    "similarity": row["similarity"]
                })

        return results

    # =========================================================================
    # Generic Similarity Search
    # =========================================================================

    async def similarity_search(
        self,
        embedding: List[float],
        collection: str,
        top_k: int = 10,
        filter: Optional[Dict[str, Any]] = None
    ) -> List[SimilarityMatch]:
        """
        Generic similarity search across any collection.

        Args:
            embedding: Query embedding vector
            collection: Collection name (incidents, known_errors, runbooks, knowledge)
            top_k: Number of results
            filter: Optional filters (key-value pairs)

        Returns:
            List of similarity matches
        """
        table_map = {
            "incidents": "incident_embeddings",
            "known_errors": "known_error_embeddings",
            "runbooks": "runbook_embeddings",
            "knowledge": "knowledge_embeddings"
        }

        table = table_map.get(collection)
        if not table:
            raise ValueError(f"Unknown collection: {collection}")

        # Build filter conditions
        conditions = []
        params = [embedding, top_k]
        param_idx = 3

        _allowed_filter_columns: Dict[str, set] = {
            "incident_embeddings": {"incident_id", "job_name", "job_type", "status", "error_code"},
            "known_error_embeddings": {"kedb_id", "active"},
            "runbook_embeddings": {"runbook_id", "issue_type", "active"},
            "knowledge_embeddings": {"doc_id", "doc_type", "source"},
        }
        allowed_cols = _allowed_filter_columns.get(table, set())
        if filter:
            for key, value in filter.items():
                if key not in allowed_cols:
                    raise ValueError(f"Filter key {key!r} is not allowed for table {table!r}")
                conditions.append(f"{key} = ${param_idx}")
                params.append(value)
                param_idx += 1

        where_clause = "WHERE " + " AND ".join(conditions) if conditions else ""

        id_column = {
            "incident_embeddings": "incident_id",
            "known_error_embeddings": "kedb_id",
            "runbook_embeddings": "runbook_id",
            "knowledge_embeddings": "doc_id"
        }[table]

        query = f"""
            SELECT
                {id_column} as id,
                content,
                metadata,
                1 - (embedding <=> $1) as similarity
            FROM {table}
            {where_clause}
            ORDER BY embedding <=> $1
            LIMIT $2;
        """

        async with self._pool.acquire() as conn:
            rows = await conn.fetch(query, *params)

        return [
            SimilarityMatch(
                id=row["id"],
                content=row["content"],
                metadata=dict(row["metadata"]) if row["metadata"] else {},
                similarity=row["similarity"],
                collection=collection
            )
            for row in rows
        ]

    # =========================================================================
    # Helper Methods
    # =========================================================================

    def _create_incident_content(
        self,
        job_name: str,
        job_type: str,
        error_message: str,
        error_code: Optional[str] = None
    ) -> str:
        """Create text content for incident embedding."""
        content = f"""
        Job: {job_name}
        Type: {job_type}
        Error Code: {error_code or 'N/A'}
        Error Message: {error_message[:2000]}
        """
        return content.strip()

    async def get_embedding(self, text: str) -> List[float]:
        """Get embedding for text (exposed for external use)."""
        return await self.embedding_client.embed(text)
