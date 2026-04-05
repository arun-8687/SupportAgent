"""
Real PostgreSQL + pgvector integration.

Production-ready database layer with:
- Connection pooling
- Retry logic
- Health checks
- Proper error handling
"""
import asyncio
import json
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4

import asyncpg
import structlog
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type
)

from src.integrations.config import get_settings

logger = structlog.get_logger()


class DatabaseError(Exception):
    """Base database error."""
    pass


class ConnectionError(DatabaseError):
    """Database connection error."""
    pass


class QueryError(DatabaseError):
    """Query execution error."""
    pass


class DatabasePool:
    """
    Managed PostgreSQL connection pool with health checks.
    """

    def __init__(
        self,
        dsn: Optional[str] = None,
        min_connections: int = 5,
        max_connections: int = 20,
        command_timeout: float = 30.0
    ):
        self.dsn = dsn or get_settings().database_url
        self.min_connections = min_connections
        self.max_connections = max_connections
        self.command_timeout = command_timeout
        self._pool: Optional[asyncpg.Pool] = None
        self._initialized = False

    async def initialize(self) -> None:
        """Initialize the connection pool."""
        if self._initialized:
            return

        try:
            self._pool = await asyncpg.create_pool(
                self.dsn,
                min_size=self.min_connections,
                max_size=self.max_connections,
                command_timeout=self.command_timeout,
                # Enable pgvector extension
                init=self._init_connection
            )
            self._initialized = True
            logger.info(
                "database_pool_initialized",
                min_connections=self.min_connections,
                max_connections=self.max_connections
            )
        except Exception as e:
            logger.error("database_pool_init_failed", error=str(e))
            raise ConnectionError(f"Failed to initialize database pool: {e}")

    async def _init_connection(self, conn: asyncpg.Connection) -> None:
        """Initialize each connection with pgvector support."""
        await conn.execute("CREATE EXTENSION IF NOT EXISTS vector")
        # Register vector type
        await conn.set_type_codec(
            'vector',
            encoder=lambda v: f'[{",".join(map(str, v))}]',
            decoder=lambda v: [float(x) for x in v.strip('[]').split(',')],
            schema='public'
        )

    async def close(self) -> None:
        """Close the connection pool."""
        if self._pool:
            await self._pool.close()
            self._initialized = False
            logger.info("database_pool_closed")

    @asynccontextmanager
    async def acquire(self):
        """Acquire a connection from the pool."""
        if not self._initialized:
            await self.initialize()

        async with self._pool.acquire() as conn:
            yield conn

    async def health_check(self) -> Dict[str, Any]:
        """Check database health."""
        try:
            async with self.acquire() as conn:
                result = await conn.fetchval("SELECT 1")
                pool_size = self._pool.get_size()
                pool_free = self._pool.get_idle_size()

                return {
                    "healthy": True,
                    "pool_size": pool_size,
                    "pool_free": pool_free,
                    "pool_used": pool_size - pool_free
                }
        except Exception as e:
            return {
                "healthy": False,
                "error": str(e)
            }


class VectorStore:
    """
    Production-ready vector store with pgvector.

    Features:
    - Semantic similarity search
    - Incident storage and retrieval
    - Knowledge base management
    - Proper indexing for performance
    """

    def __init__(self, pool: Optional[DatabasePool] = None):
        self.pool = pool or DatabasePool()
        self._tables_created = False

    async def initialize(self) -> None:
        """Initialize vector store tables."""
        await self.pool.initialize()

        if self._tables_created:
            return

        async with self.pool.acquire() as conn:
            # Create tables
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    incident_id VARCHAR(100) UNIQUE NOT NULL,
                    job_name VARCHAR(255) NOT NULL,
                    job_type VARCHAR(50) NOT NULL,
                    source_system VARCHAR(100),
                    environment VARCHAR(20),
                    error_message TEXT,
                    error_code VARCHAR(100),
                    stack_trace TEXT,
                    failure_timestamp TIMESTAMPTZ,

                    -- Classification
                    category VARCHAR(50),
                    severity VARCHAR(10),

                    -- Resolution
                    status VARCHAR(50) DEFAULT 'open',
                    resolution_summary TEXT,
                    resolution_verified BOOLEAN DEFAULT FALSE,
                    resolved_at TIMESTAMPTZ,

                    -- Vector embedding
                    embedding vector(1536),

                    -- Metadata
                    metadata JSONB DEFAULT '{}',
                    created_at TIMESTAMPTZ DEFAULT NOW(),
                    updated_at TIMESTAMPTZ DEFAULT NOW()
                )
            """)

            await conn.execute("""
                CREATE TABLE IF NOT EXISTS known_errors (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    error_id VARCHAR(100) UNIQUE NOT NULL,
                    title VARCHAR(500) NOT NULL,
                    error_pattern TEXT NOT NULL,
                    root_cause TEXT,
                    workaround TEXT,
                    permanent_fix TEXT,

                    -- Matching
                    embedding vector(1536),
                    keywords TEXT[],

                    -- Metadata
                    job_types TEXT[],
                    active BOOLEAN DEFAULT TRUE,
                    success_count INTEGER DEFAULT 0,
                    failure_count INTEGER DEFAULT 0,

                    created_at TIMESTAMPTZ DEFAULT NOW(),
                    updated_at TIMESTAMPTZ DEFAULT NOW()
                )
            """)

            await conn.execute("""
                CREATE TABLE IF NOT EXISTS runbooks (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    runbook_id VARCHAR(100) UNIQUE NOT NULL,
                    name VARCHAR(255) NOT NULL,
                    description TEXT,
                    content TEXT NOT NULL,

                    -- Matching
                    embedding vector(1536),
                    triggers JSONB,

                    -- Metadata
                    job_types TEXT[],
                    version VARCHAR(20),
                    active BOOLEAN DEFAULT TRUE,
                    execution_count INTEGER DEFAULT 0,
                    success_rate FLOAT DEFAULT 0.0,

                    created_at TIMESTAMPTZ DEFAULT NOW(),
                    updated_at TIMESTAMPTZ DEFAULT NOW()
                )
            """)

            await conn.execute("""
                CREATE TABLE IF NOT EXISTS incident_history (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    incident_id VARCHAR(100) NOT NULL,
                    action VARCHAR(100) NOT NULL,
                    action_params JSONB,
                    result JSONB,
                    cost_usd FLOAT DEFAULT 0.0,

                    -- Audit
                    performed_by VARCHAR(100) DEFAULT 'system',
                    performed_at TIMESTAMPTZ DEFAULT NOW()
                )
            """)

            await conn.execute("""
                CREATE TABLE IF NOT EXISTS circuit_breaker_state (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    key VARCHAR(500) UNIQUE NOT NULL,
                    failure_count INTEGER DEFAULT 0,
                    last_failure_at TIMESTAMPTZ,
                    circuit_opened_at TIMESTAMPTZ,
                    state VARCHAR(20) DEFAULT 'closed',

                    updated_at TIMESTAMPTZ DEFAULT NOW()
                )
            """)

            # Create indexes for performance
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_incidents_job_name
                ON incidents(job_name)
            """)

            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_incidents_created_at
                ON incidents(created_at DESC)
            """)

            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_incidents_status
                ON incidents(status)
            """)

            # Vector similarity indexes (IVFFlat for approximate search)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_incidents_embedding
                ON incidents USING ivfflat (embedding vector_cosine_ops)
                WITH (lists = 100)
            """)

            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_known_errors_embedding
                ON known_errors USING ivfflat (embedding vector_cosine_ops)
                WITH (lists = 50)
            """)

            self._tables_created = True
            logger.info("vector_store_tables_created")

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        retry=retry_if_exception_type(asyncpg.PostgresConnectionError)
    )
    async def store_incident(
        self,
        incident_id: str,
        job_name: str,
        job_type: str,
        error_message: str,
        embedding: List[float],
        **kwargs
    ) -> str:
        """Store an incident with its embedding."""
        async with self.pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO incidents (
                    incident_id, job_name, job_type, error_message, embedding,
                    source_system, environment, error_code, stack_trace,
                    failure_timestamp, category, severity, metadata
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
                ON CONFLICT (incident_id) DO UPDATE SET
                    error_message = EXCLUDED.error_message,
                    embedding = EXCLUDED.embedding,
                    updated_at = NOW()
            """,
                incident_id,
                job_name,
                job_type,
                error_message,
                embedding,
                kwargs.get('source_system'),
                kwargs.get('environment'),
                kwargs.get('error_code'),
                kwargs.get('stack_trace'),
                kwargs.get('failure_timestamp'),
                kwargs.get('category'),
                kwargs.get('severity'),
                json.dumps(kwargs.get('metadata', {}))
            )

            logger.info("incident_stored", incident_id=incident_id)
            return incident_id

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        retry=retry_if_exception_type(asyncpg.PostgresConnectionError)
    )
    async def find_similar_incidents(
        self,
        embedding: List[float],
        limit: int = 10,
        threshold: float = 0.7,
        job_type: Optional[str] = None,
        exclude_incident_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Find similar incidents using vector similarity."""
        async with self.pool.acquire() as conn:
            query = """
                SELECT
                    incident_id,
                    job_name,
                    job_type,
                    error_message,
                    resolution_summary,
                    resolution_verified,
                    status,
                    1 - (embedding <=> $1) as similarity
                FROM incidents
                WHERE embedding IS NOT NULL
                AND 1 - (embedding <=> $1) > $2
            """
            params = [embedding, threshold]
            param_idx = 3

            if job_type:
                query += f" AND job_type = ${param_idx}"
                params.append(job_type)
                param_idx += 1

            if exclude_incident_id:
                query += f" AND incident_id != ${param_idx}"
                params.append(exclude_incident_id)
                param_idx += 1

            query += f" ORDER BY similarity DESC LIMIT ${param_idx}"
            params.append(limit)

            rows = await conn.fetch(query, *params)

            return [dict(row) for row in rows]

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        retry=retry_if_exception_type(asyncpg.PostgresConnectionError)
    )
    async def get_recent_incidents(
        self,
        job_name: Optional[str] = None,
        time_window_minutes: int = 15,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """Get recent incidents for deduplication."""
        async with self.pool.acquire() as conn:
            time_window_minutes = int(time_window_minutes)
            limit = int(limit)
            query = f"""
                SELECT
                    incident_id,
                    job_name,
                    job_type,
                    error_message,
                    error_code,
                    created_at
                FROM incidents
                WHERE created_at > NOW() - INTERVAL '{time_window_minutes} minutes'
            """

            params = []

            if job_name:
                query += " AND job_name = $1"
                params.append(job_name)

            query += f" ORDER BY created_at DESC LIMIT {limit}"

            rows = await conn.fetch(query, *params)
            return [dict(row) for row in rows]

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        retry=retry_if_exception_type(asyncpg.PostgresConnectionError)
    )
    async def search_known_errors(
        self,
        embedding: List[float],
        limit: int = 5,
        threshold: float = 0.75,
        job_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Search known error database."""
        async with self.pool.acquire() as conn:
            query = """
                SELECT
                    error_id,
                    title,
                    error_pattern,
                    root_cause,
                    workaround,
                    permanent_fix,
                    success_count,
                    1 - (embedding <=> $1) as match_confidence
                FROM known_errors
                WHERE active = TRUE
                AND embedding IS NOT NULL
                AND 1 - (embedding <=> $1) > $2
            """
            params = [embedding, threshold]

            if job_type:
                query += " AND $3 = ANY(job_types)"
                params.append(job_type)

            query += " ORDER BY match_confidence DESC LIMIT $%d" % (len(params) + 1)
            params.append(limit)

            rows = await conn.fetch(query, *params)
            return [dict(row) for row in rows]

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        retry=retry_if_exception_type(asyncpg.PostgresConnectionError)
    )
    async def search_runbooks(
        self,
        embedding: List[float],
        limit: int = 3,
        threshold: float = 0.6,
        job_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Search for applicable runbooks."""
        async with self.pool.acquire() as conn:
            query = """
                SELECT
                    runbook_id,
                    name,
                    description,
                    content,
                    triggers,
                    success_rate,
                    1 - (embedding <=> $1) as relevance
                FROM runbooks
                WHERE active = TRUE
                AND embedding IS NOT NULL
                AND 1 - (embedding <=> $1) > $2
            """
            params = [embedding, threshold]

            if job_type:
                query += " AND $3 = ANY(job_types)"
                params.append(job_type)

            query += " ORDER BY relevance DESC, success_rate DESC LIMIT $%d" % (len(params) + 1)
            params.append(limit)

            rows = await conn.fetch(query, *params)
            return [dict(row) for row in rows]

    async def update_incident_resolution(
        self,
        incident_id: str,
        resolution_summary: str,
        resolution_verified: bool = False
    ) -> None:
        """Update incident with resolution."""
        async with self.pool.acquire() as conn:
            await conn.execute("""
                UPDATE incidents
                SET
                    status = 'resolved',
                    resolution_summary = $2,
                    resolution_verified = $3,
                    resolved_at = NOW(),
                    updated_at = NOW()
                WHERE incident_id = $1
            """, incident_id, resolution_summary, resolution_verified)

            logger.info(
                "incident_resolution_updated",
                incident_id=incident_id,
                verified=resolution_verified
            )

    async def record_incident_action(
        self,
        incident_id: str,
        action: str,
        action_params: Optional[Dict] = None,
        result: Optional[Dict] = None,
        cost_usd: float = 0.0,
        performed_by: str = "system"
    ) -> None:
        """Record an action taken for an incident (audit trail)."""
        async with self.pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO incident_history (
                    incident_id, action, action_params, result, cost_usd, performed_by
                ) VALUES ($1, $2, $3, $4, $5, $6)
            """,
                incident_id,
                action,
                json.dumps(action_params or {}),
                json.dumps(result or {}),
                cost_usd,
                performed_by
            )

    async def get_incident_history(
        self,
        incident_id: str
    ) -> List[Dict[str, Any]]:
        """Get full action history for an incident."""
        async with self.pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT action, action_params, result, cost_usd, performed_by, performed_at
                FROM incident_history
                WHERE incident_id = $1
                ORDER BY performed_at ASC
            """, incident_id)

            return [dict(row) for row in rows]


class PersistentCircuitBreaker:
    """
    Circuit breaker with persistent state in PostgreSQL.

    Survives restarts and works across multiple instances.
    """

    def __init__(
        self,
        pool: DatabasePool,
        threshold: int = 5,
        window_minutes: int = 30,
        cooldown_minutes: int = 60
    ):
        self.pool = pool
        self.threshold = threshold
        self.window = timedelta(minutes=window_minutes)
        self.cooldown = timedelta(minutes=cooldown_minutes)

    def _make_key(self, job_name: str, error_pattern: str) -> str:
        """Create a unique key for job+error combination."""
        return f"{job_name}::{error_pattern[:100]}"

    async def record_failure(self, job_name: str, error_pattern: str) -> None:
        """Record a failure."""
        key = self._make_key(job_name, error_pattern)
        now = datetime.utcnow()

        async with self.pool.acquire() as conn:
            # Upsert failure count
            window_minutes = int(self.window.total_seconds() // 60)
            await conn.execute(f"""
                INSERT INTO circuit_breaker_state (key, failure_count, last_failure_at, updated_at)
                VALUES ($1, 1, $2, $2)
                ON CONFLICT (key) DO UPDATE SET
                    failure_count = CASE
                        WHEN circuit_breaker_state.last_failure_at < NOW() - INTERVAL '{window_minutes} minutes'
                        THEN 1
                        ELSE circuit_breaker_state.failure_count + 1
                    END,
                    last_failure_at = $2,
                    updated_at = $2
            """, key, now)

            # Check if we should open the circuit
            row = await conn.fetchrow("""
                SELECT failure_count FROM circuit_breaker_state WHERE key = $1
            """, key)

            if row and row['failure_count'] >= self.threshold:
                await conn.execute("""
                    UPDATE circuit_breaker_state
                    SET state = 'open', circuit_opened_at = $2
                    WHERE key = $1
                """, key, now)

                logger.warning(
                    "circuit_breaker_opened",
                    job_name=job_name,
                    failure_count=row['failure_count']
                )

    async def is_open(self, job_name: str, error_pattern: str) -> bool:
        """Check if circuit is open."""
        key = self._make_key(job_name, error_pattern)
        now = datetime.utcnow()

        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("""
                SELECT state, circuit_opened_at FROM circuit_breaker_state WHERE key = $1
            """, key)

            if not row or row['state'] != 'open':
                return False

            # Check if cooldown has passed
            if row['circuit_opened_at'] and now - row['circuit_opened_at'] > self.cooldown:
                await conn.execute("""
                    UPDATE circuit_breaker_state
                    SET state = 'half-open', updated_at = $2
                    WHERE key = $1
                """, key, now)
                return False

            return True

    async def record_success(self, job_name: str, error_pattern: str) -> None:
        """Record success - reset circuit."""
        key = self._make_key(job_name, error_pattern)

        async with self.pool.acquire() as conn:
            await conn.execute("""
                UPDATE circuit_breaker_state
                SET state = 'closed', failure_count = 0, circuit_opened_at = NULL, updated_at = NOW()
                WHERE key = $1
            """, key)


# Singleton instance
_db_pool: Optional[DatabasePool] = None
_vector_store: Optional[VectorStore] = None


async def get_database_pool() -> DatabasePool:
    """Get the database pool singleton."""
    global _db_pool
    if _db_pool is None:
        _db_pool = DatabasePool()
        await _db_pool.initialize()
    return _db_pool


async def get_vector_store() -> VectorStore:
    """Get the vector store singleton."""
    global _vector_store
    if _vector_store is None:
        pool = await get_database_pool()
        _vector_store = VectorStore(pool)
        await _vector_store.initialize()
    return _vector_store
