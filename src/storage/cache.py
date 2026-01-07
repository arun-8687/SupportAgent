"""
Cache backends for rate limiting and session management.

Supports:
- In-memory (single instance, development)
- PostgreSQL (multi-instance, production without Redis)
"""
import time
from abc import ABC, abstractmethod
from typing import Dict, List, Optional
from datetime import datetime, timedelta
import asyncio

import structlog

logger = structlog.get_logger()


class CacheBackend(ABC):
    """Abstract cache backend interface."""

    @abstractmethod
    async def rate_limit_check(
        self,
        key: str,
        limit: int,
        window_seconds: int = 60
    ) -> bool:
        """
        Check if request is within rate limit.

        Returns True if allowed, False if rate limited.
        """
        pass

    @abstractmethod
    async def get(self, key: str) -> Optional[str]:
        """Get a cached value."""
        pass

    @abstractmethod
    async def set(
        self,
        key: str,
        value: str,
        ttl_seconds: Optional[int] = None
    ) -> None:
        """Set a cached value with optional TTL."""
        pass

    @abstractmethod
    async def delete(self, key: str) -> None:
        """Delete a cached value."""
        pass


class InMemoryCache(CacheBackend):
    """
    In-memory cache for single-instance deployments.

    Note: Data is not shared across instances and is lost on restart.
    Suitable for development and single-instance production.
    """

    def __init__(self):
        self._rate_limits: Dict[str, List[float]] = {}
        self._cache: Dict[str, tuple] = {}  # (value, expiry_time)
        self._lock = asyncio.Lock()

    async def rate_limit_check(
        self,
        key: str,
        limit: int,
        window_seconds: int = 60
    ) -> bool:
        """Check rate limit using sliding window."""
        async with self._lock:
            now = time.time()
            window_start = now - window_seconds

            if key not in self._rate_limits:
                self._rate_limits[key] = []

            # Clean old entries
            self._rate_limits[key] = [
                t for t in self._rate_limits[key] if t > window_start
            ]

            if len(self._rate_limits[key]) >= limit:
                return False

            self._rate_limits[key].append(now)
            return True

    async def get(self, key: str) -> Optional[str]:
        """Get cached value if not expired."""
        if key in self._cache:
            value, expiry = self._cache[key]
            if expiry is None or time.time() < expiry:
                return value
            # Expired, clean up
            del self._cache[key]
        return None

    async def set(
        self,
        key: str,
        value: str,
        ttl_seconds: Optional[int] = None
    ) -> None:
        """Set cached value with optional TTL."""
        expiry = time.time() + ttl_seconds if ttl_seconds else None
        self._cache[key] = (value, expiry)

    async def delete(self, key: str) -> None:
        """Delete cached value."""
        self._cache.pop(key, None)


class PostgreSQLCache(CacheBackend):
    """
    PostgreSQL-based cache for multi-instance deployments.

    Uses a dedicated cache table in PostgreSQL for shared state.
    Suitable for ASE deployments without Redis.
    """

    def __init__(self, pool):
        """
        Initialize with a database connection pool.

        Args:
            pool: asyncpg connection pool
        """
        self.pool = pool

    async def initialize(self) -> None:
        """Create cache tables if they don't exist."""
        async with self.pool.acquire() as conn:
            # Rate limit tracking table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS cache_rate_limits (
                    key VARCHAR(255) NOT NULL,
                    request_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    PRIMARY KEY (key, request_time)
                )
            """)

            # Create index for efficient cleanup
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_rate_limits_time
                ON cache_rate_limits (request_time)
            """)

            # General cache table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS cache_entries (
                    key VARCHAR(255) PRIMARY KEY,
                    value TEXT NOT NULL,
                    expires_at TIMESTAMPTZ,
                    created_at TIMESTAMPTZ DEFAULT NOW()
                )
            """)

            # Index for expiry cleanup
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_cache_expires
                ON cache_entries (expires_at)
                WHERE expires_at IS NOT NULL
            """)

            logger.info("postgresql_cache_initialized")

    async def rate_limit_check(
        self,
        key: str,
        limit: int,
        window_seconds: int = 60
    ) -> bool:
        """Check rate limit using PostgreSQL."""
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                # Clean old entries for this key
                await conn.execute("""
                    DELETE FROM cache_rate_limits
                    WHERE key = $1
                    AND request_time < NOW() - INTERVAL '1 second' * $2
                """, key, window_seconds)

                # Count current requests
                count = await conn.fetchval("""
                    SELECT COUNT(*) FROM cache_rate_limits
                    WHERE key = $1
                    AND request_time > NOW() - INTERVAL '1 second' * $2
                """, key, window_seconds)

                if count >= limit:
                    return False

                # Record this request
                await conn.execute("""
                    INSERT INTO cache_rate_limits (key, request_time)
                    VALUES ($1, NOW())
                """, key)

                return True

    async def get(self, key: str) -> Optional[str]:
        """Get cached value from PostgreSQL."""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("""
                SELECT value FROM cache_entries
                WHERE key = $1
                AND (expires_at IS NULL OR expires_at > NOW())
            """, key)

            if row:
                return row["value"]
            return None

    async def set(
        self,
        key: str,
        value: str,
        ttl_seconds: Optional[int] = None
    ) -> None:
        """Set cached value in PostgreSQL."""
        async with self.pool.acquire() as conn:
            expires_at = None
            if ttl_seconds:
                expires_at = datetime.utcnow() + timedelta(seconds=ttl_seconds)

            await conn.execute("""
                INSERT INTO cache_entries (key, value, expires_at)
                VALUES ($1, $2, $3)
                ON CONFLICT (key) DO UPDATE
                SET value = $2, expires_at = $3
            """, key, value, expires_at)

    async def delete(self, key: str) -> None:
        """Delete cached value from PostgreSQL."""
        async with self.pool.acquire() as conn:
            await conn.execute("""
                DELETE FROM cache_entries WHERE key = $1
            """, key)

    async def cleanup_expired(self) -> int:
        """
        Clean up expired cache entries and old rate limit records.

        Returns number of entries cleaned up.
        Call this periodically (e.g., every 5 minutes).
        """
        async with self.pool.acquire() as conn:
            # Clean expired cache entries
            result1 = await conn.execute("""
                DELETE FROM cache_entries
                WHERE expires_at IS NOT NULL AND expires_at < NOW()
            """)

            # Clean old rate limit entries (older than 5 minutes)
            result2 = await conn.execute("""
                DELETE FROM cache_rate_limits
                WHERE request_time < NOW() - INTERVAL '5 minutes'
            """)

            count1 = int(result1.split()[-1]) if result1 else 0
            count2 = int(result2.split()[-1]) if result2 else 0

            if count1 > 0 or count2 > 0:
                logger.info(
                    "cache_cleanup_completed",
                    expired_entries=count1,
                    old_rate_limits=count2
                )

            return count1 + count2


# Factory function
_cache_instance: Optional[CacheBackend] = None


async def get_cache(backend: str = "memory", pool=None) -> CacheBackend:
    """
    Get or create cache instance.

    Args:
        backend: "memory" or "postgresql"
        pool: Required for postgresql backend

    Returns:
        CacheBackend instance
    """
    global _cache_instance

    if _cache_instance is not None:
        return _cache_instance

    if backend == "postgresql":
        if pool is None:
            raise ValueError("PostgreSQL cache requires a connection pool")
        _cache_instance = PostgreSQLCache(pool)
        await _cache_instance.initialize()
    else:
        _cache_instance = InMemoryCache()

    return _cache_instance


def reset_cache() -> None:
    """Reset cache instance (for testing)."""
    global _cache_instance
    _cache_instance = None
