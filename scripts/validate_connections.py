#!/usr/bin/env python
"""
Validate Azure connections for Support Agent.

Run this after setting up Azure components to verify everything works.

Usage:
    python scripts/validate_connections.py
"""
import asyncio
import os
import sys
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def status_label(success: bool) -> str:
    """Return a colored status label."""
    if success:
        return "\033[92m✓ PASS\033[0m"
    return "\033[91m✗ FAIL\033[0m"


async def test_settings():
    """Test configuration loading."""
    print("\n1. Configuration")
    print("-" * 40)

    try:
        from src.integrations.config import get_settings
        settings = get_settings()

        print(f"  {status_label(True)} Settings loaded")
        print(f"         Environment: {settings.environment}")

        all_set = True
        if not settings.azure_openai_endpoint:
            print(f"  {status_label(False)} Azure OpenAI endpoint not configured")
            all_set = False
        if not settings.azure_openai_api_key:
            print(f"  {status_label(False)} Azure OpenAI access not configured")
            all_set = False
        if not settings.database_url:
            print(f"  {status_label(False)} Database connection not configured")
            all_set = False
        if not settings.databricks_host:
            print(f"  {status_label(False)} Databricks workspace not configured")
            all_set = False
        if not settings.databricks_token:
            print(f"  {status_label(False)} Databricks access not configured")
            all_set = False

        if all_set:
            print(f"  {status_label(True)} All required settings")

        return all_set

    except Exception:
        print(f"  {status_label(False)} Settings")
        return False


async def test_azure_openai():
    """Test Azure OpenAI connection."""
    print("\n2. Azure OpenAI")
    print("-" * 40)

    try:
        from src.integrations.llm_client import get_llm_client

        client = get_llm_client()
        print(f"  {status_label(True)} Client initialized")

        # Test chat completion
        response = await client.chat_completion(
            messages=[{"role": "user", "content": "Say 'Hello, Support Agent!' in exactly those words."}],
            max_tokens=50
        )

        if response and "Hello" in response:
            print(f"  {status_label(True)} Chat completion")
        else:
            print(f"  {status_label(False)} Chat completion")
            return False

        return True

    except Exception:
        print(f"  {status_label(False)} Azure OpenAI")
        return False


async def test_embeddings():
    """Test embedding generation."""
    print("\n3. Embeddings")
    print("-" * 40)

    try:
        from src.integrations.llm_client import get_embedding_client

        client = get_embedding_client()
        print(f"  {status_label(True)} Embedding client initialized")

        # Test embedding
        embedding = await client.embed_text("Test incident: OutOfMemoryError in Spark job")

        if embedding and len(embedding) == 3072:
            print(f"  {status_label(True)} Embedding generation")
        elif embedding:
            print(f"  {status_label(False)} Embedding generation")
            return False
        else:
            print(f"  {status_label(False)} Embedding generation")
            return False

        return True

    except Exception:
        print(f"  {status_label(False)} Embeddings")
        return False


async def test_database():
    """Test PostgreSQL connection."""
    print("\n4. PostgreSQL Database")
    print("-" * 40)

    try:
        from src.storage.database import get_database_pool

        pool = await get_database_pool()
        print(f"  {status_label(True)} Connection pool created")

        # Test query
        async with pool.acquire() as conn:
            result = await conn.fetchval("SELECT version()")
            print(f"  {status_label(True)} Database query")

            # Check pgvector extension
            ext_result = await conn.fetchval(
                "SELECT EXISTS(SELECT 1 FROM pg_extension WHERE extname = 'vector')"
            )
            if ext_result:
                print(f"  {status_label(True)} pgvector extension")
            else:
                print(f"  {status_label(False)} pgvector extension")
                return False

        return True

    except Exception:
        print(f"  {status_label(False)} Database")
        return False


async def test_azure_search():
    """Test Azure AI Search connection."""
    print("\n5. Azure AI Search")
    print("-" * 40)

    try:
        from src.integrations.config import get_settings
        settings = get_settings()

        if not settings.azure_ai_search_endpoint:
            print(f"  {status_label(False)} Azure AI Search")
            return True  # Optional component

        from src.storage.search_client import get_search_client

        client = await get_search_client()
        print(f"  {status_label(True)} Search client initialized")

        # Try a simple search
        results = await client.search("test query", top=1)
        print(f"  {status_label(True)} Search query")

        return True

    except Exception as e:
        error_msg = str(e)
        if "index" in error_msg.lower() and "not found" in error_msg.lower():
            print(f"  {status_label(True)} Azure AI Search")
            return True
        print(f"  {status_label(False)} Azure AI Search")
        return False


async def test_databricks():
    """Test Databricks connection."""
    print("\n6. Databricks")
    print("-" * 40)

    try:
        from src.integrations.databricks_client import get_databricks_client

        client = get_databricks_client()
        print(f"  {status_label(True)} Client initialized")

        # List clusters
        clusters = await client.list_clusters()
        print(f"  {status_label(True)} List clusters")

        # List jobs
        jobs = await client.list_jobs(limit=5)
        print(f"  {status_label(True)} List jobs")

        return True

    except Exception:
        print(f"  {status_label(False)} Databricks")
        return False


async def test_langsmith():
    """Test LangSmith connection (optional)."""
    print("\n7. LangSmith (Optional)")
    print("-" * 40)

    try:
        from src.observability import get_langsmith

        ls = get_langsmith()

        if not ls.enabled:
            print(f"  {status_label(True)} LangSmith")
            return True

        print(f"  {status_label(True)} LangSmith enabled")
        return True

    except Exception:
        print(f"  {status_label(False)} LangSmith")
        return True  # Optional, don't fail


async def main():
    """Run all connection tests."""
    print("=" * 50)
    print("Support Agent - Connection Validation")
    print(f"Time: {datetime.now().isoformat()}")
    print("=" * 50)

    results = {}

    # Run tests
    results["settings"] = await test_settings()

    if results["settings"]:
        results["openai"] = await test_azure_openai()
        results["embeddings"] = await test_embeddings()
        results["database"] = await test_database()
        results["search"] = await test_azure_search()
        results["databricks"] = await test_databricks()
        results["langsmith"] = await test_langsmith()

    # Summary
    print("\n" + "=" * 50)
    print("Summary")
    print("=" * 50)

    passed = sum(1 for v in results.values() if v)
    total = len(results)

    print(f"\n  Tests passed: {passed}/{total}")

    if passed == total:
        print("\n  \033[92m✓ All connections validated successfully!\033[0m")
        print("  You can now start the API with: uvicorn src.api.main:app --reload")
        return 0
    else:
        failed = [k for k, v in results.items() if not v]
        print(f"\n  \033[91m✗ Failed: {', '.join(failed)}\033[0m")
        print("  Please check your .env configuration")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
