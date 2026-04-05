#!/usr/bin/env python
"""
Validate Azure connections for Support Agent.

Run this after setting up Azure components to verify everything works.

Usage:
    python scripts/validate_connections.py
"""
import asyncio
import os
import re
import sys
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def sanitize_message(message: str) -> str:
    """Sanitize potentially sensitive information from messages."""
    # Redact common patterns for API keys, tokens, passwords, connection strings
    patterns = [
        (r'(api[_-]?key[\'"]?\s*[:=]\s*[\'"]?)([^\'")\s]+)', r'\1***REDACTED***'),
        (r'(token[\'"]?\s*[:=]\s*[\'"]?)([^\'")\s]+)', r'\1***REDACTED***'),
        (r'(password[\'"]?\s*[:=]\s*[\'"]?)([^\'")\s]+)', r'\1***REDACTED***'),
        (r'(secret[\'"]?\s*[:=]\s*[\'"]?)([^\'")\s]+)', r'\1***REDACTED***'),
        (r'(postgresql://[^:]+:)([^@]+)(@)', r'\1***REDACTED***\3'),
        (r'(AccountKey=)([^;]+)', r'\1***REDACTED***'),
    ]

    sanitized = message
    for pattern, replacement in patterns:
        sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)

    return sanitized


def print_status(name: str, success: bool, message: str = ""):
    """Print status with color."""
    if success:
        status = "\033[92m✓ PASS\033[0m"
    else:
        status = "\033[91m✗ FAIL\033[0m"

    print(f"  {status}")
    if name:
        sanitized_name = sanitize_message(name)
        print(f"         {sanitized_name}")
    if message:
        # Sanitize the message to avoid logging sensitive information
        sanitized = sanitize_message(message)
        print(f"         {sanitized}")


async def test_settings():
    """Test configuration loading."""
    print("\n1. Configuration")
    print("-" * 40)

    try:
        from src.integrations.config import get_settings
        settings = get_settings()

        print_status("Settings loaded", True)
        print(f"         Environment: {settings.environment}")

        # Check required settings
        required = [
            ("Azure OpenAI endpoint", settings.azure_openai_endpoint),
            ("Azure OpenAI access", settings.azure_openai_api_key),
            ("Database connection", settings.database_url),
            ("Databricks workspace", settings.databricks_host),
            ("Databricks access", settings.databricks_token),
        ]

        all_set = True
        for name, value in required:
            is_set = bool(value)
            if not is_set:
                print_status(f"  {name}", False, "Not configured")
                all_set = False

        if all_set:
            print_status("All required settings", True)

        return all_set

    except Exception as e:
        print_status("Settings", False, str(e))
        return False


async def test_azure_openai():
    """Test Azure OpenAI connection."""
    print("\n2. Azure OpenAI")
    print("-" * 40)

    try:
        from src.integrations.llm_client import get_llm_client

        client = get_llm_client()
        print_status("Client initialized", True)

        # Test chat completion
        response = await client.chat_completion(
            messages=[{"role": "user", "content": "Say 'Hello, Support Agent!' in exactly those words."}],
            max_tokens=50
        )

        if response and "Hello" in response:
            print_status("Chat completion", True, f"Response: {response[:60]}...")
        else:
            print_status("Chat completion", False, f"Unexpected response: {response[:60]}...")
            return False

        return True

    except Exception as e:
        print_status("Azure OpenAI", False, str(e))
        return False


async def test_embeddings():
    """Test embedding generation."""
    print("\n3. Embeddings")
    print("-" * 40)

    try:
        from src.integrations.llm_client import get_embedding_client

        client = get_embedding_client()
        print_status("Embedding client initialized", True)

        # Test embedding
        embedding = await client.embed_text("Test incident: OutOfMemoryError in Spark job")

        if embedding and len(embedding) == 3072:
            print_status("Embedding generation", True, f"Dimension: {len(embedding)}")
        elif embedding:
            print_status("Embedding generation", False, f"Wrong dimension: {len(embedding)} (expected 3072)")
            return False
        else:
            print_status("Embedding generation", False, "No embedding returned")
            return False

        return True

    except Exception as e:
        print_status("Embeddings", False, str(e))
        return False


async def test_database():
    """Test PostgreSQL connection."""
    print("\n4. PostgreSQL Database")
    print("-" * 40)

    try:
        from src.storage.database import get_database_pool

        pool = await get_database_pool()
        print_status("Connection pool created", True)

        # Test query
        async with pool.acquire() as conn:
            result = await conn.fetchval("SELECT version()")
            print_status("Database query", True, f"PostgreSQL {result.split()[1] if result else 'unknown'}")

            # Check pgvector extension
            ext_result = await conn.fetchval(
                "SELECT EXISTS(SELECT 1 FROM pg_extension WHERE extname = 'vector')"
            )
            if ext_result:
                print_status("pgvector extension", True)
            else:
                print_status("pgvector extension", False, "Extension not installed")
                return False

        return True

    except Exception as e:
        print_status("Database", False, str(e))
        return False


async def test_azure_search():
    """Test Azure AI Search connection."""
    print("\n5. Azure AI Search")
    print("-" * 40)

    try:
        from src.integrations.config import get_settings
        settings = get_settings()

        if not settings.azure_ai_search_endpoint:
            print_status("Azure AI Search", False, "Not configured (optional)")
            return True  # Optional component

        from src.storage.search_client import get_search_client

        client = await get_search_client()
        print_status("Search client initialized", True)

        # Try a simple search
        results = await client.search("test query", top=1)
        print_status("Search query", True, f"Index accessible")

        return True

    except Exception as e:
        error_msg = str(e)
        if "index" in error_msg.lower() and "not found" in error_msg.lower():
            print_status("Azure AI Search", True, "Connected (index will be created on first use)")
            return True
        print_status("Azure AI Search", False, str(e))
        return False


async def test_databricks():
    """Test Databricks connection."""
    print("\n6. Databricks")
    print("-" * 40)

    try:
        from src.integrations.databricks_client import get_databricks_client

        client = get_databricks_client()
        print_status("Client initialized", True)

        # List clusters
        clusters = await client.list_clusters()
        print_status("List clusters", True, f"Found {len(clusters)} clusters")

        # List jobs
        jobs = await client.list_jobs(limit=5)
        print_status("List jobs", True, f"Found {len(jobs)} jobs")

        return True

    except Exception as e:
        print_status("Databricks", False, str(e))
        return False


async def test_langsmith():
    """Test LangSmith connection (optional)."""
    print("\n7. LangSmith (Optional)")
    print("-" * 40)

    try:
        from src.observability import get_langsmith

        ls = get_langsmith()

        if not ls.enabled:
            print_status("LangSmith", True, "Not configured (optional)")
            return True

        print_status("LangSmith enabled", True, f"Project: {os.getenv('LANGCHAIN_PROJECT', 'default')}")
        return True

    except Exception as e:
        print_status("LangSmith", False, str(e))
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
