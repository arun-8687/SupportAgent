"""
Embedding access for semantic retrieval.

Mirrors llm.py's philosophy: a single accessor that returns a working
embedder when Azure OpenAI / OpenAI is configured (and the SDK is
importable), or None otherwise — so every caller degrades gracefully to
keyword search offline and in tests. Embedding calls share the same
bounded-concurrency + retry path as chat calls so an alert storm can't
fan out into unbounded embedding requests.
"""
import logging
from typing import List, Optional

from sre_agent.config import get_settings

logger = logging.getLogger(__name__)

_embedder = None
_embedder_initialized = False


def get_embedder():
    """Return a LangChain embeddings object, or None if unavailable."""
    global _embedder, _embedder_initialized
    if _embedder_initialized:
        return _embedder

    _embedder_initialized = True
    settings = get_settings()
    try:
        if (
            settings.azure_openai_endpoint
            and settings.azure_openai_api_key
            and settings.azure_openai_embedding_deployment
        ):
            from langchain_openai import AzureOpenAIEmbeddings

            _embedder = AzureOpenAIEmbeddings(
                azure_endpoint=settings.azure_openai_endpoint,
                api_key=settings.azure_openai_api_key,
                azure_deployment=settings.azure_openai_embedding_deployment,
                api_version=settings.azure_openai_api_version,
            )
        elif settings.openai_api_key:
            from langchain_openai import OpenAIEmbeddings

            _embedder = OpenAIEmbeddings(
                api_key=settings.openai_api_key,
                model=settings.openai_embedding_model,
            )
    except Exception:  # pragma: no cover - import/config issues
        logger.exception("Failed to initialize embedder; semantic retrieval off")
        _embedder = None
    return _embedder


def reset_for_tests() -> None:
    global _embedder, _embedder_initialized
    _embedder, _embedder_initialized = None, False


def embed_query_sync(text: str) -> Optional[List[float]]:
    """Embed one query string synchronously; None when unavailable.

    Sync so the incident store keeps the same call shape as the keyword
    KnowledgeStore and is safely callable from inside the async graph
    nodes (which already perform blocking I/O). Embedding calls per
    incident are few (one at triage, one per resolution), so bypassing the
    async concurrency gate here is acceptable.
    """
    embedder = get_embedder()
    if embedder is None or not text:
        return None
    try:
        return embedder.embed_query(text)
    except Exception:
        logger.exception("Query embedding failed")
        return None


def embed_texts_sync(texts: List[str]) -> Optional[List[List[float]]]:
    """Embed a batch synchronously (startup rehydrate); None when unavailable."""
    embedder = get_embedder()
    if embedder is None or not texts:
        return None
    try:
        return embedder.embed_documents(texts)
    except Exception:
        logger.exception("Batch embedding failed")
        return None
