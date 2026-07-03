"""
LLM access layer.

Provides structured-output generation backed by Azure OpenAI / OpenAI when
configured. When no LLM is configured (local dev, CI), callers supply a
deterministic heuristic fallback so the whole workflow remains runnable
offline — the same investigation flow, minus generative reasoning.
"""
import logging
from typing import Callable, Optional, Type, TypeVar

from pydantic import BaseModel

from sre_agent.config import get_settings

logger = logging.getLogger(__name__)

TModel = TypeVar("TModel", bound=BaseModel)

_chat_model = None
_chat_model_initialized = False


def get_chat_model():
    """Return a LangChain chat model, or None if not configured."""
    global _chat_model, _chat_model_initialized
    if _chat_model_initialized:
        return _chat_model

    _chat_model_initialized = True
    settings = get_settings()

    try:
        if settings.azure_openai_endpoint and settings.azure_openai_api_key:
            from langchain_openai import AzureChatOpenAI

            _chat_model = AzureChatOpenAI(
                azure_endpoint=settings.azure_openai_endpoint,
                api_key=settings.azure_openai_api_key,
                azure_deployment=settings.azure_openai_deployment,
                api_version=settings.azure_openai_api_version,
                temperature=0,
            )
        elif settings.openai_api_key:
            from langchain_openai import ChatOpenAI

            _chat_model = ChatOpenAI(
                api_key=settings.openai_api_key,
                model=settings.openai_model,
                temperature=0,
            )
    except Exception:  # pragma: no cover - import/config issues
        logger.exception("Failed to initialize chat model; using heuristics")
        _chat_model = None

    return _chat_model


async def generate_structured(
    system_prompt: str,
    user_prompt: str,
    schema: Type[TModel],
    fallback: Callable[[], TModel],
) -> TModel:
    """
    Ask the LLM for a structured response conforming to `schema`.

    Falls back to `fallback()` when no LLM is configured or the call fails,
    so investigations degrade gracefully instead of crashing mid-incident.
    """
    model = get_chat_model()
    if model is None:
        return fallback()

    try:
        structured = model.with_structured_output(schema)
        result = await structured.ainvoke(
            [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ]
        )
        if isinstance(result, schema):
            return result
        return schema.model_validate(result)
    except Exception:
        logger.exception("LLM structured generation failed; using fallback")
        return fallback()


async def generate_text(
    system_prompt: str,
    user_prompt: str,
    fallback: Optional[str] = None,
) -> str:
    """Free-form text generation with graceful fallback."""
    model = get_chat_model()
    if model is None:
        return fallback or ""

    try:
        response = await model.ainvoke(
            [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ]
        )
        return str(response.content)
    except Exception:
        logger.exception("LLM text generation failed; using fallback")
        return fallback or ""
