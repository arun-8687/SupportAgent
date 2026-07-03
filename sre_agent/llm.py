"""
LLM access layer.

Provides structured-output generation backed by Azure OpenAI / OpenAI when
configured, with three production protections:

  - a global concurrency semaphore so an alert storm can't fan out into
    unbounded parallel LLM calls (SRE_AGENT_LLM_MAX_CONCURRENCY),
  - retry with exponential backoff for transient failures / 429s,
  - strict-mode behavior: in production (or when mock data is disallowed)
    a missing/failed LLM RAISES instead of silently degrading to
    heuristics — a real investigation must never be quietly grounded in
    fallback reasoning.

Outside production the deterministic heuristic fallback keeps the whole
workflow runnable offline (local dev, CI).
"""
import asyncio
import logging
from typing import Callable, Optional, Type, TypeVar

from pydantic import BaseModel

from sre_agent.config import get_settings

logger = logging.getLogger(__name__)

TModel = TypeVar("TModel", bound=BaseModel)

_chat_model = None
_chat_model_initialized = False
_semaphore: Optional[asyncio.Semaphore] = None


class LLMUnavailableError(RuntimeError):
    """No LLM is configured/reachable and mock fallbacks are disallowed."""


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
        logger.exception("Failed to initialize chat model")
        _chat_model = None

    return _chat_model


def _get_semaphore() -> asyncio.Semaphore:
    global _semaphore
    if _semaphore is None:
        _semaphore = asyncio.Semaphore(get_settings().llm_max_concurrency)
    return _semaphore


async def _invoke_with_retry(coro_factory):
    """Bounded-concurrency invoke with exponential backoff on failure."""
    import time

    from sre_agent.observability import log_step, span

    settings = get_settings()
    last_exc: Optional[Exception] = None
    for attempt in range(settings.llm_retry_attempts):
        started = time.monotonic()
        try:
            async with _get_semaphore():
                with span("sre_agent.llm_call", attempt=attempt + 1):
                    result = await coro_factory()
            log_step(
                "llm_call", "succeeded",
                duration_ms=int((time.monotonic() - started) * 1000),
                attempt=attempt + 1,
                level=logging.DEBUG,
            )
            return result
        except Exception as exc:  # includes 429 rate limits
            last_exc = exc
            delay = settings.llm_retry_base_delay_seconds * (2 ** attempt)
            log_step(
                "llm_call", "retrying",
                duration_ms=int((time.monotonic() - started) * 1000),
                attempt=attempt + 1, max_attempts=settings.llm_retry_attempts,
                error=str(exc)[:200], retry_delay_s=delay,
                level=logging.WARNING,
            )
            await asyncio.sleep(delay)
    raise last_exc  # type: ignore[misc]


async def generate_structured(
    system_prompt: str,
    user_prompt: str,
    schema: Type[TModel],
    fallback: Callable[[], TModel],
) -> TModel:
    """
    Ask the LLM for a structured response conforming to `schema`.

    Development: falls back to `fallback()` when no LLM is configured or
    the call ultimately fails. Production/strict: raises
    LLMUnavailableError instead — degraded reasoning must be loud.
    """
    settings = get_settings()
    model = get_chat_model()
    if model is None:
        if not settings.mock_data_allowed:
            raise LLMUnavailableError(
                "No LLM configured and mock fallbacks are disallowed "
                "(SRE_AGENT_ENVIRONMENT=production). Configure Azure OpenAI "
                "or explicitly set SRE_AGENT_ALLOW_MOCK_DATA=true."
            )
        return fallback()

    async def call():
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

    try:
        return await _invoke_with_retry(call)
    except Exception as exc:
        if not settings.mock_data_allowed:
            raise LLMUnavailableError(
                f"LLM structured generation failed after retries: {exc}"
            ) from exc
        logger.exception("LLM structured generation failed; using fallback")
        return fallback()


async def generate_text(
    system_prompt: str,
    user_prompt: str,
    fallback: Optional[str] = None,
) -> str:
    """Free-form text generation with the same strict/dev semantics."""
    settings = get_settings()
    model = get_chat_model()
    if model is None:
        if not settings.mock_data_allowed:
            raise LLMUnavailableError(
                "No LLM configured and mock fallbacks are disallowed."
            )
        return fallback or ""

    async def call():
        response = await model.ainvoke(
            [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ]
        )
        return str(response.content)

    try:
        return await _invoke_with_retry(call)
    except Exception as exc:
        if not settings.mock_data_allowed:
            raise LLMUnavailableError(
                f"LLM text generation failed after retries: {exc}"
            ) from exc
        logger.exception("LLM text generation failed; using fallback")
        return fallback or ""
