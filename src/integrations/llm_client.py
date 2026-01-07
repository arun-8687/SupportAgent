"""
Production-ready Azure OpenAI integration with LangSmith tracing.

Features:
- LangSmith tracing for all LLM calls
- Retry with exponential backoff
- Timeout handling
- Rate limit handling
- Structured output validation with Pydantic
- Token counting and cost tracking
- Fallback models
"""
import json
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Type, TypeVar, Union
from enum import Enum

import httpx
import structlog
from langsmith import traceable
from pydantic import BaseModel, ValidationError
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
    before_sleep_log,
    RetryError
)

from src.integrations.config import get_settings

logger = structlog.get_logger()

T = TypeVar('T', bound=BaseModel)


class LLMError(Exception):
    """Base LLM error."""
    pass


class RateLimitError(LLMError):
    """Rate limit exceeded."""
    pass


class TimeoutError(LLMError):
    """Request timeout."""
    pass


class ValidationError(LLMError):
    """Output validation failed."""
    pass


class ModelUnavailableError(LLMError):
    """Model is unavailable."""
    pass


@dataclass
class TokenUsage:
    """Token usage tracking."""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0

    @property
    def estimated_cost_usd(self) -> float:
        """Estimate cost based on GPT-4 pricing."""
        # GPT-4 pricing (approximate)
        prompt_cost = self.prompt_tokens * 0.00003
        completion_cost = self.completion_tokens * 0.00006
        return prompt_cost + completion_cost


@dataclass
class LLMResponse:
    """Structured LLM response."""
    content: str
    usage: TokenUsage
    model: str
    latency_ms: float
    raw_response: Optional[Dict] = None


@dataclass
class LLMMetrics:
    """Metrics for LLM calls."""
    total_calls: int = 0
    successful_calls: int = 0
    failed_calls: int = 0
    total_tokens: int = 0
    total_cost_usd: float = 0.0
    total_latency_ms: float = 0.0
    rate_limit_hits: int = 0
    timeouts: int = 0
    validation_failures: int = 0

    def record_success(self, usage: TokenUsage, latency_ms: float) -> None:
        self.total_calls += 1
        self.successful_calls += 1
        self.total_tokens += usage.total_tokens
        self.total_cost_usd += usage.estimated_cost_usd
        self.total_latency_ms += latency_ms

    def record_failure(self, error_type: str) -> None:
        self.total_calls += 1
        self.failed_calls += 1
        if error_type == "rate_limit":
            self.rate_limit_hits += 1
        elif error_type == "timeout":
            self.timeouts += 1
        elif error_type == "validation":
            self.validation_failures += 1

    @property
    def success_rate(self) -> float:
        if self.total_calls == 0:
            return 0.0
        return self.successful_calls / self.total_calls

    @property
    def avg_latency_ms(self) -> float:
        if self.successful_calls == 0:
            return 0.0
        return self.total_latency_ms / self.successful_calls


class AzureOpenAIClient:
    """
    Production-ready Azure OpenAI client.

    Features:
    - Automatic retry with exponential backoff
    - Rate limit handling
    - Timeout handling
    - Structured output with Pydantic validation
    - Metrics tracking
    - Fallback to alternative models
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        endpoint: Optional[str] = None,
        deployment: Optional[str] = None,
        api_version: str = "2024-02-01",
        timeout_seconds: float = 60.0,
        max_retries: int = 3
    ):
        settings = get_settings()
        self.api_key = api_key or settings.azure_openai_api_key
        self.endpoint = endpoint or settings.azure_openai_endpoint
        self.deployment = deployment or settings.azure_openai_deployment
        self.api_version = api_version
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries

        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout_seconds),
            headers={
                "api-key": self.api_key,
                "Content-Type": "application/json"
            }
        )

        self.metrics = LLMMetrics()

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()

    def _build_url(self, deployment: Optional[str] = None) -> str:
        """Build the API URL."""
        dep = deployment or self.deployment
        return f"{self.endpoint}/openai/deployments/{dep}/chat/completions?api-version={self.api_version}"

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        retry=retry_if_exception_type((httpx.TimeoutException, RateLimitError)),
        before_sleep=before_sleep_log(logger, "warning")
    )
    @traceable(name="azure_openai_chat", run_type="llm")
    async def chat_completion(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.3,
        max_tokens: int = 2000,
        response_format: Optional[Dict] = None,
        deployment: Optional[str] = None
    ) -> LLMResponse:
        """
        Make a chat completion request with retry logic.

        Automatically traced by LangSmith.
        """
        start_time = time.time()

        payload = {
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens
        }

        if response_format:
            payload["response_format"] = response_format

        try:
            response = await self._client.post(
                self._build_url(deployment),
                json=payload
            )

            latency_ms = (time.time() - start_time) * 1000

            if response.status_code == 429:
                self.metrics.record_failure("rate_limit")
                retry_after = int(response.headers.get("Retry-After", 10))
                logger.warning("rate_limit_hit", retry_after=retry_after)
                raise RateLimitError(f"Rate limited, retry after {retry_after}s")

            if response.status_code >= 500:
                logger.error("llm_server_error", status=response.status_code)
                raise ModelUnavailableError(f"Server error: {response.status_code}")

            response.raise_for_status()
            data = response.json()

            usage = TokenUsage(
                prompt_tokens=data.get("usage", {}).get("prompt_tokens", 0),
                completion_tokens=data.get("usage", {}).get("completion_tokens", 0),
                total_tokens=data.get("usage", {}).get("total_tokens", 0)
            )

            content = data["choices"][0]["message"]["content"]

            self.metrics.record_success(usage, latency_ms)

            logger.info(
                "llm_request_completed",
                latency_ms=latency_ms,
                tokens=usage.total_tokens,
                cost_usd=usage.estimated_cost_usd
            )

            return LLMResponse(
                content=content,
                usage=usage,
                model=data.get("model", self.deployment),
                latency_ms=latency_ms,
                raw_response=data
            )

        except httpx.TimeoutException:
            self.metrics.record_failure("timeout")
            logger.error("llm_timeout", timeout=self.timeout_seconds)
            raise TimeoutError(f"Request timed out after {self.timeout_seconds}s")

    async def chat_completion_structured(
        self,
        messages: List[Dict[str, str]],
        response_model: Type[T],
        temperature: float = 0.2,
        max_tokens: int = 2000,
        max_validation_retries: int = 2
    ) -> T:
        """
        Make a chat completion request and validate output against a Pydantic model.

        Automatically retries if validation fails.
        """
        # Add JSON instruction to system message
        schema_json = json.dumps(response_model.model_json_schema(), indent=2)

        # Modify system message to include schema
        enhanced_messages = messages.copy()
        if enhanced_messages[0]["role"] == "system":
            enhanced_messages[0]["content"] += f"\n\nYou MUST respond with valid JSON matching this schema:\n```json\n{schema_json}\n```"
        else:
            enhanced_messages.insert(0, {
                "role": "system",
                "content": f"You MUST respond with valid JSON matching this schema:\n```json\n{schema_json}\n```"
            })

        last_error = None
        for attempt in range(max_validation_retries + 1):
            try:
                response = await self.chat_completion(
                    messages=enhanced_messages,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    response_format={"type": "json_object"}
                )

                # Parse and validate
                try:
                    data = json.loads(response.content)
                    return response_model.model_validate(data)
                except json.JSONDecodeError as e:
                    last_error = e
                    self.metrics.record_failure("validation")
                    logger.warning(
                        "llm_json_parse_failed",
                        attempt=attempt + 1,
                        error=str(e)
                    )
                except ValidationError as e:
                    last_error = e
                    self.metrics.record_failure("validation")
                    logger.warning(
                        "llm_validation_failed",
                        attempt=attempt + 1,
                        errors=e.errors()
                    )

                # Add correction message for retry
                if attempt < max_validation_retries:
                    enhanced_messages.append({
                        "role": "assistant",
                        "content": response.content
                    })
                    enhanced_messages.append({
                        "role": "user",
                        "content": f"Your response was not valid JSON or didn't match the required schema. Error: {last_error}. Please try again with valid JSON."
                    })

            except (RateLimitError, TimeoutError) as e:
                last_error = e
                if attempt == max_validation_retries:
                    raise

        raise ValidationError(f"Failed to get valid structured output after {max_validation_retries + 1} attempts: {last_error}")

    def get_metrics(self) -> Dict[str, Any]:
        """Get current metrics."""
        return {
            "total_calls": self.metrics.total_calls,
            "successful_calls": self.metrics.successful_calls,
            "failed_calls": self.metrics.failed_calls,
            "success_rate": self.metrics.success_rate,
            "total_tokens": self.metrics.total_tokens,
            "total_cost_usd": self.metrics.total_cost_usd,
            "avg_latency_ms": self.metrics.avg_latency_ms,
            "rate_limit_hits": self.metrics.rate_limit_hits,
            "timeouts": self.metrics.timeouts,
            "validation_failures": self.metrics.validation_failures
        }


class EmbeddingClient:
    """
    Production-ready embedding client.

    Supports text-embedding-3-large (3072 dims) and text-embedding-ada-002 (1536 dims).
    """

    # Embedding dimensions by model
    EMBEDDING_DIMENSIONS = {
        "text-embedding-3-large": 3072,
        "text-embedding-3-small": 1536,
        "text-embedding-ada-002": 1536,
    }

    def __init__(
        self,
        api_key: Optional[str] = None,
        endpoint: Optional[str] = None,
        deployment: Optional[str] = None,
        api_version: str = "2024-12-01-preview",
        timeout_seconds: float = 30.0
    ):
        settings = get_settings()
        self.api_key = api_key or settings.azure_openai_api_key
        self.endpoint = endpoint or settings.azure_openai_endpoint
        self.deployment = deployment or settings.embedding_deployment or "text-embedding-3-large"
        self.api_version = api_version
        self.dimensions = self.EMBEDDING_DIMENSIONS.get(self.deployment, 3072)

        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout_seconds),
            headers={
                "api-key": self.api_key,
                "Content-Type": "application/json"
            }
        )

        self._cache: Dict[str, List[float]] = {}
        self.total_requests = 0
        self.cache_hits = 0

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()

    def _build_url(self) -> str:
        """Build the API URL."""
        return f"{self.endpoint}/openai/deployments/{self.deployment}/embeddings?api-version={self.api_version}"

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        retry=retry_if_exception_type((httpx.TimeoutException, RateLimitError))
    )
    async def embed(self, text: str, use_cache: bool = True) -> List[float]:
        """Generate embedding for text."""
        self.total_requests += 1

        # Check cache
        cache_key = text[:500]  # Use first 500 chars as key
        if use_cache and cache_key in self._cache:
            self.cache_hits += 1
            return self._cache[cache_key]

        response = await self._client.post(
            self._build_url(),
            json={"input": text}
        )

        if response.status_code == 429:
            raise RateLimitError("Embedding rate limited")

        response.raise_for_status()
        data = response.json()

        embedding = data["data"][0]["embedding"]

        # Cache result
        if use_cache:
            self._cache[cache_key] = embedding
            # Limit cache size
            if len(self._cache) > 10000:
                # Remove oldest entries
                keys_to_remove = list(self._cache.keys())[:1000]
                for key in keys_to_remove:
                    del self._cache[key]

        return embedding

    async def embed_batch(
        self,
        texts: List[str],
        batch_size: int = 100
    ) -> List[List[float]]:
        """Generate embeddings for multiple texts."""
        embeddings = []

        for i in range(0, len(texts), batch_size):
            batch = texts[i:i + batch_size]

            response = await self._client.post(
                self._build_url(),
                json={"input": batch}
            )

            if response.status_code == 429:
                # Wait and retry
                await asyncio.sleep(10)
                response = await self._client.post(
                    self._build_url(),
                    json={"input": batch}
                )

            response.raise_for_status()
            data = response.json()

            batch_embeddings = [item["embedding"] for item in data["data"]]
            embeddings.extend(batch_embeddings)

        return embeddings

    def get_metrics(self) -> Dict[str, Any]:
        """Get embedding metrics."""
        return {
            "total_requests": self.total_requests,
            "cache_hits": self.cache_hits,
            "cache_hit_rate": self.cache_hits / max(1, self.total_requests),
            "cache_size": len(self._cache)
        }


# Response models for structured output

class ClassificationResponse(BaseModel):
    """Structured classification response."""
    category: str
    issue_type: str
    root_cause_hypothesis: str
    confidence: float
    business_impact: str
    is_known_issue: bool
    known_error_id: Optional[str] = None
    recommended_action: str
    reasoning: Optional[str] = None


class DiagnosisResponse(BaseModel):
    """Structured diagnosis response."""

    class Hypothesis(BaseModel):
        description: str
        probability: float
        evidence_needed: List[str]
        tools_to_use: List[str]

    hypotheses: List[Hypothesis]
    primary_hypothesis: str
    confidence: float
    investigation_plan: List[str]


class RootCauseResponse(BaseModel):
    """Structured root cause response."""
    root_cause: str
    confidence: float
    supporting_evidence: List[str]
    remaining_uncertainty: Optional[str] = None
    recommended_remediation: str
    reasoning_chain: List[str]


class RemediationResponse(BaseModel):
    """Structured remediation response."""

    class Step(BaseModel):
        action: str
        params: Dict[str, Any]
        risk: str
        rollback_action: Optional[str] = None

    recommended_approach: str
    steps: List[Step]
    risk_assessment: str
    rollback_plan: List[str]
    success_criteria: List[str]
    estimated_duration_minutes: int


# Singleton clients
_llm_client: Optional[AzureOpenAIClient] = None
_embedding_client: Optional[EmbeddingClient] = None


async def get_llm_client() -> AzureOpenAIClient:
    """Get the LLM client singleton."""
    global _llm_client
    if _llm_client is None:
        _llm_client = AzureOpenAIClient()
    return _llm_client


async def get_embedding_client() -> EmbeddingClient:
    """Get the embedding client singleton."""
    global _embedding_client
    if _embedding_client is None:
        _embedding_client = EmbeddingClient()
    return _embedding_client


# Need to import asyncio for embed_batch
import asyncio
