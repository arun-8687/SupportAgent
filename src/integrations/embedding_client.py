"""
Azure OpenAI Embedding Client.

Provides text embedding generation using Azure OpenAI's embedding models.
"""
import asyncio
from typing import List, Optional

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from src.integrations.config import get_settings


class EmbeddingClient:
    """
    Client for generating text embeddings via Azure OpenAI.

    Uses text-embedding-ada-002 or newer embedding models.
    """

    def __init__(
        self,
        endpoint: Optional[str] = None,
        api_key: Optional[str] = None,
        deployment_name: Optional[str] = None,
        api_version: str = "2024-02-15-preview"
    ):
        """
        Initialize embedding client.

        Args:
            endpoint: Azure OpenAI endpoint URL
            api_key: API key for authentication
            deployment_name: Deployment name for embedding model
            api_version: API version to use
        """
        settings = get_settings()

        self.endpoint = endpoint or settings.azure_openai_endpoint
        self.api_key = api_key or settings.azure_openai_api_key
        self.deployment_name = deployment_name or settings.azure_openai_embedding_deployment
        self.api_version = api_version

        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self):
        """Async context manager entry."""
        self._client = httpx.AsyncClient(
            timeout=30.0,
            headers={
                "api-key": self.api_key,
                "Content-Type": "application/json"
            }
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self._client:
            await self._client.aclose()

    def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=30.0,
                headers={
                    "api-key": self.api_key,
                    "Content-Type": "application/json"
                }
            )
        return self._client

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10)
    )
    async def embed(self, text: str) -> List[float]:
        """
        Generate embedding for a single text.

        Args:
            text: Text to embed

        Returns:
            List of floats representing the embedding vector
        """
        client = self._get_client()

        url = (
            f"{self.endpoint}/openai/deployments/{self.deployment_name}"
            f"/embeddings?api-version={self.api_version}"
        )

        response = await client.post(
            url,
            json={
                "input": text,
                "model": self.deployment_name
            }
        )
        response.raise_for_status()

        data = response.json()
        return data["data"][0]["embedding"]

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10)
    )
    async def embed_batch(
        self,
        texts: List[str],
        batch_size: int = 16
    ) -> List[List[float]]:
        """
        Generate embeddings for multiple texts.

        Args:
            texts: List of texts to embed
            batch_size: Number of texts per API call

        Returns:
            List of embedding vectors
        """
        all_embeddings = []

        for i in range(0, len(texts), batch_size):
            batch = texts[i:i + batch_size]

            client = self._get_client()
            url = (
                f"{self.endpoint}/openai/deployments/{self.deployment_name}"
                f"/embeddings?api-version={self.api_version}"
            )

            response = await client.post(
                url,
                json={
                    "input": batch,
                    "model": self.deployment_name
                }
            )
            response.raise_for_status()

            data = response.json()
            batch_embeddings = [item["embedding"] for item in data["data"]]
            all_embeddings.extend(batch_embeddings)

        return all_embeddings

    async def close(self):
        """Close the HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None
