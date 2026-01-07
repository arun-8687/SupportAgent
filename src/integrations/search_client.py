"""
Azure AI Search integration for hybrid search capabilities.

Provides:
- Vector similarity search (semantic)
- Full-text keyword search
- Hybrid search (vector + keyword with RRF fusion)
- Faceted search and filtering
"""
import asyncio
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional
from enum import Enum

import structlog
from azure.core.credentials import AzureKeyCredential
from azure.search.documents import SearchClient
from azure.search.documents.indexes import SearchIndexClient
from azure.search.documents.indexes.models import (
    SearchIndex,
    SearchField,
    SearchFieldDataType,
    SearchableField,
    SimpleField,
    VectorSearch,
    VectorSearchProfile,
    HnswAlgorithmConfiguration,
    SemanticConfiguration,
    SemanticSearch,
    SemanticPrioritizedFields,
    SemanticField,
)
from azure.search.documents.models import VectorizedQuery
from tenacity import retry, stop_after_attempt, wait_exponential

from src.integrations.config import get_settings

logger = structlog.get_logger()


class SearchMode(Enum):
    """Search mode options."""
    VECTOR = "vector"
    KEYWORD = "keyword"
    HYBRID = "hybrid"
    SEMANTIC = "semantic"


@dataclass
class SearchResult:
    """Search result with metadata."""
    id: str
    score: float
    document: Dict[str, Any]
    highlights: Optional[Dict[str, List[str]]] = None
    captions: Optional[List[str]] = None


@dataclass
class SearchResponse:
    """Complete search response."""
    results: List[SearchResult]
    total_count: int
    facets: Optional[Dict[str, List[Dict]]] = None


class AzureSearchClient:
    """
    Azure AI Search client for hybrid search operations.

    Indexes:
    - incidents: Past incidents with embeddings
    - known-errors: Known error database (KEDB)
    - runbooks: Remediation runbooks
    """

    # Index configurations
    INCIDENTS_INDEX = "incidents"
    KNOWN_ERRORS_INDEX = "known-errors"
    RUNBOOKS_INDEX = "runbooks"

    def __init__(
        self,
        endpoint: Optional[str] = None,
        api_key: Optional[str] = None,
        embedding_dimensions: int = 3072  # text-embedding-3-large dimensions
    ):
        settings = get_settings()
        self.endpoint = endpoint or settings.azure_search_endpoint
        self.api_key = api_key or settings.azure_search_api_key
        self.embedding_dimensions = embedding_dimensions

        self._credential = AzureKeyCredential(self.api_key)
        self._index_client = SearchIndexClient(
            endpoint=self.endpoint,
            credential=self._credential
        )
        self._search_clients: Dict[str, SearchClient] = {}

    def _get_search_client(self, index_name: str) -> SearchClient:
        """Get or create search client for an index."""
        if index_name not in self._search_clients:
            self._search_clients[index_name] = SearchClient(
                endpoint=self.endpoint,
                index_name=index_name,
                credential=self._credential
            )
        return self._search_clients[index_name]

    async def initialize_indexes(self) -> None:
        """Create all required indexes if they don't exist."""
        await asyncio.gather(
            self._create_incidents_index(),
            self._create_known_errors_index(),
            self._create_runbooks_index()
        )
        logger.info("azure_search_indexes_initialized")

    async def _create_incidents_index(self) -> None:
        """Create incidents search index."""
        fields = [
            SimpleField(name="id", type=SearchFieldDataType.String, key=True),
            SimpleField(name="incident_id", type=SearchFieldDataType.String, filterable=True),
            SearchableField(name="job_name", type=SearchFieldDataType.String, filterable=True, facetable=True),
            SimpleField(name="job_type", type=SearchFieldDataType.String, filterable=True, facetable=True),
            SearchableField(name="error_message", type=SearchFieldDataType.String),
            SearchableField(name="stack_trace", type=SearchFieldDataType.String),
            SimpleField(name="environment", type=SearchFieldDataType.String, filterable=True, facetable=True),
            SimpleField(name="severity", type=SearchFieldDataType.String, filterable=True, facetable=True),
            SimpleField(name="status", type=SearchFieldDataType.String, filterable=True, facetable=True),
            SimpleField(name="category", type=SearchFieldDataType.String, filterable=True, facetable=True),
            SearchableField(name="resolution_summary", type=SearchFieldDataType.String),
            SimpleField(name="resolution_verified", type=SearchFieldDataType.Boolean, filterable=True),
            SimpleField(name="created_at", type=SearchFieldDataType.DateTimeOffset, filterable=True, sortable=True),
            SimpleField(name="resolved_at", type=SearchFieldDataType.DateTimeOffset, filterable=True, sortable=True),
            SearchField(
                name="embedding",
                type=SearchFieldDataType.Collection(SearchFieldDataType.Single),
                searchable=True,
                vector_search_dimensions=self.embedding_dimensions,
                vector_search_profile_name="incidents-vector-profile"
            )
        ]

        vector_search = VectorSearch(
            profiles=[
                VectorSearchProfile(
                    name="incidents-vector-profile",
                    algorithm_configuration_name="incidents-hnsw-config"
                )
            ],
            algorithms=[
                HnswAlgorithmConfiguration(
                    name="incidents-hnsw-config",
                    parameters={
                        "m": 4,
                        "efConstruction": 400,
                        "efSearch": 500,
                        "metric": "cosine"
                    }
                )
            ]
        )

        semantic_config = SemanticConfiguration(
            name="incidents-semantic-config",
            prioritized_fields=SemanticPrioritizedFields(
                content_fields=[SemanticField(field_name="error_message")],
                title_fields=[SemanticField(field_name="job_name")],
                keywords_fields=[SemanticField(field_name="category")]
            )
        )

        index = SearchIndex(
            name=self.INCIDENTS_INDEX,
            fields=fields,
            vector_search=vector_search,
            semantic_search=SemanticSearch(configurations=[semantic_config])
        )

        await asyncio.to_thread(
            self._index_client.create_or_update_index, index
        )
        logger.info("incidents_index_created")

    async def _create_known_errors_index(self) -> None:
        """Create known errors search index."""
        fields = [
            SimpleField(name="id", type=SearchFieldDataType.String, key=True),
            SimpleField(name="error_id", type=SearchFieldDataType.String, filterable=True),
            SearchableField(name="title", type=SearchFieldDataType.String),
            SearchableField(name="error_pattern", type=SearchFieldDataType.String),
            SearchableField(name="root_cause", type=SearchFieldDataType.String),
            SearchableField(name="workaround", type=SearchFieldDataType.String),
            SearchableField(name="permanent_fix", type=SearchFieldDataType.String),
            SimpleField(
                name="job_types",
                type=SearchFieldDataType.Collection(SearchFieldDataType.String),
                filterable=True,
                facetable=True
            ),
            SimpleField(name="active", type=SearchFieldDataType.Boolean, filterable=True),
            SimpleField(name="success_count", type=SearchFieldDataType.Int32, sortable=True),
            SimpleField(name="failure_count", type=SearchFieldDataType.Int32),
            SearchField(
                name="embedding",
                type=SearchFieldDataType.Collection(SearchFieldDataType.Single),
                searchable=True,
                vector_search_dimensions=self.embedding_dimensions,
                vector_search_profile_name="known-errors-vector-profile"
            )
        ]

        vector_search = VectorSearch(
            profiles=[
                VectorSearchProfile(
                    name="known-errors-vector-profile",
                    algorithm_configuration_name="known-errors-hnsw-config"
                )
            ],
            algorithms=[
                HnswAlgorithmConfiguration(
                    name="known-errors-hnsw-config",
                    parameters={"m": 4, "efConstruction": 400, "efSearch": 500, "metric": "cosine"}
                )
            ]
        )

        semantic_config = SemanticConfiguration(
            name="known-errors-semantic-config",
            prioritized_fields=SemanticPrioritizedFields(
                content_fields=[SemanticField(field_name="error_pattern")],
                title_fields=[SemanticField(field_name="title")],
                keywords_fields=[SemanticField(field_name="root_cause")]
            )
        )

        index = SearchIndex(
            name=self.KNOWN_ERRORS_INDEX,
            fields=fields,
            vector_search=vector_search,
            semantic_search=SemanticSearch(configurations=[semantic_config])
        )

        await asyncio.to_thread(
            self._index_client.create_or_update_index, index
        )
        logger.info("known_errors_index_created")

    async def _create_runbooks_index(self) -> None:
        """Create runbooks search index."""
        fields = [
            SimpleField(name="id", type=SearchFieldDataType.String, key=True),
            SimpleField(name="runbook_id", type=SearchFieldDataType.String, filterable=True),
            SearchableField(name="name", type=SearchFieldDataType.String),
            SearchableField(name="description", type=SearchFieldDataType.String),
            SearchableField(name="content", type=SearchFieldDataType.String),
            SimpleField(
                name="job_types",
                type=SearchFieldDataType.Collection(SearchFieldDataType.String),
                filterable=True,
                facetable=True
            ),
            SimpleField(name="active", type=SearchFieldDataType.Boolean, filterable=True),
            SimpleField(name="success_rate", type=SearchFieldDataType.Double, sortable=True),
            SimpleField(name="execution_count", type=SearchFieldDataType.Int32, sortable=True),
            SearchField(
                name="embedding",
                type=SearchFieldDataType.Collection(SearchFieldDataType.Single),
                searchable=True,
                vector_search_dimensions=self.embedding_dimensions,
                vector_search_profile_name="runbooks-vector-profile"
            )
        ]

        vector_search = VectorSearch(
            profiles=[
                VectorSearchProfile(
                    name="runbooks-vector-profile",
                    algorithm_configuration_name="runbooks-hnsw-config"
                )
            ],
            algorithms=[
                HnswAlgorithmConfiguration(
                    name="runbooks-hnsw-config",
                    parameters={"m": 4, "efConstruction": 400, "efSearch": 500, "metric": "cosine"}
                )
            ]
        )

        semantic_config = SemanticConfiguration(
            name="runbooks-semantic-config",
            prioritized_fields=SemanticPrioritizedFields(
                content_fields=[SemanticField(field_name="content")],
                title_fields=[SemanticField(field_name="name")],
                keywords_fields=[SemanticField(field_name="description")]
            )
        )

        index = SearchIndex(
            name=self.RUNBOOKS_INDEX,
            fields=fields,
            vector_search=vector_search,
            semantic_search=SemanticSearch(configurations=[semantic_config])
        )

        await asyncio.to_thread(
            self._index_client.create_or_update_index, index
        )
        logger.info("runbooks_index_created")

    # =========================================================================
    # Document Operations
    # =========================================================================

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=10))
    async def index_incident(self, document: Dict[str, Any]) -> None:
        """Index an incident document."""
        client = self._get_search_client(self.INCIDENTS_INDEX)
        await asyncio.to_thread(client.upload_documents, [document])
        logger.debug("incident_indexed", incident_id=document.get("incident_id"))

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=10))
    async def index_incidents_batch(self, documents: List[Dict[str, Any]]) -> None:
        """Index multiple incidents."""
        client = self._get_search_client(self.INCIDENTS_INDEX)
        await asyncio.to_thread(client.upload_documents, documents)
        logger.info("incidents_batch_indexed", count=len(documents))

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=10))
    async def index_known_error(self, document: Dict[str, Any]) -> None:
        """Index a known error document."""
        client = self._get_search_client(self.KNOWN_ERRORS_INDEX)
        await asyncio.to_thread(client.upload_documents, [document])
        logger.debug("known_error_indexed", error_id=document.get("error_id"))

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=10))
    async def index_runbook(self, document: Dict[str, Any]) -> None:
        """Index a runbook document."""
        client = self._get_search_client(self.RUNBOOKS_INDEX)
        await asyncio.to_thread(client.upload_documents, [document])
        logger.debug("runbook_indexed", runbook_id=document.get("runbook_id"))

    # =========================================================================
    # Search Operations
    # =========================================================================

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=10))
    async def search_incidents(
        self,
        query: Optional[str] = None,
        embedding: Optional[List[float]] = None,
        mode: SearchMode = SearchMode.HYBRID,
        filters: Optional[str] = None,
        top: int = 10,
        include_facets: bool = False
    ) -> SearchResponse:
        """
        Search incidents using hybrid search.

        Args:
            query: Text query for keyword/semantic search
            embedding: Vector embedding for similarity search
            mode: Search mode (vector, keyword, hybrid, semantic)
            filters: OData filter expression (e.g., "environment eq 'prod'")
            top: Number of results to return
            include_facets: Whether to include facet counts
        """
        client = self._get_search_client(self.INCIDENTS_INDEX)

        search_kwargs = {
            "top": top,
            "include_total_count": True
        }

        if filters:
            search_kwargs["filter"] = filters

        if include_facets:
            search_kwargs["facets"] = ["job_type", "environment", "severity", "status", "category"]

        # Configure search based on mode
        if mode == SearchMode.VECTOR and embedding:
            search_kwargs["vector_queries"] = [
                VectorizedQuery(
                    vector=embedding,
                    k_nearest_neighbors=top,
                    fields="embedding"
                )
            ]
            search_kwargs["search_text"] = None

        elif mode == SearchMode.KEYWORD and query:
            search_kwargs["search_text"] = query

        elif mode == SearchMode.HYBRID and query and embedding:
            search_kwargs["search_text"] = query
            search_kwargs["vector_queries"] = [
                VectorizedQuery(
                    vector=embedding,
                    k_nearest_neighbors=top,
                    fields="embedding"
                )
            ]

        elif mode == SearchMode.SEMANTIC and query:
            search_kwargs["search_text"] = query
            search_kwargs["query_type"] = "semantic"
            search_kwargs["semantic_configuration_name"] = "incidents-semantic-config"
            if embedding:
                search_kwargs["vector_queries"] = [
                    VectorizedQuery(
                        vector=embedding,
                        k_nearest_neighbors=top,
                        fields="embedding"
                    )
                ]

        results = await asyncio.to_thread(
            lambda: list(client.search(**search_kwargs))
        )

        search_results = [
            SearchResult(
                id=r["id"],
                score=r.get("@search.score", 0.0),
                document=dict(r),
                highlights=r.get("@search.highlights"),
                captions=[c.text for c in r.get("@search.captions", [])] if r.get("@search.captions") else None
            )
            for r in results
        ]

        return SearchResponse(
            results=search_results,
            total_count=len(search_results),
            facets=None  # Would need to extract from response
        )

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=10))
    async def search_known_errors(
        self,
        query: Optional[str] = None,
        embedding: Optional[List[float]] = None,
        job_type: Optional[str] = None,
        top: int = 5
    ) -> SearchResponse:
        """Search known errors database."""
        client = self._get_search_client(self.KNOWN_ERRORS_INDEX)

        filters = "active eq true"
        if job_type:
            filters += f" and job_types/any(jt: jt eq '{job_type}')"

        search_kwargs = {
            "top": top,
            "filter": filters,
            "include_total_count": True
        }

        if embedding:
            search_kwargs["vector_queries"] = [
                VectorizedQuery(
                    vector=embedding,
                    k_nearest_neighbors=top,
                    fields="embedding"
                )
            ]

        if query:
            search_kwargs["search_text"] = query
            search_kwargs["query_type"] = "semantic"
            search_kwargs["semantic_configuration_name"] = "known-errors-semantic-config"

        results = await asyncio.to_thread(
            lambda: list(client.search(**search_kwargs))
        )

        return SearchResponse(
            results=[
                SearchResult(
                    id=r["id"],
                    score=r.get("@search.score", 0.0),
                    document=dict(r)
                )
                for r in results
            ],
            total_count=len(results)
        )

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=10))
    async def search_runbooks(
        self,
        query: Optional[str] = None,
        embedding: Optional[List[float]] = None,
        job_type: Optional[str] = None,
        top: int = 3
    ) -> SearchResponse:
        """Search runbooks."""
        client = self._get_search_client(self.RUNBOOKS_INDEX)

        filters = "active eq true"
        if job_type:
            filters += f" and job_types/any(jt: jt eq '{job_type}')"

        search_kwargs = {
            "top": top,
            "filter": filters,
            "order_by": ["success_rate desc"],
            "include_total_count": True
        }

        if embedding:
            search_kwargs["vector_queries"] = [
                VectorizedQuery(
                    vector=embedding,
                    k_nearest_neighbors=top,
                    fields="embedding"
                )
            ]

        if query:
            search_kwargs["search_text"] = query
            search_kwargs["query_type"] = "semantic"
            search_kwargs["semantic_configuration_name"] = "runbooks-semantic-config"

        results = await asyncio.to_thread(
            lambda: list(client.search(**search_kwargs))
        )

        return SearchResponse(
            results=[
                SearchResult(
                    id=r["id"],
                    score=r.get("@search.score", 0.0),
                    document=dict(r)
                )
                for r in results
            ],
            total_count=len(results)
        )

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=10))
    async def find_similar_incidents(
        self,
        embedding: List[float],
        exclude_id: Optional[str] = None,
        environment: Optional[str] = None,
        job_type: Optional[str] = None,
        min_score: float = 0.7,
        top: int = 10
    ) -> List[SearchResult]:
        """
        Find similar incidents using vector search.

        Used for deduplication and finding past resolutions.
        """
        filters_parts = []
        if exclude_id:
            filters_parts.append(f"incident_id ne '{exclude_id}'")
        if environment:
            filters_parts.append(f"environment eq '{environment}'")
        if job_type:
            filters_parts.append(f"job_type eq '{job_type}'")

        filters = " and ".join(filters_parts) if filters_parts else None

        response = await self.search_incidents(
            embedding=embedding,
            mode=SearchMode.VECTOR,
            filters=filters,
            top=top
        )

        # Filter by minimum score
        return [r for r in response.results if r.score >= min_score]

    async def find_resolved_similar_incidents(
        self,
        embedding: List[float],
        job_type: Optional[str] = None,
        top: int = 5
    ) -> List[SearchResult]:
        """Find similar incidents that have been resolved."""
        filters = "status eq 'resolved' and resolution_verified eq true"
        if job_type:
            filters += f" and job_type eq '{job_type}'"

        response = await self.search_incidents(
            embedding=embedding,
            mode=SearchMode.VECTOR,
            filters=filters,
            top=top
        )

        return response.results


# Singleton instance
_search_client: Optional[AzureSearchClient] = None


async def get_search_client() -> AzureSearchClient:
    """Get the Azure Search client singleton."""
    global _search_client
    if _search_client is None:
        _search_client = AzureSearchClient()
        await _search_client.initialize_indexes()
    return _search_client
