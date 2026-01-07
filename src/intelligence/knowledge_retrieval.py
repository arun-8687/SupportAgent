"""
Knowledge Retrieval (RAG) for incident diagnosis.

Retrieves relevant knowledge from multiple sources:
- Known Error Database (KEDB)
- Historical ITSM incidents
- Runbooks and documentation
- Past resolutions with similarity matching
"""
import asyncio
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from src.graph.state import (
    Incident,
    KnowledgeContext,
    KnownError,
    PastIncident,
)
from src.integrations.embedding_client import EmbeddingClient
from src.intelligence.correlation import ITSMClient
from src.storage.vector_store import VectorStore


class SuggestedResolution(BaseModel):
    """A suggested resolution from knowledge retrieval."""
    source: str  # "known_error", "past_incident", "runbook"
    resolution: str
    confidence: float = Field(ge=0.0, le=1.0)
    runbook_path: Optional[str] = None
    similar_incident_id: Optional[str] = None
    known_error_id: Optional[str] = None


class DocumentMatch(BaseModel):
    """A matched document from knowledge base."""
    doc_id: str
    title: str
    content: str
    source: str
    relevance: float


class KnowledgeRetriever:
    """
    RAG-based retrieval from multiple knowledge sources.

    Searches:
    - Known Error Database (KEDB) - known issues with workarounds
    - Historical ITSM incidents - past similar issues
    - Runbooks - applicable automation runbooks
    - Documentation - relevant technical docs
    - Recent changes - deployments that might be related
    """

    def __init__(
        self,
        vector_store: VectorStore,
        embedding_client: EmbeddingClient,
        itsm_client: Optional[ITSMClient] = None
    ):
        """
        Initialize knowledge retriever.

        Args:
            vector_store: Vector store for similarity search
            embedding_client: Client for embeddings
            itsm_client: Client for ITSM queries
        """
        self.vector_store = vector_store
        self.embedding_client = embedding_client
        self.itsm_client = itsm_client or ITSMClient()

    async def retrieve_relevant_knowledge(
        self,
        incident: Incident,
        top_k: int = 10
    ) -> KnowledgeContext:
        """
        Retrieve all relevant knowledge for diagnosis.

        Performs parallel retrieval from multiple sources and
        ranks results by relevance.

        Args:
            incident: The incident to find knowledge for
            top_k: Number of results per source

        Returns:
            KnowledgeContext with all retrieved knowledge
        """
        # Generate embedding for incident
        query_embedding = await self._generate_query_embedding(incident)

        # Parallel retrieval from all sources
        results = await asyncio.gather(
            self._search_known_errors(query_embedding, incident),
            self._search_past_incidents(query_embedding, incident),
            self._search_runbooks(query_embedding, incident),
            self._search_documentation(query_embedding, incident),
            self._get_recent_changes(incident),
            return_exceptions=True
        )

        # Unpack results (handle exceptions gracefully)
        known_errors = results[0] if not isinstance(results[0], Exception) else []
        past_incidents = results[1] if not isinstance(results[1], Exception) else []
        runbooks = results[2] if not isinstance(results[2], Exception) else []
        docs = results[3] if not isinstance(results[3], Exception) else []
        changes = results[4] if not isinstance(results[4], Exception) else []

        # Suggest resolution based on retrieved knowledge
        suggested_resolution = self._suggest_resolution(
            known_errors, past_incidents, runbooks
        )

        return KnowledgeContext(
            known_errors=known_errors[:3],  # Top 3 known errors
            similar_incidents=past_incidents[:5],  # Top 5 similar incidents
            applicable_runbooks=runbooks[:3],  # Top 3 runbooks
            relevant_docs=docs[:3],  # Top 3 docs
            recent_changes=changes,  # All recent changes
            suggested_resolution=suggested_resolution.resolution if suggested_resolution else None
        )

    async def _generate_query_embedding(
        self,
        incident: Incident
    ) -> List[float]:
        """Generate embedding for incident query."""
        # Create rich text representation
        query_text = f"""
        Job: {incident.job_name}
        Type: {incident.job_type}
        Error: {incident.error_message}
        """

        if incident.error_code:
            query_text += f"\nError Code: {incident.error_code}"

        if incident.stack_trace:
            # Include relevant part of stack trace
            query_text += f"\nStack Trace: {incident.stack_trace[:1000]}"

        return await self.embedding_client.embed(query_text)

    async def _search_known_errors(
        self,
        embedding: List[float],
        incident: Incident
    ) -> List[KnownError]:
        """
        Search Known Error Database (KEDB).

        Known errors have documented workarounds and root causes.
        """
        # Vector similarity search
        similar = await self.vector_store.search_known_errors(
            query_embedding=embedding,
            error_code=incident.error_code,
            top_k=5,
            min_similarity=0.6
        )

        known_errors = []
        for match in similar:
            known_errors.append(KnownError(
                id=match["id"],
                title=match["title"],
                error_pattern=match["error_pattern"],
                root_cause=match.get("root_cause"),
                workaround=match.get("workaround"),
                permanent_fix=match.get("permanent_fix"),
                linked_runbook=match.get("linked_runbook"),
                match_confidence=match.get("similarity", 0.0)
            ))

        # Sort by match confidence
        return sorted(known_errors, key=lambda x: x.match_confidence, reverse=True)

    async def _search_past_incidents(
        self,
        embedding: List[float],
        incident: Incident
    ) -> List[PastIncident]:
        """
        Find similar past incidents with successful resolutions.

        Prioritizes:
        - Resolved incidents with verified resolutions
        - Same job type
        - High semantic similarity
        """
        # Vector search for similar incidents
        matches = await self.vector_store.find_similar_incidents(
            query_embedding=embedding,
            job_type=incident.job_type,
            status="resolved",
            top_k=10,
            min_similarity=0.5
        )

        past_incidents = []
        for match in matches:
            # Get full incident details from ITSM
            full_incident = await self.itsm_client.get_incident(match.id)

            if full_incident:
                past_incidents.append(PastIncident(
                    incident_id=match.id,
                    error_message=full_incident.get("error_message", match.content),
                    root_cause=full_incident.get("root_cause"),
                    resolution_summary=full_incident.get("resolution_summary"),
                    resolution_verified=full_incident.get("resolution_verified", False),
                    similarity=match.similarity,
                    resolved_at=full_incident.get("resolved_at")
                ))
            else:
                # Use vector store data
                past_incidents.append(PastIncident(
                    incident_id=match.id,
                    error_message=match.metadata.get("error_message", match.content),
                    root_cause=match.metadata.get("root_cause"),
                    resolution_summary=match.metadata.get("resolution_summary"),
                    resolution_verified=match.metadata.get("resolution_verified", False),
                    similarity=match.similarity,
                    resolved_at=None
                ))

        # Sort by: resolution_verified (True first), then similarity
        return sorted(
            past_incidents,
            key=lambda x: (x.resolution_verified, x.similarity),
            reverse=True
        )

    async def _search_runbooks(
        self,
        embedding: List[float],
        incident: Incident
    ) -> List[str]:
        """
        Search for applicable runbooks.

        Returns runbook paths that match the incident.
        """
        matches = await self.vector_store.search_runbooks(
            query_embedding=embedding,
            issue_type=incident.job_type,
            top_k=5,
            min_similarity=0.5
        )

        # Return runbook file paths
        return [match["file_path"] for match in matches if match.get("file_path")]

    async def _search_documentation(
        self,
        embedding: List[float],
        incident: Incident
    ) -> List[Dict[str, Any]]:
        """
        Search general documentation and knowledge base.

        Includes:
        - Technical documentation
        - Troubleshooting guides
        - System architecture docs
        """
        matches = await self.vector_store.similarity_search(
            embedding=embedding,
            collection="knowledge",
            top_k=5,
            filter=None
        )

        docs = []
        for match in matches:
            docs.append({
                "id": match.id,
                "title": match.metadata.get("title", "Untitled"),
                "content": match.content[:500],  # Truncate for context
                "source": match.metadata.get("source", "knowledge_base"),
                "relevance": match.similarity
            })

        return docs

    async def _get_recent_changes(
        self,
        incident: Incident
    ) -> List[Dict[str, Any]]:
        """
        Get recent changes that might be related.

        Looks at changes in the last 24-48 hours.
        """
        changes = await self.itsm_client.get_recent_changes(
            affected_systems=[incident.job_name],
            time_range=timedelta(hours=48)
        )

        return [
            {
                "id": change.id,
                "title": change.title,
                "type": change.change_type,
                "completed_at": change.completed_at.isoformat() if change.completed_at else None,
                "rollback_available": change.rollback_available,
                "affected_systems": change.affected_systems
            }
            for change in changes
        ]

    def _suggest_resolution(
        self,
        known_errors: List[KnownError],
        past_incidents: List[PastIncident],
        runbooks: List[str]
    ) -> Optional[SuggestedResolution]:
        """
        Analyze retrieved knowledge to suggest best resolution.

        Priority:
        1. Known error with high confidence match (> 0.9)
        2. Past incident with verified resolution
        3. Applicable runbook
        """
        # 1. Check known errors
        for ke in known_errors:
            if ke.match_confidence > 0.9 and ke.workaround:
                return SuggestedResolution(
                    source="known_error",
                    resolution=ke.workaround,
                    confidence=ke.match_confidence,
                    runbook_path=ke.linked_runbook,
                    known_error_id=ke.id
                )

        # 2. Check past incidents with verified resolutions
        verified_incidents = [
            inc for inc in past_incidents
            if inc.resolution_verified and inc.resolution_summary
        ]
        if verified_incidents:
            best = verified_incidents[0]
            return SuggestedResolution(
                source="past_incident",
                resolution=best.resolution_summary,
                confidence=best.similarity * 0.9,  # Slight discount
                similar_incident_id=best.incident_id
            )

        # 3. Check unverified but high-similarity past resolutions
        if past_incidents:
            best = past_incidents[0]
            if best.similarity > 0.8 and best.resolution_summary:
                return SuggestedResolution(
                    source="past_incident",
                    resolution=best.resolution_summary,
                    confidence=best.similarity * 0.7,  # Higher discount for unverified
                    similar_incident_id=best.incident_id
                )

        # 4. Suggest runbook if available
        if runbooks:
            return SuggestedResolution(
                source="runbook",
                resolution=f"Apply runbook: {runbooks[0]}",
                confidence=0.6,
                runbook_path=runbooks[0]
            )

        return None


class HybridRetriever:
    """
    Hybrid retrieval combining vector search with keyword/BM25.

    Uses both semantic similarity and keyword matching for
    better recall on technical error messages.
    """

    def __init__(
        self,
        vector_store: VectorStore,
        embedding_client: EmbeddingClient
    ):
        """Initialize hybrid retriever."""
        self.vector_store = vector_store
        self.embedding_client = embedding_client

    async def hybrid_search(
        self,
        query: str,
        collection: str,
        top_k: int = 10,
        vector_weight: float = 0.7
    ) -> List[Dict[str, Any]]:
        """
        Perform hybrid search combining vector and keyword.

        Args:
            query: Search query
            collection: Collection to search
            top_k: Number of results
            vector_weight: Weight for vector results (0-1)

        Returns:
            Combined and re-ranked results
        """
        # Get embedding
        embedding = await self.embedding_client.embed(query)

        # Vector search
        vector_results = await self.vector_store.similarity_search(
            embedding=embedding,
            collection=collection,
            top_k=top_k * 2  # Get more for re-ranking
        )

        # For keyword search, extract key terms
        keywords = self._extract_keywords(query)

        # Score and combine results
        scored_results = []
        for result in vector_results:
            vector_score = result.similarity

            # Calculate keyword score
            keyword_score = self._calculate_keyword_score(
                result.content, keywords
            )

            # Combined score
            combined_score = (
                vector_weight * vector_score +
                (1 - vector_weight) * keyword_score
            )

            scored_results.append({
                "id": result.id,
                "content": result.content,
                "metadata": result.metadata,
                "vector_score": vector_score,
                "keyword_score": keyword_score,
                "combined_score": combined_score
            })

        # Sort by combined score
        scored_results.sort(key=lambda x: x["combined_score"], reverse=True)

        return scored_results[:top_k]

    def _extract_keywords(self, query: str) -> List[str]:
        """Extract important keywords from query."""
        # Remove common words
        stop_words = {
            "the", "a", "an", "is", "are", "was", "were", "be", "been",
            "being", "have", "has", "had", "do", "does", "did", "will",
            "would", "could", "should", "may", "might", "must", "shall",
            "can", "need", "job", "error", "failed", "failure", "with",
            "for", "and", "or", "but", "in", "on", "at", "to", "from"
        }

        # Tokenize and filter
        words = query.lower().split()
        keywords = [
            word for word in words
            if word not in stop_words and len(word) > 2
        ]

        return keywords

    def _calculate_keyword_score(
        self,
        content: str,
        keywords: List[str]
    ) -> float:
        """Calculate keyword match score."""
        if not keywords:
            return 0.0

        content_lower = content.lower()
        matches = sum(1 for kw in keywords if kw in content_lower)

        return matches / len(keywords)
