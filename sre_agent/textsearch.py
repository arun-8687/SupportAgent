"""
Shared keyword tokenization/overlap scoring for the lightweight search
used across the memory stores and the skills registry.

One implementation instead of five: stemming, stop-words, or threshold
changes happen here and every store benefits together.
"""
import re
from typing import Set

_WORD_RE = re.compile(r"[a-z0-9]+")


def tokens(text: str, min_len: int = 1) -> Set[str]:
    """Lowercase alphanumeric tokens of at least min_len characters."""
    return {t for t in _WORD_RE.findall((text or "").lower()) if len(t) >= min_len}


def jaccard(query_tokens: Set[str], corpus_tokens: Set[str]) -> float:
    """Jaccard similarity; 0.0 when either side is empty."""
    if not query_tokens or not corpus_tokens:
        return 0.0
    return len(query_tokens & corpus_tokens) / len(query_tokens | corpus_tokens)


def overlap_count(query_tokens: Set[str], corpus_tokens: Set[str]) -> int:
    """Raw count of query tokens present in the corpus."""
    return len(query_tokens & corpus_tokens)
