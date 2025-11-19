# ============================================================================
# FILE 3: src/ingestion/__init__.py - FIXED
# ============================================================================
"""Event ingestion package initialization."""

from src.ingestion.elastic_client import ElasticClient
from src.ingestion.event_fetcher import EventFetcher
from src.ingestion.stream_handler import StreamHandler

__all__ = [
    "ElasticClient",
    "EventFetcher",
    "StreamHandler",
]