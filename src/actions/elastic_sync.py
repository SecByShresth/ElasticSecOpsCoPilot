# ============================================================================
# src/actions/elastic_sync.py - Sync Results to Elasticsearch
# ============================================================================

"""Sync enriched results back to Elasticsearch."""
from typing import Any
from src.models.event import SecurityEvent
from src.ingestion.elastic_client import ElasticClient
from src.utils.logger import get_default_logger


class ElasticSync:
    """Synchronizes enriched events back to Elasticsearch."""

    def __init__(self, client: ElasticClient):
        """
        Initialize sync.

        Args:
            client: ElasticClient instance
        """
        self.client = client
        self.logger = get_default_logger(level="INFO")

    def sync_event(
        self,
        index: str,
        event: SecurityEvent,
        doc_id: str | None = None
    ) -> str:
        """
        Sync single enriched event.

        Args:
            index: Target index
            event: SecurityEvent to sync
            doc_id: Optional document ID

        Returns:
            Document ID
        """
        try:
            doc_body = event.to_dict(include_raw=False)
            doc_id = doc_id or event.event_id

            result_id = self.client.index_document(index, doc_body, doc_id)

            self.logger.info(
                "Event synced",
                index=index,
                doc_id=result_id
            )

            return result_id

        except Exception as e:
            self.logger.error(
                "Failed to sync event",
                event_id=event.event_id,
                error=str(e)
            )
            raise

    def sync_batch(
        self,
        index: str,
        events: list[SecurityEvent]
    ) -> int:
        """
        Sync multiple events in batch.

        Args:
            index: Target index
            events: List of SecurityEvent objects

        Returns:
            Number of synced events
        """
        try:
            documents = [e.to_dict(include_raw=False) for e in events]
            result = self.client.bulk_index(index, documents)

            synced = len(events)

            self.logger.info(
                "Batch synced",
                index=index,
                count=synced
            )

            return synced

        except Exception as e:
            self.logger.error(
                "Failed to sync batch",
                count=len(events),
                error=str(e)
            )
            raise
