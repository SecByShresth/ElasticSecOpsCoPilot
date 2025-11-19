# ============================================================================
# FILE 1: src/ingestion/event_fetcher.py - FIXED
# ============================================================================
"""Fetch security events from Elasticsearch."""

from typing import Any
from datetime import datetime, timedelta
from src.models.event import SecurityEvent
from src.ingestion.elastic_client import ElasticClient
from src.utils.logger import get_default_logger


class EventFetcher:
    """Fetches security events from Elasticsearch."""

    def __init__(self, client: ElasticClient | None = None):
        """
        Initialize event fetcher.

        Args:
            client: ElasticClient instance
        """
        self.client = client or ElasticClient()
        self.logger = get_default_logger(level="INFO")

    def fetch_alerts(
        self,
        indices: list[str] | None = None,
        lookback_hours: int = 24,
        batch_size: int = 100
    ) -> list[SecurityEvent]:
        """
        Fetch alerts from Elasticsearch.

        Args:
            indices: Index names to query
            lookback_hours: Hours to look back
            batch_size: Batch size for fetching

        Returns:
            List of SecurityEvent objects
        """
        if indices is None:
            indices = [".alerts-security.alerts-default"]

        try:
            # Build query for recent alerts
            start_time = (datetime.utcnow() - timedelta(hours=lookback_hours)).isoformat()

            query = {
                "bool": {
                    "must": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": start_time
                                }
                            }
                        }
                    ]
                }
            }

            # Search
            response = self.client.search(
                index=",".join(indices),
                query=query,
                size=batch_size
            )

            # Convert to SecurityEvent objects
            events = []
            for hit in response.get("hits", {}).get("hits", []):
                try:
                    event = SecurityEvent.from_elastic_alert(hit)
                    events.append(event)
                except Exception as e:
                    self.logger.warning(f"Failed to parse alert {hit.get('_id')}: {e}")
                    continue

            self.logger.info(f"Fetched {len(events)} alerts from {len(indices)} indices")
            return events

        except Exception as e:
            self.logger.error(f"Failed to fetch alerts: {e}")
            raise

    def fetch_by_query(
        self,
        index: str,
        query: dict[str, Any],
        size: int = 100
    ) -> list[SecurityEvent]:
        """
        Fetch alerts by custom query.

        Args:
            index: Index name
            query: Elasticsearch query
            size: Number of results

        Returns:
            List of SecurityEvent objects
        """
        try:
            response = self.client.search(index=index, query=query, size=size)

            events = []
            for hit in response.get("hits", {}).get("hits", []):
                try:
                    event = SecurityEvent.from_elastic_alert(hit)
                    events.append(event)
                except Exception as e:
                    self.logger.warning(f"Failed to parse alert {hit.get('_id')}: {e}")
                    continue

            return events

        except Exception as e:
            self.logger.error(f"Query failed: {e}")
            raise

    def fetch_failed_logins(
        self,
        lookback_hours: int = 24,
        size: int = 100
    ) -> list[SecurityEvent]:
        """Fetch failed login attempts."""
        query = {
            "bool": {
                "must": [
                    {
                        "match": {
                            "event.action": "authentication_failure"
                        }
                    }
                ]
            }
        }

        return self.fetch_by_query(
            ".alerts-security.alerts-default",
            query,
            size
        )

    def fetch_process_execution(
        self,
        process_name: str,
        lookback_hours: int = 24,
        size: int = 100
    ) -> list[SecurityEvent]:
        """Fetch process execution alerts."""
        query = {
            "bool": {
                "must": [
                    {
                        "match": {
                            "process.name": process_name
                        }
                    }
                ]
            }
        }

        return self.fetch_by_query(
            ".alerts-security.alerts-default",
            query,
            size
        )

    def fetch_network_events(
        self,
        source_ip: str | None = None,
        destination_ip: str | None = None,
        lookback_hours: int = 24,
        size: int = 100
    ) -> list[SecurityEvent]:
        """Fetch network events."""
        must_clauses = []

        if source_ip:
            must_clauses.append({"match": {"source.ip": source_ip}})

        if destination_ip:
            must_clauses.append({"match": {"destination.ip": destination_ip}})

        if not must_clauses:
            raise ValueError("Must specify source_ip or destination_ip")

        query = {"bool": {"must": must_clauses}}

        return self.fetch_by_query(
            ".alerts-security.alerts-default",
            query,
            size
        )