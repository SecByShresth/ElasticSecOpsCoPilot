"""
Enrichment coordinator for parallel processing.
Compatible with Python 3.13+
"""

from typing import Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from src.enrichment.base import BaseEnricher
from src.models.enrichment import EnrichedIOC
from src.models.event import SecurityEvent
from src.utils.logger import get_default_logger


class EnrichmentCoordinator:
    """Coordinates parallel enrichment from multiple sources."""

    def __init__(
        self,
        enrichers: list[BaseEnricher],
        max_workers: int = 4,
        timeout_seconds: int = 30,
    ):
        """
        Initialize enrichment coordinator.

        Args:
            enrichers: List of enricher instances
            max_workers: Maximum parallel workers
            timeout_seconds: Timeout per enricher
        """
        self.enrichers = enrichers
        self.max_workers = max_workers
        self.timeout_seconds = timeout_seconds
        self.logger = get_default_logger(level="INFO")

    def enrich_ioc(self, ioc_type: str, ioc_value: str) -> EnrichedIOC:
        """
        Enrich a single IOC with all sources in parallel.

        Args:
            ioc_type: Type of IOC (ip, domain, url, file_hash, etc.)
            ioc_value: Value of the IOC

        Returns:
            EnrichedIOC with all enrichment data
        """
        enriched_ioc = EnrichedIOC(type=ioc_type, value=ioc_value)

        self.logger.debug(
            "Starting enrichment",
            type=ioc_type,
            value=ioc_value,
            sources=len(self.enrichers)
        )

        # Enrich in parallel
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all enrichers
            futures = {
                executor.submit(e.enrich, enriched_ioc): e
                for e in self.enrichers
            }

            # Collect results
            for future in as_completed(futures, timeout=self.timeout_seconds):
                enricher = futures[future]

                try:
                    future.result()
                    self.logger.debug(
                        "Enricher completed",
                        source=enricher.name
                    )

                except Exception as e:
                    self.logger.error(
                        "Enricher failed",
                        source=enricher.name,
                        error=str(e)
                    )

        # Update enriched_at timestamp
        enriched_ioc.enriched_at = datetime.utcnow()

        self.logger.debug(
            "Enrichment complete",
            type=ioc_type,
            value=ioc_value,
            sources_checked=len(enriched_ioc.sources_checked)
        )

        return enriched_ioc

    def enrich_iocs(
        self,
        iocs: list[tuple[str, str]]
    ) -> list[EnrichedIOC]:
        """
        Enrich multiple IOCs.

        Args:
            iocs: List of (type, value) tuples

        Returns:
            List of EnrichedIOC objects
        """
        results = []

        self.logger.info("Starting batch enrichment", count=len(iocs))

        for ioc_type, ioc_value in iocs:
            try:
                enriched = self.enrich_ioc(ioc_type, ioc_value)
                results.append(enriched)

            except Exception as e:
                self.logger.error(
                    "Failed to enrich IOC",
                    type=ioc_type,
                    value=ioc_value,
                    error=str(e)
                )

        self.logger.info(
            "Batch enrichment complete",
            total=len(iocs),
            successful=len(results)
        )

        return results

    def enrich_event(self, event: SecurityEvent) -> None:
        """
        Enrich all IOCs in a security event.

        Args:
            event: SecurityEvent to enrich
        """
        if not event.iocs:
            self.logger.debug("No IOCs to enrich in event")
            return

        self.logger.info(
            "Enriching event IOCs",
            event_id=event.event_id,
            ioc_count=len(event.iocs)
        )

        for ioc in event.iocs:
            try:
                enriched_ioc = self.enrich_ioc(ioc.type, ioc.value)

                # Store enrichment data in event
                enrichment_key = f"{ioc.type}:{ioc.value}"

                if enrichment_key not in event.enrichments:
                    event.enrichments[enrichment_key] = []

                # Add enrichment results
                from src.models.event import EnrichmentData

                for source in enriched_ioc.sources_checked:
                    enrichment = EnrichmentData(
                        source=source,
                        data=enriched_ioc.to_dict(),
                        hit=True
                    )
                    event.enrichments[enrichment_key].append(enrichment)

            except Exception as e:
                self.logger.error(
                    "Failed to enrich IOC in event",
                    ioc=ioc.value,
                    error=str(e)
                )

        self.logger.info(
            "Event enrichment complete",
            event_id=event.event_id
        )

    def get_coordinator_stats(self) -> dict[str, Any]:
        """
        Get coordinator statistics.

        Returns:
            Statistics dictionary
        """
        cache_stats = []

        for enricher in self.enrichers:
            cache_stats.append(enricher.get_cache_stats())

        return {
            "max_workers": self.max_workers,
            "timeout_seconds": self.timeout_seconds,
            "enrichers_count": len(self.enrichers),
            "enrichers": [e.name for e in self.enrichers],
            "cache_stats": cache_stats,
        }

    def clear_all_caches(self) -> None:
        """Clear all enricher caches."""
        for enricher in self.enrichers:
            enricher.clear_cache()

        self.logger.info("All caches cleared")