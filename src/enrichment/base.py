"""
Abstract base class for enrichment sources.
Compatible with Python 3.13+
"""

from abc import ABC, abstractmethod
from typing import Any
from datetime import datetime, timedelta
import json

from src.models.enrichment import EnrichedIOC, ThreatLevel
from src.utils.logger import get_default_logger


class EnrichmentCache:
    """Simple in-memory cache for enrichment results."""

    def __init__(self, ttl_seconds: int = 86400):
        """
        Initialize cache.

        Args:
            ttl_seconds: Time to live in seconds
        """
        self.ttl_seconds = ttl_seconds
        self.cache: dict[str, tuple[Any, datetime]] = {}

    def get(self, key: str) -> Any | None:
        """
        Get cached value.

        Args:
            key: Cache key

        Returns:
            Cached value or None
        """
        if key not in self.cache:
            return None

        value, timestamp = self.cache[key]
        age = (datetime.utcnow() - timestamp).total_seconds()

        if age > self.ttl_seconds:
            del self.cache[key]
            return None

        return value

    def set(self, key: str, value: Any) -> None:
        """
        Set cached value.

        Args:
            key: Cache key
            value: Value to cache
        """
        self.cache[key] = (value, datetime.utcnow())

    def clear(self) -> None:
        """Clear cache."""
        self.cache.clear()

    def get_size(self) -> int:
        """Get cache size."""
        return len(self.cache)


class BaseEnricher(ABC):
    """
    Abstract base class for enrichment sources.
    All enrichers must implement this interface.
    """

    def __init__(
        self,
        name: str,
        config: dict[str, Any] | None = None,
        cache_ttl_seconds: int = 86400,
    ):
        """
        Initialize enricher.

        Args:
            name: Enricher name
            config: Configuration dictionary
            cache_ttl_seconds: Cache TTL in seconds
        """
        self.name = name
        self.config = config or {}
        self.logger = get_default_logger(level="INFO")
        self.cache = EnrichmentCache(cache_ttl_seconds)
        self.enabled = self.config.get("enabled", True)
        self.api_key = self.config.get("api_key")
        self.timeout_seconds = self.config.get("timeout", 30)

    @abstractmethod
    def enrich_ioc(self, ioc_type: str, ioc_value: str) -> dict[str, Any]:
        """
        Enrich a single IOC.

        Args:
            ioc_type: Type of IOC (ip, domain, url, file_hash, etc.)
            ioc_value: Value of the IOC

        Returns:
            Enrichment result dictionary
        """
        raise NotImplementedError

    def enrich(self, enriched_ioc: EnrichedIOC) -> None:
        """
        Enrich an EnrichedIOC object.

        Args:
            enriched_ioc: EnrichedIOC to enrich
        """
        if not self.enabled:
            self.logger.debug(f"{self.name} is disabled")
            return

        try:
            self.logger.debug(
                "Enriching IOC",
                source=self.name,
                type=enriched_ioc.type,
                value=enriched_ioc.value
            )

            result = self.enrich_ioc(enriched_ioc.type, enriched_ioc.value)

            if result:
                self._update_enriched_ioc(enriched_ioc, result)
                enriched_ioc.sources_checked.append(self.name)

        except Exception as e:
            self.logger.error(
                "Enrichment failed",
                source=self.name,
                error=str(e)
            )
            enriched_ioc.errors[self.name] = str(e)

    @abstractmethod
    def _update_enriched_ioc(
        self,
        enriched_ioc: EnrichedIOC,
        result: dict[str, Any]
    ) -> None:
        """
        Update EnrichedIOC with enrichment result.

        Args:
            enriched_ioc: EnrichedIOC to update
            result: Enrichment result
        """
        raise NotImplementedError

    def validate_config(self) -> bool:
        """
        Validate enricher configuration.

        Returns:
            True if valid
        """
        if self.enabled and not self.api_key:
            self.logger.warning(
                f"{self.name} enabled but no API key provided"
            )
            return False

        return True

    def get_cache_stats(self) -> dict[str, Any]:
        """
        Get cache statistics.

        Returns:
            Cache stats dictionary
        """
        return {
            "source": self.name,
            "cache_size": self.cache.get_size(),
            "ttl_seconds": self.cache.ttl_seconds,
        }

    def clear_cache(self) -> None:
        """Clear cache."""
        self.cache.clear()
        self.logger.info(f"Cache cleared for {self.name}")

    @staticmethod
    def update_threat_level(
        current: ThreatLevel,
        new: ThreatLevel
    ) -> ThreatLevel:
        """
        Update threat level (use highest).

        Args:
            current: Current threat level
            new: New threat level

        Returns:
            Highest threat level
        """
        threat_order = {
            ThreatLevel.KNOWN_BAD: 4,
            ThreatLevel.SUSPICIOUS: 3,
            ThreatLevel.UNKNOWN: 2,
            ThreatLevel.KNOWN_GOOD: 1,
        }

        if threat_order.get(new, 0) > threat_order.get(current, 0):
            return new

        return current


class RateLimiter:
    """Simple rate limiter for API calls."""

    def __init__(self, max_calls: int = 100, window_seconds: int = 60):
        """
        Initialize rate limiter.

        Args:
            max_calls: Max calls per window
            window_seconds: Time window in seconds
        """
        self.max_calls = max_calls
        self.window_seconds = window_seconds
        self.calls: list[datetime] = []

    def is_allowed(self) -> bool:
        """
        Check if call is allowed.

        Returns:
            True if within rate limit
        """
        now = datetime.utcnow()
        cutoff = now - timedelta(seconds=self.window_seconds)

        # Remove old calls
        self.calls = [c for c in self.calls if c > cutoff]

        if len(self.calls) >= self.max_calls:
            return False

        self.calls.append(now)
        return True

    def get_remaining(self) -> int:
        """
        Get remaining calls.

        Returns:
            Number of remaining calls
        """
        now = datetime.utcnow()
        cutoff = now - timedelta(seconds=self.window_seconds)

        self.calls = [c for c in self.calls if c > cutoff]
        return max(0, self.max_calls - len(self.calls))

    def wait_if_needed(self) -> float:
        """
        Wait if rate limit reached.

        Returns:
            Seconds waited
        """
        if self.is_allowed():
            return 0.0

        if not self.calls:
            return 0.0

        oldest = self.calls[0]
        cutoff = oldest + timedelta(seconds=self.window_seconds)
        wait_seconds = (cutoff - datetime.utcnow()).total_seconds()

        return max(0.0, wait_seconds)