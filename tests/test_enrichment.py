# ============================================================================
# tests/test_enrichment.py - Enrichment Tests
# ============================================================================

"""Tests for enrichment modules."""
import pytest
from src.enrichment.base import BaseEnricher, EnrichmentCache, RateLimiter
from src.models.enrichment import EnrichedIOC, ThreatLevel


class TestEnrichmentCache:
    """Test enrichment caching."""

    def test_cache_set_and_get(self):
        """Test cache set and get."""
        cache = EnrichmentCache(ttl_seconds=60)
        cache.set("key1", {"data": "value"})
        assert cache.get("key1") == {"data": "value"}

    def test_cache_expiration(self):
        """Test cache expiration."""
        cache = EnrichmentCache(ttl_seconds=1)
        cache.set("key1", {"data": "value"})
        import time
        time.sleep(2)
        assert cache.get("key1") is None

    def test_cache_size(self):
        """Test cache size tracking."""
        cache = EnrichmentCache()
        cache.set("key1", "value1")
        cache.set("key2", "value2")
        assert cache.get_size() == 2

    def test_cache_clear(self):
        """Test cache clearing."""
        cache = EnrichmentCache()
        cache.set("key1", "value1")
        cache.clear()
        assert cache.get_size() == 0


class TestRateLimiter:
    """Test rate limiting."""

    def test_rate_limit_allowed(self):
        """Test rate limit allows calls."""
        limiter = RateLimiter(max_calls=3, window_seconds=60)
        assert limiter.is_allowed()
        assert limiter.is_allowed()
        assert limiter.is_allowed()

    def test_rate_limit_exceeded(self):
        """Test rate limit blocks calls."""
        limiter = RateLimiter(max_calls=2, window_seconds=60)
        assert limiter.is_allowed()
        assert limiter.is_allowed()
        assert not limiter.is_allowed()

    def test_rate_limit_remaining(self):
        """Test remaining calls calculation."""
        limiter = RateLimiter(max_calls=5, window_seconds=60)
        limiter.is_allowed()
        limiter.is_allowed()
        assert limiter.get_remaining() == 3


class TestEnrichedIOC:
    """Test enriched IOC."""

    def test_enriched_ioc_creation(self):
        """Test creating enriched IOC."""
        ioc = EnrichedIOC(
            type="ip",
            value="192.168.1.1",
            threat_level=ThreatLevel.SUSPICIOUS
        )
        assert ioc.type == "ip"
        assert ioc.value == "192.168.1.1"
        assert ioc.threat_level == ThreatLevel.SUSPICIOUS

    def test_enriched_ioc_serialization(self):
        """Test IOC serialization."""
        ioc = EnrichedIOC(type="ip", value="192.168.1.1")
        data = ioc.to_dict()
        assert data["type"] == "ip"
        assert data["value"] == "192.168.1.1"

    def test_threat_summary(self):
        """Test threat summary generation."""
        ioc = EnrichedIOC(type="ip", value="192.168.1.1")
        summary = ioc.get_threat_summary()
        assert isinstance(summary, str)