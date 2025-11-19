"""
IPLocation.net enrichment source.
Free GeoIP alternative to MaxMind - no database required!
"""

from typing import Any
import requests
from datetime import datetime

from src.enrichment.base import BaseEnricher, RateLimiter
from src.models.enrichment import (
    MaxMindResult,  # Reuse the same data model
    ThreatLevel,
    EnrichedIOC,
)


class IPLocationEnricher(BaseEnricher):
    """IPLocation.net GeoIP enrichment source (Free API)."""

    def __init__(self, config: dict[str, Any] | None = None):
        """
        Initialize IPLocation enricher.

        Args:
            config: Configuration dictionary
        """
        super().__init__("iplocation", config)
        self.base_url = "https://api.iplocation.net/"
        
       # No API key needed for free tier!
        # Rate limit: Be respectful, 1 request per second
        self.rate_limiter = RateLimiter(max_calls=60, window_seconds=60)
        
        self.logger.info("IPLocation.net enricher initialized (Free API, no key required)")

    def enrich_ioc(self, ioc_type: str, ioc_value: str) -> dict[str, Any]:
        """
        Enrich IP with geolocation data from IPLocation.net.

        Args:
            ioc_type: Type of IOC (must be 'ip')
            ioc_value: IP address

        Returns:
            Enrichment result
        """
        if ioc_type != "ip":
            return {}

        # Check cache
        cached = self.cache.get(f"iploc:{ioc_value}")
        if cached:
            self.logger.debug("IPLocation cache hit")
            return cached

        # Check rate limit
        if not self.rate_limiter.is_allowed():
            self.logger.warning("IPLocation rate limit reached (60 req/min)")
            return {}

        try:
            result = self._query_iplocation(ioc_value)
            
            # Cache result
            if result:
                self.cache.set(f"iploc:{ioc_value}", result)

            return result

        except Exception as e:
            self.logger.error(f"IPLocation enrichment failed: {e}")
            return {}

    def _query_iplocation(self, ip: str) -> dict[str, Any]:
        """
        Query IPLocation.net API.

        Args:
            ip: IP address to lookup

        Returns:
            API response
        """
        try:
            # Simple API call - no auth required!
            response = requests.get(
                self.base_url,
                params={"ip": ip},
                timeout=self.timeout_seconds
            )

            if response.status_code == 200:
                data = response.json()
                
                # Check if API returned valid data
                if data.get("response_code") == "200":
                    return data
                else:
                    self.logger.warning(f"IPLocation API error: {data.get('response_message', 'Unknown error')}")
                    return {}
            else:
                self.logger.warning(f"IPLocation API HTTP error: {response.status_code}")
                return {}

        except requests.exceptions.RequestException as e:
            self.logger.error(f"IPLocation API request failed: {e}")
            return {}

    def _update_enriched_ioc(
        self,
        enriched_ioc: EnrichedIOC,
        result: dict[str, Any]
    ) -> None:
        """
        Update EnrichedIOC with IPLocation result.

        Args:
            enriched_ioc: EnrichedIOC to update
            result: API result
        """
        try:
            # Map IPLocation response to MaxMindResult format
            # (reusing existing data model for compatibility)
            
            maxmind_result = MaxMindResult(
                ip_address=result.get("ip", ""),
                country_code=result.get("country_code2", ""),
                country_name=result.get("country_name", ""),
                city="",  # IPLocation free tier doesn't provide city
                postal_code="",
                latitude=0.0,  # Free tier doesn't provide coordinates
                longitude=0.0,
                isp=result.get("isp", ""),
                organization=result.get("isp", ""),  # Use ISP as org
                asn="",
                # query_type and is_private removed as they don't exist in MaxMindResult
                raw_response=result,
            )

            enriched_ioc.maxmind = maxmind_result

            self.logger.debug(
                f"IPLocation enrichment successful: {result.get('country_code2')} - {result.get('isp')}"
            )

        except Exception as e:
            self.logger.error(f"Failed to update IPLocation result: {e}")
