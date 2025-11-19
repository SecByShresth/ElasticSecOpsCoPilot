"""
AbuseIPDB enrichment source.
Compatible with Python 3.13+
"""

from typing import Any
import requests

from src.enrichment.base import BaseEnricher, RateLimiter
from src.models.enrichment import (
    AbuseIPDBResult,
    ThreatLevel,
    EnrichedIOC,
)
from src.utils.validators import IPValidator


class AbuseIPDBEnricher(BaseEnricher):
    """AbuseIPDB enrichment source."""

    def __init__(self, config: dict[str, Any] | None = None):
        """
        Initialize AbuseIPDB enricher.

        Args:
            config: Configuration dictionary
        """
        super().__init__("abuseipdb", config)
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.rate_limiter = RateLimiter(max_calls=15, window_seconds=60)

    def enrich_ioc(self, ioc_type: str, ioc_value: str) -> dict[str, Any]:
        """
        Enrich IP with AbuseIPDB data.

        Args:
            ioc_type: Type of IOC
            ioc_value: Value of IOC

        Returns:
            Enrichment result
        """
        # Only handles IPs
        if ioc_type not in ["ip", "source_ip", "destination_ip"]:
            return {}

        # Validate IP
        if not IPValidator.is_valid_ip(ioc_value):
            return {}

        # Check cache
        cached = self.cache.get(f"abuseipdb:{ioc_value}")
        if cached:
            self.logger.debug("AbuseIPDB cache hit")
            return cached

        # Check rate limit
        if not self.rate_limiter.is_allowed():
            self.logger.warning("AbuseIPDB rate limit reached")
            return {}

        try:
            result = self._query_abuseipdb(ioc_value)
            self.cache.set(f"abuseipdb:{ioc_value}", result)
            return result

        except Exception as e:
            self.logger.error(f"AbuseIPDB enrichment failed: {e}")
            return {}

    def _query_abuseipdb(self, ip_address: str) -> dict[str, Any]:
        """
        Query AbuseIPDB API.

        Args:
            ip_address: IP address to query

        Returns:
            API response
        """
        headers = {
            "Key": self.api_key,
            "Accept": "application/json",
        }

        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": 90,
            "verbose": True,
        }

        try:
            response = requests.get(
                f"{self.base_url}/check",
                headers=headers,
                params=params,
                timeout=self.timeout_seconds
            )

            if response.status_code == 200:
                return response.json()

            self.logger.warning(f"AbuseIPDB API error: {response.status_code}")
            return {}

        except requests.exceptions.RequestException as e:
            self.logger.error(f"AbuseIPDB API request failed: {e}")
            return {}

    def _update_enriched_ioc(
        self,
        enriched_ioc: EnrichedIOC,
        result: dict[str, Any]
    ) -> None:
        """
        Update EnrichedIOC with AbuseIPDB result.

        Args:
            enriched_ioc: EnrichedIOC to update
            result: API result
        """
        try:
            data = result.get("data", {})

            # Determine threat level
            abuse_score = data.get("abuseConfidenceScore", 0)

            if abuse_score >= 75:
                threat_level = ThreatLevel.KNOWN_BAD
            elif abuse_score >= 25:
                threat_level = ThreatLevel.SUSPICIOUS
            else:
                threat_level = ThreatLevel.UNKNOWN

            abuse_result = AbuseIPDBResult(
                ip_address=enriched_ioc.value,
                abuse_confidence_score=abuse_score,
                total_reports=data.get("totalReports", 0),
                usage_type=data.get("usageType"),
                isp=data.get("isp"),
                domain=data.get("domain"),
                threat_level=threat_level,
                report_types=data.get("reportedCategories", []),
                is_whitelisted=data.get("isWhitelisted", False),
                is_vpn=data.get("isVpn", False),
                raw_response=result,
            )

            enriched_ioc.abuseipdb = abuse_result

            # Update threat level
            enriched_ioc.threat_level = self.update_threat_level(
                enriched_ioc.threat_level,
                threat_level
            )

            # Update confidence based on abuse score
            if abuse_score > 0:
                enriched_ioc.confidence = max(
                    enriched_ioc.confidence,
                    abuse_score / 100.0
                )

            self.logger.debug(f"AbuseIPDB enrichment successful: score={abuse_score}, reports={data.get('totalReports', 0)}")

        except Exception as e:
            self.logger.error(f"Failed to update AbuseIPDB result: {e}")