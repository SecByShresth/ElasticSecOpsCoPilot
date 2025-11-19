"""
Shodan enrichment source.
Compatible with Python 3.13+
"""

from typing import Any
import requests

from src.enrichment.base import BaseEnricher, RateLimiter
from src.models.enrichment import (
    ShodanResult,
    ThreatLevel,
    EnrichedIOC,
)
from src.utils.validators import IPValidator


class ShodanEnricher(BaseEnricher):
    """Shodan enrichment source for IP reconnaissance."""

    def __init__(self, config: dict[str, Any] | None = None):
        """
        Initialize Shodan enricher.

        Args:
            config: Configuration dictionary
        """
        super().__init__("shodan", config)
        self.base_url = "https://api.shodan.io"
        self.rate_limiter = RateLimiter(max_calls=1, window_seconds=1)

    def enrich_ioc(self, ioc_type: str, ioc_value: str) -> dict[str, Any]:
        """
        Enrich IP with Shodan data.

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
        cached = self.cache.get(f"shodan:{ioc_value}")
        if cached:
            self.logger.debug("Shodan cache hit")
            return cached

        # Check rate limit
        if not self.rate_limiter.is_allowed():
            self.logger.warning("Shodan rate limit reached")
            return {}

        try:
            result = self._query_shodan(ioc_value)
            self.cache.set(f"shodan:{ioc_value}", result)
            return result

        except Exception as e:
            self.logger.error(f"Shodan enrichment failed: {e}")
            return {}

    def _query_shodan(self, ip_address: str) -> dict[str, Any]:
        """
        Query Shodan API.

        Args:
            ip_address: IP address to query

        Returns:
            API response
        """
        params = {
            "key": self.api_key,
            "minify": False,
        }

        try:
            response = requests.get(
                f"{self.base_url}/shodan/host/{ip_address}",
                params=params,
                timeout=self.timeout_seconds
            )

            if response.status_code == 404:
                return {"found": False}

            if response.status_code == 200:
                return response.json()

            if response.status_code == 401:
                self.logger.error("Shodan API key invalid or expired")
                return {}

            self.logger.warning(f"Shodan API error: {response.status_code} - {response.text[:200]}")
            return {}

        except requests.exceptions.Timeout:
            self.logger.warning("Shodan API timeout")
            return {}

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Shodan API request failed: {e}")
            return {}

    def _update_enriched_ioc(
        self,
        enriched_ioc: EnrichedIOC,
        result: dict[str, Any]
    ) -> None:
        """
        Update EnrichedIOC with Shodan result.

        Args:
            enriched_ioc: EnrichedIOC to update
            result: API result
        """
        try:
            # Extract data
            ports = result.get("ports", [])
            vulns = result.get("vulns", [])
            services = []

            # Build services list from data
            if "data" in result:
                for item in result.get("data", []):
                    services.append({
                        "port": item.get("port"),
                        "protocol": item.get("transport"),
                        "product": item.get("product"),
                        "banner": item.get("data", "")[:100]
                    })

            # Determine threat level
            threat_level = ThreatLevel.UNKNOWN
            if vulns:
                threat_level = ThreatLevel.SUSPICIOUS
            if len(ports) > 5:  # Many open ports
                threat_level = ThreatLevel.SUSPICIOUS

            shodan_result = ShodanResult(
                ip_address=enriched_ioc.value,
                found=True,
                organization=result.get("org"),
                asn=result.get("asn"),
                country_code=result.get("country_code"),
                country_name=result.get("country_name"),
                city=result.get("city"),
                latitude=result.get("latitude"),
                longitude=result.get("longitude"),
                ports=ports[:20],  # Limit to first 20
                services=services[:10],  # Limit to first 10
                vulnerabilities=vulns[:10],  # Limit to first 10
                last_update=result.get("last_update"),
                raw_response=result,
            )

            enriched_ioc.shodan = shodan_result

            # Update threat level
            enriched_ioc.threat_level = self.update_threat_level(
                enriched_ioc.threat_level,
                threat_level
            )

            # Update confidence based on findings
            if vulns or len(ports) > 3:
                enriched_ioc.confidence = max(
                    enriched_ioc.confidence,
                    min(0.8, 0.5 + len(vulns) * 0.1)
                )

            self.logger.debug(f"Shodan enrichment successful: {len(ports)} ports, {len(vulns)} vulns")

        except Exception as e:
            self.logger.error(f"Failed to update Shodan result: {e}")