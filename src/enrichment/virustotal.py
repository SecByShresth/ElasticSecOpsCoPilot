"""
VirusTotal enrichment source.
Compatible with Python 3.13+
"""

from typing import Any
from datetime import datetime
import requests

from src.enrichment.base import BaseEnricher, RateLimiter
from src.models.enrichment import (
    VirusTotalResult,
    ThreatLevel,
    EnrichedIOC,
)


class VirusTotalEnricher(BaseEnricher):
    """VirusTotal enrichment source."""

    def __init__(self, config: dict[str, Any] | None = None):
        """
        Initialize VirusTotal enricher.

        Args:
            config: Configuration dictionary
        """
        super().__init__("virustotal", config)
        self.base_url = "https://www.virustotal.com/api/v3"
        
        # Get rate limits from config or use defaults
        rate_limit_config = self.config.get("rate_limit", {})
        requests_per_minute = rate_limit_config.get("requests_per_minute", 4)
        self.requests_per_day = rate_limit_config.get("requests_per_day", 500)
        self.requests_per_month = rate_limit_config.get("requests_per_month", 15500)
        
        # Initialize rate limiter for per-minute limit
        self.rate_limiter = RateLimiter(max_calls=requests_per_minute, window_seconds=60)
        
        # Track daily and monthly usage
        self.request_count_today = 0
        self.request_count_month = 0
        self.last_reset_day = datetime.utcnow().day
        self.last_reset_month = datetime.utcnow().month
        
        self.logger.info(f"VirusTotal rate limits: {requests_per_minute}/min, {self.requests_per_day}/day, {self.requests_per_month}/month")

    def _check_daily_monthly_limits(self) -> bool:
        """Check if daily or monthly quotas are exceeded."""
        now = datetime.utcnow()
        
        # Reset daily counter if new day
        if now.day != self.last_reset_day:
            self.request_count_today = 0
            self.last_reset_day = now.day
            self.logger.info("VirusTotal daily counter reset")
        
        # Reset monthly counter if new month
        if now.month != self.last_reset_month:
            self.request_count_month = 0
            self.last_reset_month = now.month
            self.logger.info("VirusTotal monthly counter reset")
        
        # Check quotas
        if self.request_count_today >= self.requests_per_day:
            self.logger.warning(f"VirusTotal daily quota reached ({self.requests_per_day}/day)")
            return False
        
        if self.request_count_month >= self.requests_per_month:
            self.logger.warning(f"VirusTotal monthly quota reached ({self.requests_per_month}/month)")
            return False
        
        return True

    def enrich_ioc(self, ioc_type: str, ioc_value: str) -> dict[str, Any]:
        """
        Enrich IOC with VirusTotal data.

        Args:
            ioc_type: Type of IOC
            ioc_value: Value of IOC

        Returns:
            Enrichment result
        """
        # Check cache
        cached = self.cache.get(f"vt:{ioc_type}:{ioc_value}")
        if cached:
            self.logger.debug("VirusTotal cache hit")
            return cached

        # Check per-minute rate limit
        if not self.rate_limiter.is_allowed():
            self.logger.warning("VirusTotal rate limit reached (4 req/min)")
            return {}
        
        # Check daily and monthly quotas
        if not self._check_daily_monthly_limits():
            return {}

        try:
            # Map IOC type to VT endpoint
            endpoint = self._get_endpoint(ioc_type)
            if not endpoint:
                return {}

            # Query VirusTotal
            result = self._query_virustotal(endpoint, ioc_value)
            
            # Increment counters on successful API call
            if result:
                self.request_count_today += 1
                self.request_count_month += 1
                self.logger.debug(f"VT usage: {self.request_count_today}/{self.requests_per_day} today, {self.request_count_month}/{self.requests_per_month} this month")

            # Cache result
            self.cache.set(f"vt:{ioc_type}:{ioc_value}", result)

            return result

        except Exception as e:
            self.logger.error(f"VirusTotal enrichment failed: {e}")
            return {}

    def _get_endpoint(self, ioc_type: str) -> str | None:
        """
        Get VirusTotal endpoint for IOC type.

        Args:
            ioc_type: Type of IOC

        Returns:
            Endpoint string or None
        """
        mapping = {
            "file_hash": "files",
            "md5": "files",
            "sha256": "files",
            "sha1": "files",
            "url": "urls",
            "domain": "domains",
            "ip": "ip_addresses",
        }

        return mapping.get(ioc_type)

    def _query_virustotal(
        self,
        endpoint: str,
        value: str
    ) -> dict[str, Any]:
        """
        Query VirusTotal API.

        Args:
            endpoint: API endpoint
            value: Value to query

        Returns:
            API response
        """
        headers = {"x-apikey": self.api_key}

        # For files, query by hash
        if endpoint == "files":
            url = f"{self.base_url}/files/{value}"
        else:
            url = f"{self.base_url}/{endpoint}/{value}"

        try:
            response = requests.get(
                url,
                headers=headers,
                timeout=self.timeout_seconds
            )

            if response.status_code == 404:
                return {"found": False}

            if response.status_code == 200:
                return response.json()

            self.logger.warning(f"VirusTotal API error: {response.status_code}")
            return {}

        except requests.exceptions.RequestException as e:
            self.logger.error(f"VirusTotal API request failed: {e}")
            return {}

    def _update_enriched_ioc(
        self,
        enriched_ioc: EnrichedIOC,
        result: dict[str, Any]
    ) -> None:
        """
        Update EnrichedIOC with VirusTotal result.

        Args:
            enriched_ioc: EnrichedIOC to update
            result: API result
        """
        try:
            data = result.get("data", {})
            attributes = data.get("attributes", {})

            # Get analysis results
            analysis = attributes.get("last_analysis_results", {})
            detected = sum(
                1 for v in analysis.values()
                if v.get("category") == "malicious"
            )
            total = len(analysis)

            vt_result = VirusTotalResult(
                indicator=enriched_ioc.value,
                indicator_type=enriched_ioc.type,
                detected=detected > 0,
                detection_ratio=f"{detected}/{total}",
                threat_level=(
                    ThreatLevel.KNOWN_BAD if detected > 0
                    else ThreatLevel.UNKNOWN
                ),
                categories=attributes.get("categories", []),
                last_analysis_date=attributes.get("last_analysis_date"),
                vendors={
                    k: v.get("category", "undetected")
                    for k, v in analysis.items()
                },
                raw_response=result,
            )

            enriched_ioc.virustotal = vt_result

            # Update threat level
            enriched_ioc.threat_level = self.update_threat_level(
                enriched_ioc.threat_level,
                vt_result.threat_level
            )

            # Update confidence
            if detected > 0:
                enriched_ioc.confidence = max(
                    enriched_ioc.confidence,
                    detected / total
                )

            self.logger.debug(f"VirusTotal enrichment successful: {detected}/{total} detected")

        except Exception as e:
            self.logger.error(f"Failed to update VirusTotal result: {e}")