"""
WHOIS enrichment source.
Compatible with Python 3.13+
"""

from typing import Any
import whois

from src.enrichment.base import BaseEnricher
from src.models.enrichment import (
    WhoisResult,
    ThreatLevel,
    EnrichedIOC,
)
from src.utils.validators import DomainValidator, IPValidator


class WhoisEnricher(BaseEnricher):
    """WHOIS enrichment source for domain and IP registration data."""

    def __init__(self, config: dict[str, Any] | None = None):
        """
        Initialize WHOIS enricher.

        Args:
            config: Configuration dictionary
        """
        super().__init__("whois", config)

    def enrich_ioc(self, ioc_type: str, ioc_value: str) -> dict[str, Any]:
        """
        Enrich domain or IP with WHOIS data.

        Args:
            ioc_type: Type of IOC
            ioc_value: Value of IOC

        Returns:
            Enrichment result
        """
        # Handle domains and IPs
        if ioc_type == "domain":
            if not DomainValidator.is_valid_domain(ioc_value):
                return {}
        elif ioc_type == "ip":
            if not IPValidator.is_valid_ip(ioc_value):
                return {}
        else:
            return {}

        # Check cache
        cached = self.cache.get(f"whois:{ioc_value}")
        if cached:
            self.logger.debug("WHOIS cache hit")
            return cached

        try:
            result = self._query_whois(ioc_value)
            self.cache.set(f"whois:{ioc_value}", result)
            return result

        except Exception as e:
            self.logger.debug(f"WHOIS enrichment failed for {ioc_value}: {e}")
            return {}

    def _query_whois(self, value: str) -> dict[str, Any]:
        """
        Query WHOIS database.

        Args:
            value: Domain or IP to query

        Returns:
            WHOIS data
        """
        try:
            result = whois.whois(value)

            # Convert result to dict for serialization
            result_dict = {}

            # Standard WHOIS fields
            for key in [
                "domain_name",
                "registrar",
                "registrant_name",
                "registrant_email",
                "registrant_country",
                "creation_date",
                "expiration_date",
                "updated_date",
                "name_servers",
                "status",
            ]:
                if hasattr(result, key):
                    value = getattr(result, key)
                    if value:
                        if isinstance(value, (list, tuple)):
                            result_dict[key] = [str(v) for v in value]
                        else:
                            result_dict[key] = str(value)

            # Additional info
            result_dict["raw_data"] = str(result)

            return result_dict if result_dict else {}

        except whois.parser.PywhoisError as e:
            self.logger.debug(f"WHOIS lookup not found: {value}")
            return {}

        except Exception as e:
            self.logger.error(f"WHOIS query error: {e}")
            return {}

    def _update_enriched_ioc(
        self,
        enriched_ioc: EnrichedIOC,
        result: dict[str, Any]
    ) -> None:
        """
        Update EnrichedIOC with WHOIS result.

        Args:
            enriched_ioc: EnrichedIOC to update
            result: WHOIS data
        """
        try:
            if not result:
                return

            # Detect if private registration
            is_private = self._is_private_registration(result)

            # Threat level: private registrations can be suspicious
            threat_level = ThreatLevel.SUSPICIOUS if is_private else ThreatLevel.UNKNOWN

            whois_result = WhoisResult(
                query=enriched_ioc.value,
                query_type="domain" if "." in enriched_ioc.value else "ip",
                found=True,
                registrar=result.get("registrar"),
                registrant_name=result.get("registrant_name"),
                registrant_country=result.get("registrant_country"),
                registrant_email=result.get("registrant_email"),
                creation_date=result.get("creation_date"),
                expiration_date=result.get("expiration_date"),
                updated_date=result.get("updated_date"),
                name_servers=result.get("name_servers", []),
                status=result.get("status", []),
                is_private=is_private,
                raw_response=result.get("raw_data", ""),
            )

            enriched_ioc.whois = whois_result

            # Update threat level for private registrations
            if is_private:
                enriched_ioc.threat_level = self.update_threat_level(
                    enriched_ioc.threat_level,
                    threat_level
                )
                enriched_ioc.confidence = max(
                    enriched_ioc.confidence,
                    0.5
                )

            self.logger.debug(f"WHOIS enrichment successful for {enriched_ioc.value} (private={is_private})")

        except Exception as e:
            self.logger.error(f"Failed to update WHOIS result: {e}")

    @staticmethod
    def _is_private_registration(result: dict[str, Any]) -> bool:
        """
        Check if registration is private.

        Args:
            result: WHOIS result

        Returns:
            True if private
        """
        # Check for privacy service indicators
        privacy_indicators = [
            "privacy",
            "redacted",
            "protected",
            "proxy",
            "private",
            "confidential",
        ]

        result_str = str(result).lower()

        return any(indicator in result_str for indicator in privacy_indicators)