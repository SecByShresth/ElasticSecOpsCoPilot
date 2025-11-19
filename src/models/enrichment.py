"""
Enrichment result models.
Compatible with Python 3.13+
Uses native type syntax (PEP 585 & 604)
"""

from dataclasses import dataclass, field
from typing import Any
from datetime import datetime
from enum import Enum


class ThreatLevel(str, Enum):
    """Threat classification levels."""
    KNOWN_BAD = "known_bad"
    SUSPICIOUS = "suspicious"
    UNKNOWN = "unknown"
    KNOWN_GOOD = "known_good"


@dataclass
class VirusTotalResult:
    """VirusTotal enrichment result."""
    indicator: str
    indicator_type: str  # file, domain, url, ip
    detected: bool = False
    detection_ratio: str = "0/0"  # e.g., "5/72"
    threat_level: ThreatLevel = ThreatLevel.UNKNOWN
    categories: list[str] = field(default_factory=list)
    last_analysis_date: str | None = None
    vendors: dict[str, str] = field(default_factory=dict)  # vendor -> classification
    raw_response: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "indicator": self.indicator,
            "indicator_type": self.indicator_type,
            "detected": self.detected,
            "detection_ratio": self.detection_ratio,
            "threat_level": self.threat_level.value,
            "categories": self.categories,
            "last_analysis_date": self.last_analysis_date,
            "vendors_count": len(self.vendors),
        }


@dataclass
class AbuseIPDBResult:
    """AbuseIPDB enrichment result."""
    ip_address: str
    abuse_confidence_score: float  # 0-100
    total_reports: int = 0
    usage_type: str | None = None
    isp: str | None = None
    domain: str | None = None
    threat_level: ThreatLevel = ThreatLevel.UNKNOWN
    report_types: list[str] = field(default_factory=list)
    is_whitelisted: bool = False
    is_vpn: bool = False
    raw_response: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "ip_address": self.ip_address,
            "abuse_confidence_score": self.abuse_confidence_score,
            "total_reports": self.total_reports,
            "usage_type": self.usage_type,
            "isp": self.isp,
            "domain": self.domain,
            "threat_level": self.threat_level.value,
            "is_whitelisted": self.is_whitelisted,
            "is_vpn": self.is_vpn,
            "report_types": self.report_types,
        }


@dataclass
class ShodanResult:
    """Shodan enrichment result."""
    ip_address: str
    found: bool = False
    organization: str | None = None
    asn: str | None = None
    country_code: str | None = None
    country_name: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    ports: list[int] = field(default_factory=list)
    services: list[dict[str, Any]] = field(default_factory=list)
    vulnerabilities: list[str] = field(default_factory=list)
    last_update: str | None = None
    raw_response: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "ip_address": self.ip_address,
            "found": self.found,
            "organization": self.organization,
            "asn": self.asn,
            "country_code": self.country_code,
            "country_name": self.country_name,
            "city": self.city,
            "ports_count": len(self.ports),
            "services_count": len(self.services),
            "vulnerabilities_count": len(self.vulnerabilities),
            "ports": self.ports[:20],  # Return first 20 ports
        }


@dataclass
class MaxMindResult:
    """MaxMind GeoIP enrichment result."""
    ip_address: str
    country_code: str | None = None
    country_name: str | None = None
    subdivision_code: str | None = None
    subdivision_name: str | None = None
    city: str | None = None
    postal_code: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    timezone: str | None = None
    accuracy_radius: int | None = None
    asn: str | None = None
    isp: str | None = None
    organization: str | None = None
    is_anonymous_proxy: bool = False
    is_satellite_provider: bool = False
    raw_response: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "ip_address": self.ip_address,
            "country_code": self.country_code,
            "country_name": self.country_name,
            "city": self.city,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "timezone": self.timezone,
            "asn": self.asn,
            "isp": self.isp,
            "is_anonymous_proxy": self.is_anonymous_proxy,
            "is_satellite_provider": self.is_satellite_provider,
        }


@dataclass
class WhoisResult:
    """WHOIS enrichment result."""
    query: str
    query_type: str  # domain, ip
    found: bool = False
    registrar: str | None = None
    registrant_name: str | None = None
    registrant_country: str | None = None
    registrant_email: str | None = None
    creation_date: str | None = None
    expiration_date: str | None = None
    updated_date: str | None = None
    name_servers: list[str] = field(default_factory=list)
    status: list[str] = field(default_factory=list)
    is_private: bool = False
    raw_response: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "query": self.query,
            "query_type": self.query_type,
            "found": self.found,
            "registrar": self.registrar,
            "registrant_country": self.registrant_country,
            "creation_date": self.creation_date,
            "expiration_date": self.expiration_date,
            "is_private": self.is_private,
            "name_servers_count": len(self.name_servers),
        }


@dataclass
class EnrichedIOC:
    """IOC with all enrichment data applied."""
    type: str  # ip, domain, file, url, process, etc.
    value: str
    threat_level: ThreatLevel = ThreatLevel.UNKNOWN
    confidence: float = 0.0

    virustotal: VirusTotalResult | None = None
    abuseipdb: AbuseIPDBResult | None = None
    shodan: ShodanResult | None = None
    maxmind: MaxMindResult | None = None
    whois: WhoisResult | None = None

    enriched_at: datetime = field(default_factory=datetime.utcnow)
    sources_checked: list[str] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "type": self.type,
            "value": self.value,
            "threat_level": self.threat_level.value,
            "confidence": self.confidence,
            "virustotal": self.virustotal.to_dict() if self.virustotal else None,
            "abuseipdb": self.abuseipdb.to_dict() if self.abuseipdb else None,
            "shodan": self.shodan.to_dict() if self.shodan else None,
            "maxmind": self.maxmind.to_dict() if self.maxmind else None,
            "whois": self.whois.to_dict() if self.whois else None,
            "enriched_at": self.enriched_at.isoformat(),
            "sources_checked": self.sources_checked,
        }

    def get_threat_summary(self) -> str:
        """Generate threat summary from enrichment data."""
        summaries: list[str] = []

        if self.virustotal and self.virustotal.detected:
            summaries.append(f"VirusTotal: {self.virustotal.detection_ratio}")

        if self.abuseipdb and self.abuseipdb.abuse_confidence_score > 50:
            summaries.append(
                f"AbuseIPDB: {self.abuseipdb.abuse_confidence_score}% confidence"
            )

        if self.shodan and self.shodan.found and self.shodan.vulnerabilities:
            summaries.append(f"Shodan: {len(self.shodan.vulnerabilities)} vulns found")

        if self.whois and self.whois.is_private:
            summaries.append("WHOIS: Private registration")

        return " | ".join(summaries) if summaries else "No threats detected"