"""
Event and Alert data models for Elastic SecOps Copilot.
Compatible with Python 3.13+
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Set
from enum import Enum
import uuid
import json


class SeverityLevel(str, Enum):
    """Alert severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class EventStatus(str, Enum):
    """Event processing status."""
    INGESTED = "ingested"
    ENRICHED = "enriched"
    TRIAGED = "triaged"
    CORRELATED = "correlated"
    CLOSED = "closed"
    ESCALATED = "escalated"


@dataclass
class GeoLocation:
    """Geographic location information."""
    country_code: Optional[str] = None
    country_name: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    timezone: Optional[str] = None
    asn: Optional[str] = None
    isp: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class IOC:
    """Indicator of Compromise (hashable)."""
    type: str  # ip, domain, file, url, process, etc.
    value: str
    source: Optional[str] = None
    confidence: float = 0.0

    def __hash__(self) -> int:
        return hash((self.type, self.value))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, IOC):
            return NotImplemented
        return self.type == other.type and self.value == other.value

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "value": self.value,
            "source": self.source,
            "confidence": self.confidence,
        }


@dataclass
class EnrichmentData:
    """Container for enrichment results."""
    source: str  # virustotal, abuseipdb, shodan, etc.
    timestamp: datetime = field(default_factory=datetime.utcnow)
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    hit: bool = False  # True if indicator found in source

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "timestamp": self.timestamp.isoformat(),
            "data": self.data,
            "error": self.error,
            "hit": self.hit,
        }


@dataclass
class TriageResult:
    """Triage analysis result."""
    classifier: str
    classification: str
    severity: SeverityLevel
    score: float  # 0-100
    confidence: float  # 0-1
    reasoning: str
    false_positive_probability: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "classifier": self.classifier,
            "classification": self.classification,
            "severity": self.severity.value,
            "score": self.score,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
            "false_positive_probability": self.false_positive_probability,
        }


@dataclass
class MitreMapping:
    """MITRE ATT&CK technique mapping."""
    technique_id: str  # e.g., T1047
    technique_name: str
    tactic: str
    subtechnique_id: Optional[str] = None
    subtechnique_name: Optional[str] = None
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic": self.tactic,
            "subtechnique_id": self.subtechnique_id,
            "subtechnique_name": self.subtechnique_name,
            "confidence": self.confidence,
            "evidence": self.evidence,
        }


@dataclass
class CorrelationLink:
    """Link between correlated events."""
    event_id: str
    correlation_score: float
    pattern_name: str
    shared_indicators: List[IOC] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "correlation_score": self.correlation_score,
            "pattern_name": self.pattern_name,
            "shared_indicators": [ioc.to_dict() for ioc in self.shared_indicators],
        }


@dataclass
class SOCNote:
    """SOC analyst note."""
    content: str
    generated_at: datetime = field(default_factory=datetime.utcnow)
    generated_by: str = "secops-copilot"
    sections: Dict[str, str] = field(default_factory=dict)
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "content": self.content,
            "generated_at": self.generated_at.isoformat(),
            "generated_by": self.generated_by,
            "sections": self.sections,
            "references": self.references,
        }


@dataclass
class SecurityEvent:
    """
    Main security event model representing an Elastic Security alert or event.
    Designed to work with ECS (Elastic Common Schema).
    Compatible with Python 3.13+
    """

    # Identifiers
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    elastic_doc_id: Optional[str] = None
    alert_id: Optional[str] = None

    # Timing
    timestamp: datetime = field(default_factory=datetime.utcnow)
    event_timestamp: datetime = field(default_factory=datetime.utcnow)
    ingested_at: datetime = field(default_factory=datetime.utcnow)

    # Core event data (ECS fields)
    event_action: str = ""
    event_category: List[str] = field(default_factory=list)
    event_type: List[str] = field(default_factory=list)
    event_module: Optional[str] = None
    event_dataset: Optional[str] = None

    # Alert-specific
    alert_name: Optional[str] = None
    alert_description: Optional[str] = None
    rule_id: Optional[str] = None
    rule_name: Optional[str] = None

    # Host information
    host_name: Optional[str] = None
    host_id: Optional[str] = None
    host_os_name: Optional[str] = None
    host_ip: Optional[List[str]] = None

    # Process information
    process_pid: Optional[int] = None
    process_name: Optional[str] = None
    process_path: Optional[str] = None
    process_command_line: Optional[str] = None
    process_hash_md5: Optional[str] = None
    process_hash_sha256: Optional[str] = None
    process_parent_pid: Optional[int] = None
    process_parent_name: Optional[str] = None

    # File information
    file_name: Optional[str] = None
    file_path: Optional[str] = None
    file_hash_md5: Optional[str] = None
    file_hash_sha256: Optional[str] = None
    file_size: Optional[int] = None

    # Network information
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    network_protocol: Optional[str] = None
    url_full: Optional[str] = None
    domain_name: Optional[str] = None

    # User information
    user_name: Optional[str] = None
    user_id: Optional[str] = None
    user_domain: Optional[str] = None

    # Raw data
    raw_data: Dict[str, Any] = field(default_factory=dict)

    # Enrichment
    enrichments: Dict[str, List[EnrichmentData]] = field(default_factory=dict)
    iocs: Set[IOC] = field(default_factory=set)
    geo_source: Optional[GeoLocation] = None
    geo_destination: Optional[GeoLocation] = None

    # Triage
    triage_result: Optional[TriageResult] = None
    severity: SeverityLevel = SeverityLevel.INFO

    # MITRE mapping
    mitre_mappings: List[MitreMapping] = field(default_factory=list)

    # Correlation
    correlated_events: List[CorrelationLink] = field(default_factory=list)
    correlation_group_id: Optional[str] = None

    # Notes & remediation
    soc_note: Optional[SOCNote] = None
    remediation_steps: List[str] = field(default_factory=list)

    # Status tracking
    status: EventStatus = EventStatus.INGESTED
    status_history: List[tuple[EventStatus, datetime]] = field(default_factory=list)

    # Metadata
    tags: List[str] = field(default_factory=list)
    custom_fields: Dict[str, Any] = field(default_factory=dict)

    def add_status(self, status: EventStatus) -> None:
        """Record status change."""
        self.status = status
        self.status_history.append((status, datetime.utcnow()))

    def add_enrichment(self, source: str, data: EnrichmentData) -> None:
        """Add enrichment data."""
        if source not in self.enrichments:
            self.enrichments[source] = []
        self.enrichments[source].append(data)

    def add_ioc(self, ioc: IOC) -> None:
        """Add IOC."""
        self.iocs.add(ioc)

    def add_tag(self, tag: str) -> None:
        """Add tag."""
        if tag not in self.tags:
            self.tags.append(tag)

    def to_dict(self, include_raw: bool = False) -> Dict[str, Any]:
        """Convert to dictionary."""
        data = {
            "event_id": self.event_id,
            "elastic_doc_id": self.elastic_doc_id,
            "alert_id": self.alert_id,
            "timestamp": self.timestamp.isoformat(),
            "ingested_at": self.ingested_at.isoformat(),
            "event_action": self.event_action,
            "event_category": self.event_category,
            "event_type": self.event_type,
            "alert_name": self.alert_name,
            "rule_id": self.rule_id,
            "host_name": self.host_name,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "user_name": self.user_name,
            "severity": self.severity.value,
            "status": self.status.value,
            "tags": self.tags,
            "enrichments": {
                k: [e.to_dict() for e in v]
                for k, v in self.enrichments.items()
            },
            "iocs": [ioc.to_dict() for ioc in self.iocs],
            "triage": self.triage_result.to_dict() if self.triage_result else None,
            "mitre_mappings": [m.to_dict() for m in self.mitre_mappings],
            "correlated_events": [c.to_dict() for c in self.correlated_events],
            "soc_note": self.soc_note.to_dict() if self.soc_note else None,
            "remediation_steps": self.remediation_steps,
            "custom_fields": self.custom_fields,
        }

        if include_raw:
            data["raw_data"] = self.raw_data

        return data

    def to_json(self, **kwargs: Any) -> str:
        """Convert to JSON."""
        return json.dumps(self.to_dict(**kwargs), default=str, indent=2)

    @staticmethod
    def from_elastic_alert(alert: Dict[str, Any]) -> "SecurityEvent":
        """Create SecurityEvent from Elastic alert document."""
        event = SecurityEvent()
        event.elastic_doc_id = alert.get("_id")
        event.raw_data = alert.get("_source", {})

        source = alert.get("_source", {})

        # Parse timestamp
        if "@timestamp" in source:
            ts_str = source["@timestamp"]
            if isinstance(ts_str, str):
                event.timestamp = datetime.fromisoformat(
                    ts_str.replace("Z", "+00:00")
                )
                event.event_timestamp = event.timestamp

        # Alert fields
        if "alert" in source:
            alert_data = source["alert"]
            event.alert_id = alert_data.get("uuid")
            event.alert_name = alert_data.get("title")
            event.alert_description = alert_data.get("description")
            event.rule_id = alert_data.get("rule", {}).get("id")
            event.rule_name = alert_data.get("rule", {}).get("name")

        # Event fields
        if "event" in source:
            event_data = source["event"]
            event.event_action = event_data.get("action", "")
            event.event_category = event_data.get("category", [])
            event.event_type = event_data.get("type", [])
            event.event_module = event_data.get("module")
            event.event_dataset = event_data.get("dataset")

        # Host fields
        if "host" in source:
            host_data = source["host"]
            event.host_name = host_data.get("name")
            event.host_id = host_data.get("id")
            if "os" in host_data:
                event.host_os_name = host_data["os"].get("name")
            if "ip" in host_data:
                host_ip = host_data["ip"]
                event.host_ip = host_ip if isinstance(host_ip, list) else [host_ip]

        # Process fields
        if "process" in source:
            proc_data = source["process"]
            event.process_pid = proc_data.get("pid")
            event.process_name = proc_data.get("name")
            event.process_path = proc_data.get("executable")
            event.process_command_line = proc_data.get("command_line")
            if "hash" in proc_data:
                event.process_hash_md5 = proc_data["hash"].get("md5")
                event.process_hash_sha256 = proc_data["hash"].get("sha256")
            if "parent" in proc_data:
                event.process_parent_pid = proc_data["parent"].get("pid")
                event.process_parent_name = proc_data["parent"].get("name")

        # File fields
        if "file" in source:
            file_data = source["file"]
            event.file_name = file_data.get("name")
            event.file_path = file_data.get("path")
            if "hash" in file_data:
                event.file_hash_md5 = file_data["hash"].get("md5")
                event.file_hash_sha256 = file_data["hash"].get("sha256")
            event.file_size = file_data.get("size")

        # Network fields
        if "source" in source:
            source_data = source["source"]
            event.source_ip = source_data.get("ip")
            event.source_port = source_data.get("port")

        if "destination" in source:
            dest_data = source["destination"]
            event.destination_ip = dest_data.get("ip")
            event.destination_port = dest_data.get("port")

        if "network" in source:
            event.network_protocol = source["network"].get("protocol")

        if "url" in source:
            event.url_full = source["url"].get("full")

        if "dns" in source:
            event.domain_name = source["dns"].get("question", {}).get("name")

        # User fields
        if "user" in source:
            user_data = source["user"]
            event.user_name = user_data.get("name")
            event.user_id = user_data.get("id")
            event.user_domain = user_data.get("domain")

        return event