# ============================================================================
# FILE 1: src/models/correlation.py
# ============================================================================
"""
Correlation and pattern matching models.
Compatible with Python 3.13+
Uses native type syntax (PEP 585 & 604)
"""

from dataclasses import dataclass, field
from typing import Any
from datetime import datetime
from enum import Enum
import uuid


class CorrelationPatternType(str, Enum):
    """Correlation pattern types."""
    SAME_SOURCE = "same_source"
    SAME_DESTINATION = "same_destination"
    SAME_USER = "same_user"
    SAME_PROCESS = "same_process"
    SAME_FILE_HASH = "same_file_hash"
    SAME_DOMAIN = "same_domain"
    SAME_IP = "same_ip"
    SEQUENTIAL = "sequential"  # Events in sequence
    BEHAVIORAL_CHAIN = "behavioral_chain"
    MULTI_STAGE_ATTACK = "multi_stage_attack"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION = "data_exfiltration"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"


@dataclass
class CorrelationPattern:
    """Defines a correlation pattern for event grouping."""
    name: str
    pattern_type: CorrelationPatternType
    description: str
    conditions: list[str]  # Conditions that must be met
    threshold: int  # Minimum events to correlate
    time_window_seconds: int  # Time window for correlation
    weight: float = 1.0  # Weighting for this pattern
    enabled: bool = True
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "name": self.name,
            "pattern_type": self.pattern_type.value,
            "description": self.description,
            "threshold": self.threshold,
            "time_window_seconds": self.time_window_seconds,
            "weight": self.weight,
            "enabled": self.enabled,
        }


@dataclass
class CorrelationMatch:
    """A match of events to a correlation pattern."""
    pattern: CorrelationPattern
    matched_events: list[str]  # event_ids
    match_score: float  # 0-1
    first_event_time: datetime
    last_event_time: datetime
    matched_indicators: dict[str, Any] = field(default_factory=dict)
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "pattern_name": self.pattern.name,
            "pattern_type": self.pattern.pattern_type.value,
            "matched_event_count": len(self.matched_events),
            "match_score": self.match_score,
            "time_span_seconds": (
                self.last_event_time - self.first_event_time
            ).total_seconds(),
            "evidence": self.evidence,
        }


@dataclass
class CorrelationCluster:
    """A cluster of correlated events."""
    cluster_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = field(default_factory=datetime.utcnow)
    event_ids: set[str] = field(default_factory=set)
    patterns_matched: list[CorrelationMatch] = field(default_factory=list)

    # Cluster metadata
    primary_pattern: CorrelationPattern | None = None
    cluster_score: float = 0.0
    cluster_severity: str | None = None
    cluster_ttl_seconds: int = 3600

    # Timeline info
    first_event_time: datetime | None = None
    last_event_time: datetime | None = None

    # Narrative
    narrative: str = ""
    indicators: dict[str, set[str]] = field(default_factory=dict)

    def add_event(self, event_id: str, timestamp: datetime) -> None:
        """Add event to cluster."""
        self.event_ids.add(event_id)

        if self.first_event_time is None or timestamp < self.first_event_time:
            self.first_event_time = timestamp

        if self.last_event_time is None or timestamp > self.last_event_time:
            self.last_event_time = timestamp

    def add_pattern_match(self, match: CorrelationMatch) -> None:
        """Add pattern match to cluster."""
        self.patterns_matched.append(match)

        if self.primary_pattern is None:
            self.primary_pattern = match.pattern

        # Update cluster score
        self.cluster_score = max(
            self.cluster_score,
            match.match_score * match.pattern.weight
        )

    def add_indicator(self, indicator_type: str, value: str) -> None:
        """Add indicator to cluster."""
        if indicator_type not in self.indicators:
            self.indicators[indicator_type] = set()
        self.indicators[indicator_type].add(value)

    def is_expired(self) -> bool:
        """Check if cluster has expired."""
        if self.last_event_time is None:
            return False

        age_seconds = (
            datetime.utcnow() - self.last_event_time
        ).total_seconds()
        return age_seconds > self.cluster_ttl_seconds

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        time_span = (
            (self.last_event_time - self.first_event_time).total_seconds()
            if self.first_event_time and self.last_event_time
            else 0
        )

        return {
            "cluster_id": self.cluster_id,
            "created_at": self.created_at.isoformat(),
            "event_count": len(self.event_ids),
            "patterns_matched": len(self.patterns_matched),
            "primary_pattern": (
                self.primary_pattern.name
                if self.primary_pattern
                else None
            ),
            "cluster_score": self.cluster_score,
            "cluster_severity": self.cluster_severity,
            "time_span_seconds": time_span,
            "indicator_types": list(self.indicators.keys()),
            "narrative": self.narrative,
        }


@dataclass
class EventSequence:
    """A sequence of events over time."""
    sequence_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    events: list[tuple[str, datetime]] = field(default_factory=list)

    # Sequence metadata
    host_name: str | None = None
    user_name: str | None = None
    source_ip: str | None = None

    # Attack chain
    attack_chain: list[str] = field(default_factory=list)
    severity_progression: list[int] = field(default_factory=list)

    def add_event(self, event_id: str, timestamp: datetime) -> None:
        """Add event to sequence, maintaining chronological order."""
        self.events.append((event_id, timestamp))
        self.events.sort(key=lambda x: x[1])

    def get_duration(self) -> float:
        """Get duration of sequence in seconds."""
        if len(self.events) < 2:
            return 0.0

        first_time = self.events[0][1]
        last_time = self.events[-1][1]
        return (last_time - first_time).total_seconds()

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        avg_severity = (
            sum(self.severity_progression) / len(self.severity_progression)
            if self.severity_progression
            else 0
        )

        return {
            "sequence_id": self.sequence_id,
            "event_count": len(self.events),
            "host_name": self.host_name,
            "user_name": self.user_name,
            "source_ip": self.source_ip,
            "duration_seconds": self.get_duration(),
            "attack_chain": self.attack_chain,
            "avg_severity": avg_severity,
        }


@dataclass
class CorrelationResult:
    """Overall correlation analysis result."""
    event_id: str
    correlation_performed_at: datetime = field(default_factory=datetime.utcnow)

    # Clusters and matches
    correlated_clusters: list[CorrelationCluster] = field(default_factory=list)
    direct_correlations: list[str] = field(default_factory=list)  # event_ids

    # Attack sequences
    sequences: list[EventSequence] = field(default_factory=list)

    # Intelligence
    is_part_of_campaign: bool = False
    campaign_id: str | None = None
    campaign_name: str | None = None

    # Severity escalation
    severity_escalation_detected: bool = False
    escalation_reason: str | None = None

    # Summary
    total_correlated_events: int = 0
    patterns_matched: int = 0
    cluster_score: float = 0.0  # ✅ FIX #1: ADDED THIS LINE
    confidence: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "event_id": self.event_id,
            "correlation_performed_at": (
                self.correlation_performed_at.isoformat()
            ),
            "cluster_count": len(self.correlated_clusters),
            "direct_correlations": len(self.direct_correlations),
            "sequences": len(self.sequences),
            "total_correlated_events": self.total_correlated_events,
            "patterns_matched": self.patterns_matched,
            "cluster_score": self.cluster_score,  # ✅ FIX #1: ADDED THIS LINE
            "confidence": self.confidence,
            "is_part_of_campaign": self.is_part_of_campaign,
            "severity_escalation_detected": (
                self.severity_escalation_detected
            ),
            "clusters": [c.to_dict() for c in self.correlated_clusters],
        }