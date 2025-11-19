# ============================================================================
# src/models/__init__.py
# ============================================================================

"""
Data models for Elastic SecOps Copilot.
"""

from src.models.event import (
    SecurityEvent,
    SeverityLevel,
    EventStatus,
    IOC,
    EnrichmentData,
    TriageResult,
    MitreMapping,
    CorrelationLink,
    SOCNote,
    GeoLocation,
)

from src.models.enrichment import (
    ThreatLevel,
    VirusTotalResult,
    AbuseIPDBResult,
    ShodanResult,
    MaxMindResult,
    WhoisResult,
    EnrichedIOC,
)

from src.models.correlation import (
    CorrelationPattern,
    CorrelationPatternType,
    CorrelationMatch,
    CorrelationCluster,
    EventSequence,
    CorrelationResult,
)

__all__ = [
    # Event models
    "SecurityEvent",
    "SeverityLevel",
    "EventStatus",
    "IOC",
    "EnrichmentData",
    "TriageResult",
    "MitreMapping",
    "CorrelationLink",
    "SOCNote",
    "GeoLocation",

    # Enrichment models
    "ThreatLevel",
    "VirusTotalResult",
    "AbuseIPDBResult",
    "ShodanResult",
    "MaxMindResult",
    "WhoisResult",
    "EnrichedIOC",

    # Correlation models
    "CorrelationPattern",
    "CorrelationPatternType",
    "CorrelationMatch",
    "CorrelationCluster",
    "EventSequence",
    "CorrelationResult",
]