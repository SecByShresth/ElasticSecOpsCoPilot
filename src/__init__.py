# ============================================================================
# src/__init__.py
# ============================================================================

"""
Elastic SecOps Copilot - Security automation and enrichment platform.
Integrates with Elastic Cloud, Serverless, or Self-Hosted deployments.

Compatible with Python 3.13+
"""

__version__ = "1.0.0"
__author__ = "SecOps Team"
__license__ = "MIT"

# Import main models for easy access
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

# Import utilities
from src.utils.logger import (
    get_default_logger,
    setup_logging,
    LoggerConfig,
)

from src.utils.config_loader import (
    get_config,
    load_config,
    ConfigLoader,
    ConfigError,
)

from src.utils.validators import (
    IPValidator,
    DomainValidator,
    URLValidator,
    HashValidator,
    EmailValidator,
    IOCValidator,
    SeverityValidator,
    ValidationError,
)

__all__ = [
    # Version
    "__version__",

    # Models - Event
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

    # Models - Enrichment
    "ThreatLevel",
    "VirusTotalResult",
    "AbuseIPDBResult",
    "ShodanResult",
    "MaxMindResult",
    "WhoisResult",
    "EnrichedIOC",

    # Models - Correlation
    "CorrelationPattern",
    "CorrelationPatternType",
    "CorrelationMatch",
    "CorrelationCluster",
    "EventSequence",
    "CorrelationResult",

    # Utils
    "get_default_logger",
    "setup_logging",
    "LoggerConfig",
    "get_config",
    "load_config",
    "ConfigLoader",
    "ConfigError",
    "IPValidator",
    "DomainValidator",
    "URLValidator",
    "HashValidator",
    "EmailValidator",
    "IOCValidator",
    "SeverityValidator",
    "ValidationError",
]

# ============================================================================
# src/utils/__init__.py
# ============================================================================

"""
Utility modules for Elastic SecOps Copilot.
"""

from src.utils.logger import (
    LoggerConfig,
    setup_logging,
    get_default_logger,
    log_exception,
)

from src.utils.config_loader import (
    ConfigLoader,
    ConfigError,
    load_config,
    get_config,
)

from src.utils.validators import (
    ValidationError,
    IPValidator,
    DomainValidator,
    URLValidator,
    HashValidator,
    EmailValidator,
    IOCValidator,
    SeverityValidator,
)

__all__ = [
    # Logger
    "LoggerConfig",
    "setup_logging",
    "get_default_logger",
    "log_exception",

    # Config
    "ConfigLoader",
    "ConfigError",
    "load_config",
    "get_config",

    # Validators
    "ValidationError",
    "IPValidator",
    "DomainValidator",
    "URLValidator",
    "HashValidator",
    "EmailValidator",
    "IOCValidator",
    "SeverityValidator",
]