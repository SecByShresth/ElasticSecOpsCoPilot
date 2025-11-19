# ============================================================================
# FILE 2: src/correlation/engine.py
# ============================================================================

"""Event correlation engine."""
from typing import Any
from datetime import datetime, timedelta
from src.models.event import SecurityEvent
from src.models.correlation import (
    CorrelationCluster,
    CorrelationPattern,
    CorrelationMatch,
    CorrelationResult,
)
from src.utils.logger import get_default_logger


class CorrelationEngine:
    """Correlates events to find attack patterns."""

    def __init__(self, patterns: list[CorrelationPattern] | None = None):
        """
        Initialize correlation engine.

        Args:
            patterns: List of correlation patterns
        """
        self.patterns = patterns or self._get_default_patterns()
        self.clusters: dict[str, CorrelationCluster] = {}
        self.logger = get_default_logger(level="INFO")

    def correlate(self, event: SecurityEvent) -> CorrelationResult | None:
        """
        Correlate event with existing events.

        Args:
            event: SecurityEvent to correlate

        Returns:
            CorrelationResult or None if no matches
        """
        result = CorrelationResult(event_id=event.event_id)

        # Try to match patterns
        for pattern in self.patterns:
            if not pattern.enabled:
                continue

            cluster = self._find_matching_cluster(event, pattern)

            if cluster:
                result.correlated_clusters.append(cluster)
                result.patterns_matched += 1
                result.total_correlated_events += len(cluster.event_ids)
                result.cluster_score = max(result.cluster_score, cluster.cluster_score)

                # ✅ FIX #2: Use 'extra' parameter for logger
                self.logger.info(
                    "Pattern matched",
                    extra={
                        "pattern": pattern.name,
                        "events": len(cluster.event_ids)
                    }
                )

        # Return result if any matches found
        if result.patterns_matched > 0:
            result.confidence = min(1.0, result.patterns_matched / len(self.patterns))
            return result

        return None

    def _find_matching_cluster(
        self,
        event: SecurityEvent,
        pattern: CorrelationPattern
    ) -> CorrelationCluster | None:
        """Find or create matching cluster."""
        if pattern.name == "multi_failed_login_detection":
            return self._match_failed_logins(event, pattern)

        elif pattern.name == "lateral_movement":
            return self._match_lateral_movement(event, pattern)

        elif pattern.name == "data_exfiltration_chain":
            return self._match_data_exfiltration(event, pattern)

        return None

    def _match_failed_logins(
        self,
        event: SecurityEvent,
        pattern: CorrelationPattern
    ) -> CorrelationCluster | None:
        """Match failed login pattern."""
        if "failed" not in (event.alert_name or "").lower():
            return None

        # Create cluster
        cluster = CorrelationCluster()
        cluster.add_event(event.event_id, event.timestamp)

        if event.user_name:
            cluster.add_indicator("user", event.user_name)

        if event.source_ip:
            cluster.add_indicator("source_ip", event.source_ip)

        if event.host_name:
            cluster.add_indicator("host", event.host_name)

        cluster.primary_pattern = pattern
        cluster.cluster_score = 0.8
        cluster.narrative = (
            f"Failed authentication attempts detected "
            f"for user {event.user_name} on {event.host_name}"
        )

        return cluster

    def _match_lateral_movement(
        self,
        event: SecurityEvent,
        pattern: CorrelationPattern
    ) -> CorrelationCluster | None:
        """Match lateral movement pattern."""
        # Check for lateral movement indicators
        lateral_indicators = [
            event.network_protocol in ["ssh", "rdp", "smb", "winrm"],
            "lateral" in (event.alert_name or "").lower(),
            event.destination_port in [22, 445, 3389, 5985],
        ]

        if not any(lateral_indicators):
            return None

        # Create cluster
        cluster = CorrelationCluster()
        cluster.add_event(event.event_id, event.timestamp)

        if event.source_ip:
            cluster.add_indicator("source_ip", event.source_ip)

        if event.destination_ip:
            cluster.add_indicator("destination_ip", event.destination_ip)

        if event.user_name:
            cluster.add_indicator("user", event.user_name)

        cluster.primary_pattern = pattern
        cluster.cluster_score = 0.85
        cluster.cluster_severity = "high"
        cluster.narrative = (
            f"Lateral movement detected from {event.source_ip} "
            f"to {event.destination_ip} via {event.network_protocol}"
        )

        return cluster

    def _match_data_exfiltration(
        self,
        event: SecurityEvent,
        pattern: CorrelationPattern
    ) -> CorrelationCluster | None:
        """Match data exfiltration pattern."""
        if "exfiltration" not in (event.alert_name or "").lower():
            return None

        # Create cluster
        cluster = CorrelationCluster()
        cluster.add_event(event.event_id, event.timestamp)

        if event.source_ip:
            cluster.add_indicator("source_ip", event.source_ip)

        if event.destination_ip:
            cluster.add_indicator("destination_ip", event.destination_ip)

        if event.user_name:
            cluster.add_indicator("user", event.user_name)

        cluster.primary_pattern = pattern
        cluster.cluster_score = 0.90
        cluster.cluster_severity = "critical"
        cluster.narrative = (
            f"Data exfiltration detected: {event.user_name} "
            f"transferring data to external IP {event.destination_ip}"
        )

        return cluster

    def _get_default_patterns(self) -> list[CorrelationPattern]:
        """Get default correlation patterns."""
        from src.models.correlation import CorrelationPatternType

        return [
            CorrelationPattern(
                name="multi_failed_login_detection",
                pattern_type=CorrelationPatternType.BEHAVIORAL_CHAIN,
                description="Multiple failed login attempts",
                conditions=["event.action:failed_login"],
                threshold=5,
                time_window_seconds=600,
                weight=1.0,
                enabled=True,
            ),
            CorrelationPattern(
                name="lateral_movement",
                pattern_type=CorrelationPatternType.LATERAL_MOVEMENT,
                description="Lateral movement across hosts",
                conditions=["network.protocol:(ssh|rdp|smb)"],
                threshold=2,
                time_window_seconds=1800,
                weight=1.2,
                enabled=True,
            ),
            CorrelationPattern(
                name="data_exfiltration_chain",
                pattern_type=CorrelationPatternType.DATA_EXFILTRATION,
                description="Data exfiltration activity",
                conditions=["event.action:exfiltration"],
                threshold=1,
                time_window_seconds=3600,
                weight=1.5,
                enabled=True,
            ),
        ]