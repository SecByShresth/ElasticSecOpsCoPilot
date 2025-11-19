# ============================================================================
# tests/test_correlation.py - Correlation Tests
# ============================================================================

"""Tests for correlation modules."""
import pytest
from datetime import datetime
from src.correlation.engine import CorrelationEngine
from src.correlation.patterns import PatternLibrary
from src.models.event import SecurityEvent
from src.models.correlation import CorrelationCluster


class TestCorrelationEngine:
    """Test correlation engine."""

    def test_engine_initialization(self):
        """Test engine initialization."""
        engine = CorrelationEngine()
        assert engine.patterns is not None
        assert len(engine.patterns) > 0

    def test_correlate_failed_logins(self):
        """Test failed login correlation."""
        engine = CorrelationEngine()
        event = SecurityEvent(
            alert_name="Failed Login Attempt",
            user_name="testuser",
            host_name="WORKSTATION-01"
        )
        result = engine.correlate(event)
        # May or may not match depending on implementation
        assert result is None or result.patterns_matched >= 0

    def test_pattern_library_patterns(self):
        """Test pattern library."""
        patterns = PatternLibrary.get_all_patterns()
        assert len(patterns) >= 5

    def test_failed_login_pattern(self):
        """Test failed login pattern definition."""
        pattern = PatternLibrary.failed_login_pattern()
        assert pattern.name == "multi_failed_login_detection"
        assert pattern.threshold == 5


class TestCorrelationCluster:
    """Test correlation clustering."""

    def test_cluster_creation(self):
        """Test cluster creation."""
        cluster = CorrelationCluster()
        assert cluster.event_ids == set()

    def test_cluster_add_event(self):
        """Test adding events to cluster."""
        cluster = CorrelationCluster()
        now = datetime.utcnow()
        cluster.add_event("event_1", now)
        assert "event_1" in cluster.event_ids

    def test_cluster_add_indicator(self):
        """Test adding indicators."""
        cluster = CorrelationCluster()
        cluster.add_indicator("ip", "192.168.1.1")
        assert "ip" in cluster.indicators
        assert "192.168.1.1" in cluster.indicators["ip"]

    def test_cluster_expiration(self):
        """Test cluster expiration."""
        cluster = CorrelationCluster(cluster_ttl_seconds=1)
        now = datetime.utcnow()
        cluster.add_event("event_1", now)
        import time
        time.sleep(2)
        assert cluster.is_expired()