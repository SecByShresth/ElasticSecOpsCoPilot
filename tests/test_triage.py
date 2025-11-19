# ============================================================================
# tests/test_triage.py - Triage Tests
# ============================================================================

"""Tests for triage modules."""
import pytest
from src.triage.scorer import SeverityScorer
from src.triage.classifier import EventClassifier
from src.triage.mitre_mapper import MitreMapper
from src.models.event import SecurityEvent, SeverityLevel


class TestSeverityScorer:
    """Test severity scoring."""

    def test_scorer_initialization(self):
        """Test scorer initialization."""
        scorer = SeverityScorer()
        assert scorer.thresholds["critical"] == 80

    def test_calculate_score_powershell(self):
        """Test scoring for powershell execution."""
        scorer = SeverityScorer()
        event = SecurityEvent(process_name="powershell.exe")
        score = scorer.calculate_score(event)
        assert score > 0

    def test_get_severity_critical(self):
        """Test severity level calculation."""
        scorer = SeverityScorer()
        assert scorer.get_severity(85) == SeverityLevel.CRITICAL
        assert scorer.get_severity(65) == SeverityLevel.HIGH
        assert scorer.get_severity(45) == SeverityLevel.MEDIUM
        assert scorer.get_severity(25) == SeverityLevel.LOW

    def test_score_event(self):
        """Test complete event scoring."""
        scorer = SeverityScorer()
        event = SecurityEvent(
            alert_name="Suspicious Powershell",
            process_name="powershell.exe"
        )
        result = scorer.score_event(event)
        assert result.score >= 0
        assert result.confidence >= 0


class TestEventClassifier:
    """Test event classification."""

    def test_classifier_malware(self):
        """Test malware classification."""
        classifier = EventClassifier()
        event = SecurityEvent(alert_name="Malware Detected")
        cls, conf = classifier.classify(event)
        assert cls == "malware"
        assert conf == 0.95

    def test_classifier_phishing(self):
        """Test phishing classification."""
        classifier = EventClassifier()
        event = SecurityEvent(alert_name="Phishing Email")
        cls, conf = classifier.classify(event)
        assert cls == "phishing"
        assert conf == 0.90

    def test_classifier_unknown(self):
        """Test unknown classification."""
        classifier = EventClassifier()
        event = SecurityEvent(alert_name="Generic Event")
        cls, conf = classifier.classify(event)
        assert cls == "unknown"
        assert conf == 0.50


class TestMitreMapper:
    """Test MITRE mapping."""

    def test_mitre_mapper_initialization(self):
        """Test mapper initialization."""
        mapper = MitreMapper()
        assert mapper.techniques is not None

    def test_map_powershell_command(self):
        """Test mapping powershell command."""
        mapper = MitreMapper()
        event = SecurityEvent(
            alert_name="Powershell Execution",
            process_name="powershell.exe"
        )
        mappings = mapper.map_event(event)
        assert len(mappings) > 0

    def test_map_phishing(self):
        """Test mapping phishing."""
        mapper = MitreMapper()
        event = SecurityEvent(alert_name="Phishing Detected")
        mappings = mapper.map_event(event)
        assert len(mappings) > 0
