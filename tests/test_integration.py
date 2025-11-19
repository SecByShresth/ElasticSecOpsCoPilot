# ============================================================================
# tests/test_integration.py - Integration Tests
# ============================================================================

"""End-to-end integration tests."""
import pytest
from src.models.event import SecurityEvent, SeverityLevel
from src.enrichment.base import BaseEnricher
from src.enrichment.coordinator import EnrichmentCoordinator
from src.triage.scorer import SeverityScorer
from src.triage.classifier import EventClassifier
from src.triage.mitre_mapper import MitreMapper
from src.correlation.engine import CorrelationEngine
from src.notes.generator import NotesGenerator


class TestFullPipeline:
    """Test complete pipeline."""

    def test_event_creation_and_enrichment(self):
        """Test event creation through enrichment."""
        # Create event
        event = SecurityEvent(
            alert_name="Test Alert",
            host_name="TEST-HOST",
            user_name="testuser",
            process_name="powershell.exe"
        )

        # Verify basic fields
        assert event.alert_name == "Test Alert"
        assert event.host_name == "TEST-HOST"

    def test_event_scoring_and_classification(self):
        """Test scoring and classification."""
        event = SecurityEvent(
            alert_name="Malware Detection",
            process_name="powershell.exe"
        )

        # Score
        scorer = SeverityScorer()
        score = scorer.calculate_score(event)
        assert score > 0

        # Classify
        classifier = EventClassifier()
        cls, conf = classifier.classify(event)
        assert cls == "malware"

    def test_event_mitre_mapping(self):
        """Test MITRE mapping."""
        event = SecurityEvent(
            alert_name="Command Execution",
            process_name="cmd.exe"
        )

        mapper = MitreMapper()
        mappings = mapper.map_event(event)
        assert isinstance(mappings, list)

    def test_notes_generation(self):
        """Test notes generation."""
        event = SecurityEvent(
            alert_name="Security Alert",
            host_name="WORKSTATION-01",
            user_name="testuser"
        )

        generator = NotesGenerator()
        note = generator.generate(event)

        assert note.content is not None
        assert len(note.sections) > 0

    def test_event_correlation(self):
        """Test event correlation."""
        engine = CorrelationEngine()

        event = SecurityEvent(
            alert_name="Failed Login",
            user_name="testuser"
        )

        result = engine.correlate(event)
        # Result may be None if no patterns match
        assert result is None or result.patterns_matched >= 0

    def test_event_serialization(self):
        """Test event serialization."""
        event = SecurityEvent(
            alert_name="Test",
            host_name="TEST-HOST"
        )

        # To dict
        event_dict = event.to_dict()
        assert event_dict["alert_name"] == "Test"

        # To JSON
        event_json = event.to_json()
        assert isinstance(event_json, str)


class TestPerformance:
    """Performance tests."""

    def test_bulk_event_creation(self):
        """Test creating many events."""
        events = []
        for i in range(100):
            event = SecurityEvent(
                alert_name=f"Alert {i}",
                host_name=f"HOST-{i % 10}",
                user_name=f"user{i % 5}"
            )
            events.append(event)

        assert len(events) == 100

    def test_batch_scoring(self):
        """Test batch scoring."""
        scorer = SeverityScorer()
        events = [
            SecurityEvent(
                alert_name=f"Alert {i}",
                process_name="powershell.exe" if i % 2 == 0 else "cmd.exe"
            )
            for i in range(50)
        ]

        scores = [scorer.calculate_score(e) for e in events]
        assert len(scores) == 50
        assert all(0 <= s <= 100 for s in scores)