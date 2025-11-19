# ============================================================================
# FILE 2: scripts/process_live_alerts.py
# ============================================================================
# !/usr/bin/env python3
"""Process live alerts from Elasticsearch with full pipeline."""

import sys
import os
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ingestion.elastic_client import ElasticClient
from src.ingestion.event_fetcher import EventFetcher
from src.triage.scorer import SeverityScorer
from src.triage.classifier import EventClassifier
from src.triage.mitre_mapper import MitreMapper
from src.correlation.engine import CorrelationEngine
from src.notes.generator import NotesGenerator
from src.actions.elastic_sync import ElasticSync
from src.utils.logger import get_default_logger


def process_live_alerts():
    """Process live alerts with full pipeline."""

    logger = get_default_logger(level="INFO")

    print("🔗 Connecting to Elasticsearch Serverless...")
    try:
        client = ElasticClient()
        health = client.health()
        print(f"✅ Connected! Status: {health.get('status')}")
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        return

    # Initialize components
    print("\n🚀 Initializing Elastic SecOps Copilot...")
    try:
        fetcher = EventFetcher(client)
        scorer = SeverityScorer()
        classifier = EventClassifier()
        mapper = MitreMapper()
        correlation_engine = CorrelationEngine()
        notes_generator = NotesGenerator()
        sync = ElasticSync(client)
        print("✅ All components ready")
    except Exception as e:
        print(f"❌ Initialization failed: {e}")
        client.close()
        return

    # Fetch recent alerts
    print("\n📥 Fetching alerts from Elasticsearch...")
    try:
        alerts = fetcher.fetch_alerts(
            indices=[".alerts-security.alerts-default"],
            lookback_hours=24,
            batch_size=100
        )
        print(f"✅ Fetched {len(alerts)} alerts")
    except Exception as e:
        print(f"❌ Failed to fetch alerts: {e}")
        client.close()
        return

    if not alerts:
        print("\n⚠️  No alerts found!")
        print("\n💡 First create test alerts:")
        print("   python scripts/create_test_alerts.py")
        client.close()
        return

    # Process each alert
    print(f"\n⚙️  Processing {len(alerts)} alerts through pipeline...\n")

    processed_count = 0

    for idx, event in enumerate(alerts, 1):
        try:
            print(f"[{idx}/{len(alerts)}] 🔄 {event.alert_name}")

            # Step 1: Score severity
            score = scorer.calculate_score(event)
            severity = scorer.get_severity(score)
            event.severity = severity
            print(f"        📊 Severity: {severity.value} (Score: {score}/100)")

            # Step 2: Classify
            classification, confidence = classifier.classify(event)
            print(f"        🏷️  Classification: {classification}")

            # Step 3: MITRE Mapping
            mitre_mappings = mapper.map_event(event)
            if mitre_mappings:
                techniques = ", ".join([m.technique_id for m in mitre_mappings[:2]])
                print(f"        🎯 MITRE: {techniques}")

            # Step 4: Correlate
            correlation_result = correlation_engine.correlate(event)
            if correlation_result and correlation_result.patterns_matched > 0:
                print(f"        🔗 Correlated: {correlation_result.patterns_matched} pattern(s)")

            # Step 5: Generate notes
            note = notes_generator.generate(event)
            print(f"        📝 Notes: {len(note.sections)} sections")

            # Step 6: Sync
            sync.sync_event("security-alerts-enriched", event)
            print(f"        💾 Synced to Elasticsearch\n")

            processed_count += 1

        except Exception as e:
            print(f"        ❌ Error: {str(e)[:100]}\n")
            logger.exception(f"Error processing alert: {e}")
            continue

    client.close()

    print(f"\n{'=' * 70}")
    print(f"✅ PROCESSING COMPLETE")
    print(f"{'=' * 70}")
    print(f"Processed: {processed_count}/{len(alerts)} alerts")
    print(f"Success Rate: {(processed_count / len(alerts) * 100):.1f}%")
    print(f"Output Index: security-alerts-enriched")
    print(f"\n📊 View in Kibana:")
    print(f"   1. Go to Discover")
    print(f"   2. Create data view for 'security-alerts-enriched'")
    print(f"   3. View enriched alerts with scores, MITRE mappings, and notes")


if __name__ == "__main__":
    process_live_alerts()