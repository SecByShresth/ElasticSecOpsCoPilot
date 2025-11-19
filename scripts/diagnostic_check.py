#!/usr/bin/env python3
"""Diagnostic script to check alert flow."""

import sys
import os
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ingestion.elastic_client import ElasticClient


def run_diagnostics():
    """Run comprehensive diagnostics."""

    print("=" * 80)
    print("🔍 ELASTIC SECOPS COPILOT - DIAGNOSTIC CHECK")
    print("=" * 80)

    try:
        client = ElasticClient()
        print("\n✅ Connected to Elasticsearch Serverless")
    except Exception as e:
        print(f"\n❌ Connection failed: {e}")
        return

    # Step 1: Check raw alerts data stream
    print("\n" + "=" * 80)
    print("STEP 1: Check Raw Alerts Data Stream")
    print("=" * 80)

    try:
        count_response = client.client.count(
            index=".alerts-security.alerts-default"
        )
        raw_count = count_response.get("count", 0)
        print(f"📊 Total alerts in .alerts-security.alerts-default: {raw_count}")

        if raw_count == 0:
            print("\n⚠️  NO ALERTS FOUND IN RAW DATA STREAM!")
            print("This means:")
            print("  1. Elastic Endpoint is NOT installed or running")
            print("  2. OR Endpoint is not generating events")
            print("  3. OR Events are going to different index")
        else:
            print(f"✅ Found {raw_count} raw alerts")

            # Show recent alerts
            search_response = client.client.search(
                index=".alerts-security.alerts-default",
                query={"match_all": {}},
                size=5,
                sort=[{"@timestamp": {"order": "desc"}}]
            )

            hits = search_response.get("hits", {}).get("hits", [])
            print(f"\n📋 Most recent {len(hits)} alerts:")
            for hit in hits:
                source = hit.get("_source", {})
                timestamp = source.get("@timestamp", "N/A")
                title = source.get("alert", {}).get("title", "Unknown")
                print(f"   - {title}")
                print(f"     @ {timestamp}")

    except Exception as e:
        print(f"❌ Error checking raw alerts: {e}")

    # Step 2: Check enriched alerts index
    print("\n" + "=" * 80)
    print("STEP 2: Check Enriched Alerts Index")
    print("=" * 80)

    try:
        count_response = client.client.count(
            index="security-alerts-enriched"
        )
        enriched_count = count_response.get("count", 0)
        print(f"📊 Total enriched alerts: {enriched_count}")

        if enriched_count == 0:
            print("\n⚠️  NO ENRICHED ALERTS YET!")
            print("This means:")
            print("  1. Enrichment pipeline hasn't run yet")
            print("  2. OR no raw alerts exist to enrich")
            print("  3. OR enrichment is failing silently")
        else:
            print(f"✅ Found {enriched_count} enriched alerts")

            # Show enriched alerts
            search_response = client.client.search(
                index="security-alerts-enriched",
                query={"match_all": {}},
                size=3,
                sort=[{"@timestamp": {"order": "desc"}}]
            )

            hits = search_response.get("hits", {}).get("hits", [])
            print(f"\n📋 Most recent enriched alerts:")
            for hit in hits:
                source = hit.get("_source", {})
                severity = source.get("severity", "UNKNOWN")
                title = source.get("alert_name", "Unknown")
                score = source.get("triage_result", {}).get("score", "N/A")
                print(f"   - {title} | {severity} | Score: {score}/100")

    except Exception as e:
        print(f"❌ Error checking enriched alerts: {e}")

    # Step 3: Check available indices
    print("\n" + "=" * 80)
    print("STEP 3: Check Available Indices")
    print("=" * 80)

    try:
        indices = client.client.indices.get(index="*")
        index_names = list(indices.keys())

        print(f"📋 Available indices ({len(index_names)}):")

        # Filter for security-related indices
        security_indices = [i for i in index_names if "alert" in i.lower() or "security" in i.lower()]

        if security_indices:
            print("\n🔐 Security/Alert related indices:")
            for idx in sorted(security_indices):
                try:
                    idx_count = client.client.count(index=idx).get("count", 0)
                    print(f"   ✅ {idx}: {idx_count} documents")
                except:
                    print(f"   ⚠️  {idx}: (could not count)")
        else:
            print("\n⚠️  No security/alert indices found!")
            print("\n📌 All available indices:")
            for idx in sorted(index_names)[:20]:  # Show first 20
                print(f"   - {idx}")

    except Exception as e:
        print(f"❌ Error checking indices: {e}")

    # Step 4: Check if Elastic Endpoint is active
    print("\n" + "=" * 80)
    print("STEP 4: Check Elastic Endpoint Status")
    print("=" * 80)

    try:
        # Search for Endpoint data
        endpoint_search = client.client.search(
            index="logs-endpoint.events.*",
            query={"match_all": {}},
            size=1
        )

        endpoint_count = endpoint_search.get("hits", {}).get("total", {}).get("value", 0)

        if endpoint_count > 0:
            print(f"✅ Elastic Endpoint IS generating events: {endpoint_count} events found")
        else:
            print("❌ Elastic Endpoint is NOT generating events")
            print("\n💡 To fix:")
            print("   1. Go to Elastic Cloud Console")
            print("   2. Integrations → Elastic Endpoint")
            print("   3. Deploy agent to your machine")
            print("   4. Wait 5-10 minutes for first events")

    except Exception as e:
        print(f"⚠️  Could not check Endpoint data: {e}")

    # Step 5: Summary and recommendations
    print("\n" + "=" * 80)
    print("SUMMARY & RECOMMENDATIONS")
    print("=" * 80)

    print(f"\n📊 Status:")
    print(f"   Raw alerts: {raw_count if 'raw_count' in locals() else 'Unknown'}")
    print(f"   Enriched alerts: {enriched_count if 'enriched_count' in locals() else 'Unknown'}")

    if 'raw_count' in locals() and raw_count == 0:
        print("\n🔴 ISSUE: No raw alerts detected")
        print("\n✅ SOLUTION:")
        print("   1. Check if Elastic Endpoint is installed:")
        print("      - Open 'Services' (services.msc)")
        print("      - Look for 'Elastic Endpoint' or 'elastic-agent'")
        print("   2. If not installed:")
        print("      - Go to Elastic Cloud Console")
        print("      - Integrations → Elastic Endpoint")
        print("      - Deploy and install agent")
        print("   3. If installed, check status:")
        print("      - Open Fleet Management in Kibana")
        print("      - Check if agent is 'Healthy'")
        print("   4. Generate test events:")
        print("      - Run: python scripts/simulate_attacks.py")
        print("   5. Wait 2-5 minutes and run this diagnostic again")

    elif 'raw_count' in locals() and raw_count > 0 and enriched_count == 0:
        print("\n🟡 ISSUE: Raw alerts exist but not enriched")
        print("\n✅ SOLUTION:")
        print("   1. Run enrichment pipeline manually:")
        print("      - python scripts/process_live_alerts.py")
        print("   2. Or set up continuous enrichment:")
        print("      - python scripts/continuous_enrichment.py")
        print("   3. Check logs for errors:")
        print("      - tail -f logs/elastic-secops-copilot.log")

    elif 'enriched_count' in locals() and enriched_count > 0:
        print("\n🟢 EVERYTHING IS WORKING!")
        print("\n✅ Next steps:")
        print("   1. View alerts in Kibana:")
        print("      - Go to Discover")
        print("      - Create data view for 'security-alerts-enriched'")
        print("   2. Set up continuous monitoring:")
        print("      - python scripts/continuous_enrichment.py")
        print("   3. Create Kibana dashboard")

    client.close()

    print("\n" + "=" * 80)


if __name__ == "__main__":
    run_diagnostics()