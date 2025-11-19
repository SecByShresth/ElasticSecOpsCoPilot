#!/usr/bin/env python3
"""Verify alerts exist and process them."""

import sys
import os
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ingestion.elastic_client import ElasticClient


def verify_alerts():
    """Verify alerts were created."""

    print("🔍 VERIFYING ALERTS IN ELASTICSEARCH\n")

    try:
        client = ElasticClient()

        # Check index exists
        print("📋 Checking data stream...")
        try:
            response = client.client.indices.get(index=".alerts-security.alerts-default")
            print(f"✅ Data stream exists: .alerts-security.alerts-default")
        except Exception as e:
            print(f"⚠️  Could not get index info: {e}")

        # Count documents
        print("\n📊 Counting alerts...")
        try:
            count_response = client.client.count(
                index=".alerts-security.alerts-default"
            )
            count = count_response.get("count", 0)
            print(f"✅ Found {count} alerts in data stream")
        except Exception as e:
            print(f"❌ Count failed: {e}")

        # Search for recent alerts
        print("\n🔎 Searching for recent alerts...")
        try:
            search_response = client.client.search(
                index=".alerts-security.alerts-default",
                query={"match_all": {}},
                size=10,
                sort=[{"@timestamp": {"order": "desc"}}]
            )

            hits = search_response.get("hits", {}).get("hits", [])
            print(f"✅ Found {len(hits)} alert(s) in search")

            if hits:
                print("\n📋 Alert Details:")
                for hit in hits:
                    source = hit.get("_source", {})
                    timestamp = source.get("@timestamp", "N/A")
                    title = source.get("alert", {}).get("title", "N/A")
                    print(f"   - {title} @ {timestamp}")
            else:
                print("⚠️  No alerts found in search results")
        except Exception as e:
            print(f"❌ Search failed: {e}")

        client.close()

        print("\n" + "=" * 70)
        print("✅ VERIFICATION COMPLETE")
        print("=" * 70)
        print("\n🚀 Now run: python scripts/process_live_alerts.py")

    except Exception as e:
        print(f"❌ Error: {e}")


if __name__ == "__main__":
    verify_alerts()