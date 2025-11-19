#!/usr/bin/env python3
"""
Diagnose what Elastic Endpoint is actually capturing
Shows all network events, file events, process events with their IOCs
"""

import sys
import os
import json
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ingestion.elastic_client import ElasticClient
from src.utils.logger import get_default_logger

logger = get_default_logger(level="INFO")


class EndpointDiagnostic:
    """Diagnose Elastic Endpoint events."""

    def __init__(self):
        self.client = ElasticClient()

    def get_all_endpoint_events(self, hours: int = 1) -> list:
        """Get all Endpoint events from last N hours."""
        try:
            logger.info(f"\n🔍 Fetching Elastic Endpoint events from last {hours} hour(s)...\n")

            time_range = datetime.now(timezone.utc) - timedelta(hours=hours)

            # Search all endpoint indices
            endpoint_indices = [
                ".ds-logs-endpoint.events.process-*",
                ".ds-logs-endpoint.events.network-*",
                ".ds-logs-endpoint.events.file-*",
                ".ds-logs-endpoint.events.dns-*",
            ]

            all_events = []

            for index_pattern in endpoint_indices:
                try:
                    query = {
                        "bool": {
                            "must": [
                                {"range": {"@timestamp": {"gte": time_range.isoformat()}}}
                            ]
                        }
                    }

                    results = self.client.client.search(
                        index=index_pattern,
                        query=query,
                        size=1000,
                        sort=[{"@timestamp": {"order": "desc"}}],
                        _source=True
                    )

                    hits = results["hits"]["hits"]
                    logger.info(f"📊 {index_pattern}: {len(hits)} events")

                    for hit in hits:
                        all_events.append({
                            "index": index_pattern,
                            "id": hit["_id"],
                            "data": hit["_source"]
                        })

                except Exception as e:
                    if "no matching indices" not in str(e).lower():
                        logger.debug(f"Index {index_pattern}: {str(e)[:60]}")

            return all_events

        except Exception as e:
            logger.error(f"Error fetching events: {e}")
            return []

    def extract_iocs_from_event(self, event: dict) -> dict:
        """Extract IOCs from an endpoint event."""
        iocs = {
            "ips": [],
            "domains": [],
            "urls": [],
            "hashes": [],
            "processes": [],
            "files": []
        }

        try:
            # Network IOCs
            if event.get("source", {}).get("ip"):
                iocs["ips"].append(f"Source: {event['source']['ip']}")
            if event.get("destination", {}).get("ip"):
                iocs["ips"].append(f"Dest: {event['destination']['ip']}")

            # DNS
            if event.get("dns", {}).get("question", {}).get("name"):
                iocs["domains"].append(event['dns']['question']['name'])
            if event.get("dns", {}).get("resolved_ip"):
                for ip in event['dns']['resolved_ip']:
                    iocs["ips"].append(f"Resolved: {ip}")

            # URLs
            if event.get("url", {}).get("full"):
                iocs["urls"].append(event['url']['full'])

            # File hashes
            if event.get("file", {}).get("hash"):
                hashes = event['file']['hash']
                if isinstance(hashes, dict):
                    for hash_type, hash_val in hashes.items():
                        iocs["hashes"].append(f"{hash_type}: {hash_val}")
                else:
                    iocs["hashes"].append(str(hashes))

            # Process information
            if event.get("process", {}).get("name"):
                iocs["processes"].append(event['process']['name'])
            if event.get("process", {}).get("command_line"):
                iocs["processes"].append(f"CMD: {event['process']['command_line'][:80]}")

            # File operations
            if event.get("file", {}).get("path"):
                iocs["files"].append(event['file']['path'])
            if event.get("file", {}).get("name"):
                iocs["files"].append(f"Name: {event['file']['name']}")

        except Exception as e:
            logger.debug(f"IOC extraction error: {e}")

        return iocs

    def categorize_events(self, events: list) -> dict:
        """Categorize events by type."""
        categories = {
            "process": [],
            "network": [],
            "file": [],
            "dns": [],
            "other": []
        }

        for event in events:
            data = event.get("data", {})
            event_type = data.get("event", {}).get("type", ["unknown"])[0]
            category = data.get("event", {}).get("category", ["unknown"])[0]

            if "process" in event["index"]:
                categories["process"].append(event)
            elif "network" in event["index"]:
                categories["network"].append(event)
            elif "file" in event["index"]:
                categories["file"].append(event)
            elif "dns" in event["index"]:
                categories["dns"].append(event)
            else:
                categories["other"].append(event)

        return categories

    def print_event_summary(self, event: dict, event_num: int):
        """Print a summary of an event."""
        data = event.get("data", {})

        timestamp = data.get("@timestamp", "Unknown")
        event_action = data.get("event", {}).get("action", "Unknown")
        message = data.get("message", "")[:100]

        logger.info(f"\n  [{event_num}] {timestamp}")
        logger.info(f"      Action: {event_action}")
        logger.info(f"      Message: {message}")

        # Extract and show IOCs
        iocs = self.extract_iocs_from_event(data)

        if any(iocs.values()):
            logger.info("      IOCs Found:")
            if iocs["ips"]:
                for ip in iocs["ips"][:3]:
                    logger.info(f"        📍 IP: {ip}")
            if iocs["domains"]:
                for domain in iocs["domains"][:3]:
                    logger.info(f"        🌐 Domain: {domain}")
            if iocs["urls"]:
                for url in iocs["urls"][:3]:
                    logger.info(f"        🔗 URL: {url}")
            if iocs["hashes"]:
                for h in iocs["hashes"][:3]:
                    logger.info(f"        #️⃣  Hash: {h}")
            if iocs["processes"]:
                for proc in iocs["processes"][:2]:
                    logger.info(f"        ⚙️  Process: {proc}")
            if iocs["files"]:
                for file in iocs["files"][:2]:
                    logger.info(f"        📄 File: {file}")

    def run_diagnostic(self):
        """Run the diagnostic."""
        logger.info("\n" + "=" * 100)
        logger.info("🔍 ELASTIC ENDPOINT DIAGNOSTIC - What's Actually Being Captured?")
        logger.info("=" * 100)

        # Fetch events
        events = self.get_all_endpoint_events(hours=2)

        if not events:
            logger.error("\n❌ NO ENDPOINT EVENTS FOUND!")
            logger.error("This means either:")
            logger.error("   1. Elastic Endpoint is NOT installed on your machine")
            logger.error("   2. Elastic Endpoint is installed but NOT monitoring your machine")
            logger.error("   3. No activities have occurred in the past 2 hours")
            logger.info("\n💡 To fix:")
            logger.info("   1. Verify Endpoint is running: sc query elastic-agent")
            logger.info("   2. Check Elastic Cloud console > Fleet > Agents")
            logger.info("   3. Perform an action (download file, visit website, run process)")
            self.client.close()
            return

        logger.info(f"\n✅ Found {len(events)} Endpoint events!\n")

        # Categorize
        categories = self.categorize_events(events)

        logger.info("📊 EVENT BREAKDOWN:")
        logger.info(f"   🔵 Process Events: {len(categories['process'])}")
        logger.info(f"   🔵 Network Events: {len(categories['network'])}")
        logger.info(f"   🔵 File Events: {len(categories['file'])}")
        logger.info(f"   🔵 DNS Events: {len(categories['dns'])}")
        logger.info(f"   🔵 Other: {len(categories['other'])}")

        # Show sample events from each category
        for category_name, category_events in categories.items():
            if not category_events:
                continue

            logger.info(f"\n{'=' * 100}")
            logger.info(f"📋 {category_name.upper()} EVENTS (showing first 3)")
            logger.info("=" * 100)

            for i, event in enumerate(category_events[:3], 1):
                self.print_event_summary(event, i)

        logger.info(f"\n{'=' * 100}")
        logger.info("✅ DIAGNOSTIC COMPLETE")
        logger.info("=" * 100)
        logger.info("\n💡 NEXT STEPS:")
        logger.info("   1. Perform an action on your machine:")
        logger.info("      - Download a file")
        logger.info("      - Visit a website (visit a suspicious-looking site)")
        logger.info("      - Run a process")
        logger.info("      - Connect to external network")
        logger.info("   2. Run this diagnostic again to see new events")
        logger.info("   3. Run continuous enrichment to extract IOCs and enrich them\n")

        self.client.close()


if __name__ == "__main__":
    diagnostic = EndpointDiagnostic()
    diagnostic.run_diagnostic()