#!/usr/bin/env python3
"""
Simple IOC Enrichment - No hanging, just works
"""

import sys
import os
import logging

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datetime import datetime, timezone, timedelta
import time

print("\n[1] Importing dependencies...")
from src.ingestion.elastic_client import ElasticClient
from src.utils.config_loader import get_config
from src.enrichment.virustotal import VirusTotalEnricher
from src.enrichment.shodan_enricher import ShodanEnricher
from src.enrichment.abuseipdb import AbuseIPDBEnricher
from src.enrichment.iplocation import IPLocationEnricher
from src.enrichment.whois_enricher import WhoisEnricher
from src.models.enrichment import EnrichedIOC, ThreatLevel


def get_nested(d, path):
    """Get nested value from dict."""
    try:
        for key in path.split("."):
            d = d.get(key) if isinstance(d, dict) else None
            if d is None:
                return None
        return d
    except:
        return None


def has_iocs(log):
    """Check if log has HASH, IP, or DNS."""
    # Check for hashes
    hash_paths = ["file.hash.md5", "file.hash.sha1", "file.hash.sha256", "process.hash.md5", "process.hash.sha256"]
    for path in hash_paths:
        if get_nested(log, path):
            return True

    # Check for external IPs
    ip_paths = ["source.ip", "destination.ip", "client.ip", "server.ip"]
    for path in ip_paths:
        val = get_nested(log, path)
        if val and not any(str(val).startswith(x) for x in ["192.168", "10.", "127.", "172."]):
            return True

    # Check for DNS
    dns_paths = ["dns.question.name", "destination.domain", "url.domain"]
    for path in dns_paths:
        if get_nested(log, path):
            return True

    return False


def extract_iocs(log):
    """Extract HASH, IP, DNS from log."""
    iocs = {"hashes": [], "ips": [],  "dns": []}

    # Extract hashes
    for path in ["file.hash.md5", "file.hash.sha1", "file.hash.sha256", "process.hash.md5", "process.hash.sha256"]:
        val = get_nested(log, path)
        if val:
            iocs["hashes"].append(str(val))

    # Extract IPs
    for path in ["source.ip", "destination.ip", "client.ip", "server.ip"]:
        val = get_nested(log, path)
        if val:
            ip_str = str(val)
            if not any(ip_str.startswith(x) for x in ["192.168", "10.", "127.", "172."]):
                iocs["ips"].append(ip_str)

    # Extract DNS
    for path in ["dns.question.name", "destination.domain", "url.domain"]:
        val = get_nested(log, path)
        if val:
            iocs["dns"].append(str(val))

    return iocs


def enrich_data(iocs, enrichers, logger):
    """Enrich extracted IOCs using available enrichers - returns list to avoid field explosion."""
    enrichment_results = []

    # Enrich Hashes (VirusTotal)
    for h in iocs["hashes"]:
        try:
            hash_type = "sha256" if len(h) == 64 else "md5" if len(h) == 32 else "sha1"
            enriched_ioc = EnrichedIOC(value=h, type=hash_type)
            
            if "virustotal" in enrichers:
                vt_result = enrichers["virustotal"].enrich_ioc(hash_type, h)
                if vt_result:
                    enrichers["virustotal"]._update_enriched_ioc(enriched_ioc, vt_result)
                    if enriched_ioc.virustotal:
                        enrichment_results.append({
                            "ioc_type": "hash",
                            "ioc_value": h,
                            "source": "virustotal",
                            "data": enriched_ioc.virustotal.to_dict()
                        })
        except Exception as e:
            logger.error(f"Error enriching hash {h}: {e}")

    # Enrich IPs (Shodan, AbuseIPDB, IPLocation)
    for ip in iocs["ips"]:
        try:
            enriched_ioc = EnrichedIOC(value=ip, type="ip")
            
            # Shodan
            if "shodan" in enrichers:
                shodan_result = enrichers["shodan"].enrich_ioc("ip", ip)
                if shodan_result:
                    enrichers["shodan"]._update_enriched_ioc(enriched_ioc, shodan_result)
                    if enriched_ioc.shodan:
                        enrichment_results.append({
                            "ioc_type": "ip",
                            "ioc_value": ip,
                            "source": "shodan",
                            "data": enriched_ioc.shodan.to_dict()
                        })

            # AbuseIPDB
            if "abuseipdb" in enrichers:
                abuse_result = enrichers["abuseipdb"].enrich_ioc("ip", ip)
                if abuse_result:
                    enrichers["abuseipdb"]._update_enriched_ioc(enriched_ioc, abuse_result)
                    if enriched_ioc.abuseipdb:
                        enrichment_results.append({
                            "ioc_type": "ip",
                            "ioc_value": ip,
                            "source": "abuseipdb",
                            "data": enriched_ioc.abuseipdb.to_dict()
                        })

            # IPLocation (replaces MaxMind)
            if "iplocation" in enrichers:
                iploc_result = enrichers["iplocation"].enrich_ioc("ip", ip)
                if iploc_result:
                    enrichers["iplocation"]._update_enriched_ioc(enriched_ioc, iploc_result)
                    if enriched_ioc.maxmind:  # We reuse the maxmind field for geoip data
                        enrichment_results.append({
                            "ioc_type": "ip",
                            "ioc_value": ip,
                            "source": "iplocation",
                            "data": enriched_ioc.maxmind.to_dict()
                        })
                    
        except Exception as e:
            logger.error(f"Error enriching IP {ip}: {e}")

    # Enrich DNS (WHOIS)
    for domain in iocs["dns"]:
        try:
            enriched_ioc = EnrichedIOC(value=domain, type="domain")
            
            if "whois" in enrichers:
                whois_result = enrichers["whois"].enrich_ioc("domain", domain)
                if whois_result:
                    enrichers["whois"]._update_enriched_ioc(enriched_ioc, whois_result)
                    if enriched_ioc.whois:
                        enrichment_results.append({
                            "ioc_type": "domain",
                            "ioc_value": domain,
                            "source": "whois",
                            "data": enriched_ioc.whois.to_dict()
                        })
        except Exception as e:
            logger.error(f"Error enriching domain {domain}: {e}")

    return enrichment_results


def ensure_output_index(client, index_name):
    """Ensure output index exists with correct mapping settings."""
    try:
        if not client.client.indices.exists(index=index_name):
            print(f"Creating index {index_name} with total_fields.limit=2000...")
            client.client.indices.create(
                index=index_name,
                body={
                    "settings": {
                        "index.mapping.total_fields.limit": 2000
                    }
                }
            )
        else:
            # Update existing index settings
            client.client.indices.put_settings(
                index=index_name,
                body={
                    "index.mapping.total_fields.limit": 2000
                }
            )
    except Exception as e:
        print(f"⚠️ Could not configure index settings (might be restricted in Serverless): {e}")


def main():
    # Configure logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    logger = logging.getLogger("enrichment_service")

    print("[2] Loading configuration...")
    config = get_config()

    print("[3] Creating client...")
    client = ElasticClient()

    print("[4] Testing connection...")
    try:
        info = client.client.info()
        print(f"✅ Connected to {info['cluster_name']}\n")
    except Exception as e:
        print(f"❌ Connection error: {e}")
        sys.exit(1)

    # Initialize Enrichers
    print("[5] Initializing enrichers...")
    enrichers = {
        "virustotal": VirusTotalEnricher(config.get_section("enrichment.virustotal")),
        "shodan": ShodanEnricher(config.get_section("enrichment.shodan")),
        "abuseipdb": AbuseIPDBEnricher(config.get_section("enrichment.abuseipdb")),
        "iplocation": IPLocationEnricher(config.get_section("enrichment.iplocation")),
        "whois": WhoisEnricher(config.get_section("enrichment.whois"))
    }

    # Configuration
    source_indices = [
        ".ds-logs-endpoint.events.process-*",
        ".ds-logs-endpoint.events.file-*",
        ".ds-logs-endpoint.events.network-*",
        ".ds-logs-endpoint.events.dns-*",
        ".ds-logs-system.security-*",
    ]
    output_index = "security-alerts-enriched"

    # Ensure index exists with correct settings
    ensure_output_index(client, output_index)

    print("=" * 80)
    print("🚀 IOC ENRICHMENT SERVICE")
    print("=" * 80)
    print("Looking for: HASH → VT, IP → Shodan/AbuseIPDB/IPLocation, DNS → WHOIS\n")

    last_check = datetime.now(timezone.utc) - timedelta(hours=24)
    processed = set()
    iteration = 0

    try:
        while True:
            iteration += 1
            print(f"[Iteration {iteration}] Fetching logs...")

            all_logs = []

            for index in source_indices:
                try:
                    results = client.client.search(
                        index=index,
                        query={"range": {"@timestamp": {"gte": last_check.isoformat()}}},
                        size=100,
                        _source=True
                    )

                    for hit in results["hits"]["hits"]:
                        if hit["_id"] not in processed:
                            all_logs.append(hit["_source"])
                            all_logs[-1]["_id"] = hit["_id"]
                            all_logs[-1]["_index"] = hit["_index"]
                except Exception as e:
                    pass

            if all_logs:
                print(f"✅ Found {len(all_logs)} logs\n")

                enriched_count = 0

                for log in all_logs:
                    doc_id = log.pop("_id")
                    source_index = log.pop("_index", "unknown")
                    processed.add(doc_id)

                    if has_iocs(log):
                        iocs = extract_iocs(log)
                        
                        # Perform Enrichment
                        enrichment_data = enrich_data(iocs, enrichers, logger)

                        # Create summary for logging
                        vt_found = any(e for e in enrichment_data if e["source"] == "virustotal")
                        shodan_found = any(e for e in enrichment_data if e["source"] == "shodan")
                        abuse_found = any(e for e in enrichment_data if e["source"] == "abuseipdb")
                        iploc_found = any(e for e in enrichment_data if e["source"] == "iplocation")
                        whois_found = any(e for e in enrichment_data if e["source"] == "whois")

                        # Extract only essential metadata (NOT the whole log!)
                        source_metadata = {
                            "@timestamp": log.get("@timestamp"),
                            "host_name": log.get("host", {}).get("name"),
                            "event_action": log.get("event", {}).get("action"),
                            "event_category": log.get("event", {}).get("category"),
                            "process_name": log.get("process", {}).get("name"),
                            "file_name": log.get("file", {}).get("name"),
                            "source_index": source_index
                        }

                        enriched = {
                            "@timestamp": log.get("@timestamp", datetime.now(timezone.utc).isoformat()),
                            "source_doc_id": doc_id,  # Reference to original document
                            "source_metadata": source_metadata,  # Only essential fields
                            "iocs": iocs,
                            "enrichments": enrichment_data,
                            "status": "enriched",
                            "enriched_at": datetime.now(timezone.utc).isoformat()
                        }

                        try:
                            client.client.index(
                                index=output_index,
                                id=doc_id,
                                document=enriched,
                                op_type="create"
                            )
                            enriched_count += 1

                            if iocs["hashes"]:
                                print(f"  📍 HASH: {iocs['hashes'][0][:12]}... -> VT: {'✅' if vt_found else '❌'}")
                            if iocs["ips"]:
                                print(f"  🌐 IP: {iocs['ips'][0]} -> Shodan: {'✅' if shodan_found else '❌'} Abuse: {'✅' if abuse_found else '❌'} Geo: {'✅' if iploc_found else '❌'}")
                            if iocs["dns"]:
                                print(f"  🔗 DNS: {iocs['dns'][0]} -> WHOIS: {'✅' if whois_found else '❌'}")
                            print()
                        except Exception as e:
                            logger.error(f"Failed to index enriched document {doc_id}: {e}")

                print(f"✅ Enriched {enriched_count} logs\n")
            else:
                print("No new logs\n")

            last_check = datetime.now(timezone.utc)
            print(f"Waiting 10s...\n")
            time.sleep(10)

    except KeyboardInterrupt:
        print("\n⏹️  Stopped")
    finally:
        client.close()

if __name__ == "__main__":
    main()