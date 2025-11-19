#!/usr/bin/env python3
"""
Analyze Endpoint logs to see what IOCs are actually available
Shows: Do logs have HASH? IP? DNS?
"""

import sys
import os
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ingestion.elastic_client import ElasticClient
from src.utils.validators import HashValidator, IPValidator, DomainValidator

client = ElasticClient()

print("\n" + "="*100)
print("📊 ANALYZING ENDPOINT LOGS - Finding Available IOCs")
print("="*100 + "\n")

# Fetch sample logs
indices = [
    ".ds-logs-endpoint.events.process-*",
    ".ds-logs-endpoint.events.file-*",
    ".ds-logs-endpoint.events.network-*",
    ".ds-logs-endpoint.events.dns-*",
]

time_range = datetime.now(timezone.utc) - timedelta(hours=1)

stats = {
    "total_logs": 0,
    "logs_with_hash": 0,
    "logs_with_ip": 0,
    "logs_with_dns": 0,
    "hashes_found": [],
    "ips_found": [],
    "dns_found": [],
    "sample_hash_logs": [],
    "sample_ip_logs": [],
    "sample_dns_logs": []
}

def find_hash(log):
    paths = ["file.hash.md5", "file.hash.sha1", "file.hash.sha256", "process.hash.md5", "process.hash.sha256"]
    for path in paths:
        keys = path.split(".")
        val = log
        for key in keys:
            if isinstance(val, dict):
                val = val.get(key)
            else:
                val = None
                break
        if val and HashValidator.detect_hash_type(str(val)):
            return str(val)
    return None

def find_ip(log):
    paths = ["source.ip", "destination.ip", "client.ip", "server.ip"]
    for path in paths:
        keys = path.split(".")
        val = log
        for key in keys:
            if isinstance(val, dict):
                val = val.get(key)
            else:
                val = None
                break
        if val:
            ip_str = str(val)
            if IPValidator.is_valid_ip(ip_str):
                if not (IPValidator.is_private_ip(ip_str) or IPValidator.is_loopback(ip_str)):
                    return ip_str
    return None

def find_dns(log):
    paths = ["dns.question.name", "destination.domain", "url.domain"]
    for path in paths:
        keys = path.split(".")
        val = log
        for key in keys:
            if isinstance(val, dict):
                val = val.get(key)
            else:
                val = None
                break
        if val:
            domain_str = str(val)
            if DomainValidator.is_valid_domain(domain_str):
                if not any(domain_str.lower().endswith(x) for x in [".local", ".lan"]):
                    return domain_str
    return None

print("Analyzing logs...")

for index in indices:
    try:
        query = {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": time_range.isoformat()}}}
                ]
            }
        }

        results = client.client.search(
            index=index,
            query=query,
            size=100,
            _source=True
        )

        for hit in results["hits"]["hits"]:
            log = hit["_source"]
            stats["total_logs"] += 1

            # Check for HASH
            hash_val = find_hash(log)
            if hash_val:
                stats["logs_with_hash"] += 1
                stats["hashes_found"].append(hash_val)
                if len(stats["sample_hash_logs"]) < 2:
                    stats["sample_hash_logs"].append({
                        "index": index,
                        "hash": hash_val,
                        "file_name": log.get("file", {}).get("name")
                    })

            # Check for IP
            ip_val = find_ip(log)
            if ip_val:
                stats["logs_with_ip"] += 1
                stats["ips_found"].append(ip_val)
                if len(stats["sample_ip_logs"]) < 2:
                    stats["sample_ip_logs"].append({
                        "index": index,
                        "ip": ip_val,
                        "event": log.get("event", {}).get("action")
                    })

            # Check for DNS
            dns_val = find_dns(log)
            if dns_val:
                stats["logs_with_dns"] += 1
                stats["dns_found"].append(dns_val)
                if len(stats["sample_dns_logs"]) < 2:
                    stats["sample_dns_logs"].append({
                        "index": index,
                        "dns": dns_val,
                        "event": log.get("event", {}).get("action")
                    })

    except Exception as e:
        if "no matching indices" not in str(e).lower():
            print(f"  Error in {index}: {str(e)[:60]}")

print("\n" + "="*100)
print("📊 RESULTS")
print("="*100 + "\n")

print(f"Total logs analyzed: {stats['total_logs']}")
print(f"Logs with HASH: {stats['logs_with_hash']} ({100*stats['logs_with_hash']/max(1,stats['total_logs']):.1f}%)")
print(f"Logs with EXTERNAL IP: {stats['logs_with_ip']} ({100*stats['logs_with_ip']/max(1,stats['total_logs']):.1f}%)")
print(f"Logs with DNS/Domain: {stats['logs_with_dns']} ({100*stats['logs_with_dns']/max(1,stats['total_logs']):.1f}%)")

if stats["hashes_found"]:
    print(f"\n🔍 Sample HASHES found:")
    for h in set(stats["hashes_found"][:3]):
        print(f"   {h[:16]}...")

if stats["ips_found"]:
    print(f"\n🔍 Sample EXTERNAL IPs found:")
    for ip in set(stats["ips_found"][:3]):
        print(f"   {ip}")

if stats["dns_found"]:
    print(f"\n🔍 Sample DNS/Domains found:")
    for dns in set(stats["dns_found"][:3]):
        print(f"   {dns}")

print("\n" + "="*100)
print("💡 INTERPRETATION")
print("="*100 + "\n")

if stats["logs_with_hash"] == 0 and stats["logs_with_ip"] == 0 and stats["logs_with_dns"] == 0:
    print("❌ NO IOCs FOUND IN ENDPOINT LOGS")
    print("\nThis means:")
    print("  • Elastic Endpoint is capturing logs")
    print("  • But they don't have external threat indicators (HASH, IP, DNS)")
    print("  • Your normal activities (browsing, downloads) aren't being captured")
    print("\n✅ TO GET LOGS WITH IOCs, YOU NEED TO:")
    print("  1. DOWNLOAD a file from the internet")
    print("  2. VISIT a website (check network logs)")
    print("  3. RUN an executable")
    print("  4. CONNECT to external network")
    print("\nThen run this diagnostic again to see if logs have IOCs")
else:
    print(f"✅ FOUND IOCs!")
    if stats["logs_with_hash"]:
        print(f"   📍 {stats['logs_with_hash']} logs with file hashes")
    if stats["logs_with_ip"]:
        print(f"   🌐 {stats['logs_with_ip']} logs with external IPs")
    if stats["logs_with_dns"]:
        print(f"   🔗 {stats['logs_with_dns']} logs with DNS queries")
    print(f"\n   The enrichment service WILL enrich these logs!")

client.close()

print("\n" + "="*100 + "\n")