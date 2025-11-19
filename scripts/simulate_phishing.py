#!/usr/bin/env python3
"""Simulate phishing detection without visiting real malicious sites."""

import sys
import os
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ingestion.elastic_client import ElasticClient


def create_phishing_alert_simulation():
    """Create simulated phishing alerts."""

    print("🎣 Creating SIMULATED phishing detection alerts\n")

    client = ElasticClient()

    simulated_phishing_alerts = [
        {
            "_source": {
                "@timestamp": datetime.now(timezone.utc).isoformat(),
                "alert": {
                    "uuid": "phishing-1",
                    "title": "Phishing Email Detection - Credential Harvesting",
                    "rule": {
                        "id": "phishing-001",
                        "name": "T1598 - Phishing for Information"
                    }
                },
                "event": {
                    "action": "phishing_detected",
                    "category": ["phishing"],
                    "type": ["alert"],
                },
                "host": {
                    "name": "workstation-01",
                    "os": {"name": "Windows"}
                },
                "user": {
                    "name": "user",
                    "domain": "CORP"
                },
                "email": {
                    "subject": "URGENT: Verify Your Account",
                    "sender": "noreply@secure-bank-verification.com",
                    "attachment_count": 1
                },
                "phishing": {
                    "detected_type": "credential_harvesting",
                    "target_entity": "Banking Credentials",
                    "urgency_language": True,
                    "spoofed_domain": "secure-bank-verification.com",
                    "real_domain": "bankofamerica.com"
                }
            }
        },
        {
            "_source": {
                "@timestamp": datetime.now(timezone.utc).isoformat(),
                "alert": {
                    "uuid": "phishing-2",
                    "title": "Suspicious Link Click Detected",
                    "rule": {
                        "id": "phishing-002",
                        "name": "T1566 - Phishing"
                    }
                },
                "event": {
                    "action": "url_click",
                    "category": ["web"],
                    "type": ["click"],
                },
                "host": {
                    "name": "workstation-01"
                },
                "user": {
                    "name": "user"
                },
                "url": {
                    "original": "http://legitimate-bank-verify.tk/verify?id=abc123",
                    "domain": "legitimate-bank-verify.tk",
                    "suspicious_indicators": [
                        "newly_registered_domain",
                        "typosquatting",
                        "http_not_https",
                        "suspicious_parameters"
                    ]
                },
                "source": {
                    "ip": "192.168.1.100"
                },
                "destination": {
                    "ip": "192.0.2.1",
                    "domain": "legitimate-bank-verify.tk",
                    "port": 80
                }
            }
        },
        {
            "_source": {
                "@timestamp": datetime.now(timezone.utc).isoformat(),
                "alert": {
                    "uuid": "phishing-3",
                    "title": "Credential Entry Detected - Phishing Site",
                    "rule": {
                        "id": "phishing-003",
                        "name": "Credential Theft Prevention"
                    }
                },
                "event": {
                    "action": "credential_entry",
                    "category": ["authentication"],
                    "type": ["credential_submission"],
                },
                "host": {
                    "name": "workstation-01"
                },
                "user": {
                    "name": "user"
                },
                "browser": {
                    "name": "Chrome",
                    "url_visited": "http://paypa1-verify.com/account/login",
                    "form_fields_entered": ["email", "password", "security_question"]
                },
                "threat": {
                    "indicator": "typosquatted_domain",
                    "risk": "HIGH",
                    "description": "User entered credentials on PayPal typosquatted domain"
                }
            }
        }
    ]

    indexed = 0
    for alert in simulated_phishing_alerts:
        try:
            result = client.client.index(
                index=".alerts-security.alerts-default",
                document=alert["_source"],
                op_type="create"
            )
            print(f"✅ Created: {alert['_source']['alert']['title']}")
            indexed += 1
        except Exception as e:
            print(f"❌ Failed: {str(e)[:80]}")

    client.close()

    print(f"\n{'=' * 70}")
    print(f"✅ SIMULATED {indexed}/{len(simulated_phishing_alerts)} phishing alerts")
    print(f"{'=' * 70}")
    print(f"\n🎯 Next: python scripts/process_live_alerts.py")


if __name__ == "__main__":
    create_phishing_alert_simulation()