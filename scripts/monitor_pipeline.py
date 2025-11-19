#!/usr/bin/env python3
"""Monitor pipeline performance."""

import time
from datetime import datetime, timedelta
from src.ingestion.elastic_client import ElasticClient
from src.utils.logger import get_default_logger


def monitor():
    """Monitor indexing performance."""

    logger = get_default_logger(level="INFO")
    client = ElasticClient()

    print("📊 Monitoring Pipeline Performance\n")

    while True:
        try:
            # Get counts
            response = client.client.count(index="security-alerts-enriched")
            count = response["count"]

            print(f"[{datetime.utcnow().strftime('%H:%M:%S')}] Enriched alerts: {count}")

            time.sleep(10)
        except KeyboardInterrupt:
            print("\n✅ Monitoring stopped")
            break
        except Exception as e:
            print(f"Error: {e}")


if __name__ == "__main__":
    monitor()