# ElasticSecOpsCoPilot 🛡️

**An autonomous security operations agent for Elastic Security (Serverless & Cloud).**

ElasticSecOpsCoPilot is a Python-based service that acts as a force multiplier for SOC analysts. It continuously monitors your Elastic Security logs, automatically extracts Indicators of Compromise (IOCs), enriches them with threat intelligence from multiple providers, and indexes the enriched data back into Elasticsearch for immediate threat hunting and alerting.

## 🚀 Key Features

*   **Real-time Enrichment**: Automatically detects and enriches IOCs from `logs-*` and `events-*` indices.
*   **Multi-Source Intelligence**:
    *   🦠 **VirusTotal**: Hash analysis (MD5, SHA1, SHA256) for malware detection.
    *   🌐 **AbuseIPDB**: IP reputation scoring and confidence levels.
    *   🌍 **IPLocation.net**: Geo-location and ISP data (Free API, no database required).
    *   🔎 **Shodan**: Internet-wide scan data for IP addresses.
    *   📋 **WHOIS**: Domain registration and registrar information.
*   **Elastic Serverless Ready**: Fully compatible with Elastic Cloud Serverless environments.
*   **Smart Rate Limiting**: Built-in rate limiters to respect free-tier API quotas (e.g., VirusTotal's 4 requests/min).
*   **Optimized Storage**: Stores lightweight enriched documents to avoid Elasticsearch field limit explosions.
*   **Threat Scoring**: Normalizes threat levels (`known_bad`, `suspicious`, `safe`) across different providers.

---

## 🛠️ Installation

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/yourusername/ElasticSecOpsCoPilot.git
    cd ElasticSecOpsCoPilot
    ```

2.  **Create a virtual environment** (recommended):
    ```bash
    python -m venv .venv
    source .venv/bin/activate  # On Windows: .venv\Scripts\activate
    ```

3.  **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

---

## ⚙️ Configuration

1.  **Configure `config/config.yaml`**:
    Copy the template or edit the existing `config/config.yaml` file. You will need to provide:
    *   **Elasticsearch Connection**: API Endpoint and API Key.
    *   **API Keys**: Add your keys for VirusTotal, AbuseIPDB, and Shodan.
    *   **IPLocation**: Enabled by default (no key required).

    ```yaml
    elastic:
      serverless:
        api_endpoint: "https://your-project.es.us-central1.gcp.elastic.cloud"
        api_key: "YOUR_ELASTIC_API_KEY"

    enrichment:
      virustotal:
        api_key: "YOUR_VT_API_KEY"
      abuseipdb:
        api_key: "YOUR_ABUSEIPDB_KEY"
    ```

---

## 🏃‍♂️ Usage

### Start the Enrichment Service
Run the continuous enrichment service. It will poll for new logs, enrich them, and index the results to `security-alerts-enriched`.

```bash
python scripts/continuous_enrichment_service.py
```

You should see output indicating it is fetching logs and enriching IOCs:
```
[Iteration 1] Fetching logs...
✅ Found 15 logs

  📍 HASH: a342a53c... -> VT: ✅
  🌐 IP: 13.69.239.73 -> Shodan: ❌ Abuse: ✅ Geo: ✅
```

### Verify Results
Go to your **Elastic Security** instance and discover the `security-alerts-enriched` index. You can use the provided guides in the `docs/` folder to set up dashboards and threat hunting queries.

---

## 📂 Project Structure

Here is an explanation of the key files in this repository:

### **Root Directory**
*   `requirements.txt`: Python dependencies required to run the project.
*   `README.md`: This documentation file.

### **`scripts/`** - Operational Scripts
*   `continuous_enrichment_service.py`: **The Core Service**. Runs an infinite loop to fetch logs, extract IOCs, call enrichers, and save results.
*   `verify_enrichment_service.py`: A test script to verify that your API keys and enrichment logic are working correctly without running the full service.
*   `reset_enriched_index.py`: Utility to delete and recreate the output index if mapping errors occur.
*   `create_dashboards.py`: Script to programmatically create Kibana dashboards (if permissions allow).
*   `analyze_endpoint_logs.py`: Helper to analyze raw endpoint logs for debugging.

### **`src/`** - Source Code
*   **`src/enrichment/`**: Contains the logic for each threat intel provider.
    *   `virustotal.py`: VirusTotal API integration.
    *   `abuseipdb.py`: AbuseIPDB API integration.
    *   `iplocation.py`: IPLocation.net integration (GeoIP).
    *   `shodan_enricher.py`: Shodan API integration.
    *   `whois_enricher.py`: WHOIS lookup logic.
    *   `base.py`: Base class for all enrichers, handling caching and rate limiting.
*   **`src/ingestion/`**:
    *   `elastic_client.py`: Wrapper for the Elasticsearch Python client, handling connection and queries.
*   **`src/models/`**:
    *   `enrichment.py`: Data classes (Pydantic/Dataclasses) defining the structure of enriched data.
*   **`src/utils/`**:
    *   `config_loader.py`: Utilities for reading and validating `config.yaml`.
    *   `logger.py`: Centralized logging configuration.

### **`config/`**
*   `config.yaml`: Main configuration file for API keys, thresholds, and settings.

### **`docs/`**
*   `THREAT_HUNTING_GUIDE.md`: **Must Read**. A guide on how to query the enriched data to find threats.
*   `VERIFY_ENRICHED_LOGS.md`: Instructions on how to verify data in the Elastic UI.
*   `IPLOCATION_SETUP.md`: Documentation specific to the IPLocation integration.

---

## 🛡️ Threat Hunting

Once data is flowing, use **Kibana / Elastic Security** to hunt for threats.

**Example Query (Find confirmed malware):**
```kql
enrichments.data.threat_level: "known_bad" OR enrichments.data.detected: true
```

**Example Query (Find high-risk IPs):**
```kql
enrichments.data.abuse_confidence_score >= 75
```

See `docs/THREAT_HUNTING_GUIDE.md` for detailed hunting workflows.
