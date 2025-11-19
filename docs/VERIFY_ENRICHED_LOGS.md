# Verifying Enriched Logs in Elastic Security (Serverless)

## 📍 Where to Find Your Enriched Logs

Your enriched logs are stored in the index: **`security-alerts-enriched`**

They will NOT automatically appear in the standard Security Alerts interface. Instead, you need to view them through **Discover** or create custom dashboards.

---

## 🔍 Method 1: Using Discover (Recommended for Verification)

### Step-by-Step Instructions:

1. **Navigate to Discover**
   - Open your Elastic Security Serverless instance
   - Click on the **☰ hamburger menu** (top left)
   - Under **Analytics**, click **Discover**

2. **Create/Select Data View**
   - Click the **Data View** dropdown (top left, below search bar)
   - If `security-alerts-enriched*` doesn't exist, click **"Create a data view"**
   - Enter these details:
     - **Name**: `Security Alerts Enriched`
     - **Index pattern**: `security-alerts-enriched*`
     - **Timestamp field**: `@timestamp`
   - Click **Save data view to Kibana**

3. **View Enriched Documents**
   - Select the `security-alerts-enriched*` data view
   - You should now see all enriched documents
   - Use the time picker (top right) to adjust the time range

4. **Inspect Enrichment Data**
   - Click the **▶** (expand) button on any document
   - Look for these fields:
     - `enrichments[]` - Array of enrichment results
     - `iocs` - Extracted indicators
     - `status` - Should be "enriched"
     - `enriched_at` - Timestamp of enrichment

---

## 🎨 Method 2: Creating a Custom Dashboard

### Quick Setup:

1. **Go to Dashboards**
   - Click **☰ menu** → **Analytics** → **Dashboards**
   - Click **Create dashboard**

2. **Add Visualizations**

   **A. Enrichment Count Panel:**
   - Click **Create visualization**
   - Choose **Metric**
   - Data view: `security-alerts-enriched*`
   - Metric: Count
   - Label: "Total Enriched Alerts"

   **B. Enrichments by Source:**
   - Create visualization → **Pie chart** or **Bar chart**
   - Data view: `security-alerts-enriched*`
   - Buckets: `enrichments.source` (keyword)
   - Shows breakdown: VirusTotal, AbuseIPDB, MaxMind, WHOIS, Shodan

   **C. Timeline:**
   - Create visualization → **Area** or **Bar**
   - Data view: `security-alerts-enriched*`
   - X-axis: `@timestamp` (Date histogram)
   - Y-axis: Count

3. **Save Dashboard**
   - Click **Save** (top right)
   - Name it: "IOC Enrichment Dashboard"

---

## 🔎 Method 3: Using Dev Tools (Advanced)

1. **Open Dev Tools**
   - Click **☰ menu** → **Management** → **Dev Tools**

2. **Query Enriched Logs**

   ```json
   GET security-alerts-enriched/_search
   {
     "query": {
       "match_all": {}
     },
     "size": 10,
     "sort": [
       {
         "@timestamp": {
           "order": "desc"
         }
       }
     ]
   }
   ```

3. **Search for Specific IOC Type**

   ```json
   GET security-alerts-enriched/_search
   {
     "query": {
       "nested": {
         "path": "enrichments",
         "query": {
           "term": {
             "enrichments.source": "virustotal"
           }
         }
       }
     },
     "size": 10
   }
   ```

4. **Get Enrichment Statistics**

   ```json
   GET security-alerts-enriched/_search
   {
     "size": 0,
     "aggs": {
       "enrichment_sources": {
         "nested": {
           "path": "enrichments"
         },
         "aggs": {
           "by_source": {
             "terms": {
               "field": "enrichments.source"
             }
           }
         }
       }
     }
   }
   ```

---

## 📊 What Your Enriched Document Looks Like

Here's the structure of an enriched document:

```json
{
  "@timestamp": "2025-01-20T01:30:00.000Z",
  "status": "enriched",
  "enriched_at": "2025-01-20T01:30:05.123Z",
  
  "source": {
    // Original log data from Elastic Agent
    "process": {...},
    "file": {...},
    "host": {...}
  },
  
  "iocs": {
    "hashes": ["abc123..."],
    "ips": ["192.0.2.1"],
    "dns": ["example.com"]
  },
  
  "enrichments": [
    {
      "ioc_type": "hash",
      "ioc_value": "abc123...",
      "source": "virustotal",
      "data": {
        "indicator": "abc123...",
        "detected": true,
        "detection_ratio": "15/72",
        "threat_level": "known_bad",
        "vendors_count": 72
      }
    },
    {
      "ioc_type": "ip",
      "ioc_value": "192.0.2.1",
      "source": "abuseipdb",
      "data": {
        "ip_address": "192.0.2.1",
        "abuse_confidence_score": 85,
        "total_reports": 45,
        "threat_level": "known_bad",
        "is_whitelisted": false
      }
    },
    {
      "ioc_type": "ip",
      "ioc_value": "192.0.2.1",
      "source": "maxmind",
      "data": {
        "country_code": "US",
        "city": "New York",
        "latitude": 40.7128,
        "longitude": -74.0060
      }
    }
  ]
}
```

---

## 🚀 Quick Verification Checklist

After starting your enrichment service, verify it's working:

- [ ] **Check Discover**: Navigate to Discover and select `security-alerts-enriched*` data view
- [ ] **Verify Count**: Check that documents are appearing (count should increase over time)
- [ ] **Inspect Document**: Expand a document and verify `enrichments[]` array exists
- [ ] **Check Enrichment Sources**: Verify you see entries from VirusTotal, AbuseIPDB, MaxMind, WHOIS
- [ ] **Review Timestamps**: Confirm `enriched_at` is recent
- [ ] **Check Service Logs**: Review console output of `continuous_enrichment_service.py`

---

## 🎯 Useful Kibana Query Language (KQL) Searches

Use these in the Discover search bar:

```
# Show only enriched alerts
status: "enriched"

# Show alerts enriched in last hour
enriched_at >= now-1h

# Show alerts with VirusTotal detections
enrichments.source: "virustotal" AND enrichments.data.detected: true

# Show alerts with high abuse scores
enrichments.source: "abuseipdb" AND enrichments.data.abuse_confidence_score >= 80

# Show alerts with specific IOC
iocs.hashes: "abc123..." OR iocs.ips: "192.0.2.1"
```

---

## ⚠️ Troubleshooting

### "No data found"
1. Check that `continuous_enrichment_service.py` is running
2. Verify logs are being ingested into source indices (`.ds-logs-endpoint.events.*`)
3. Check service console output for errors
4. Ensure time range in Discover covers when enrichment ran

### "No enrichments field"
1. Service may not be finding IOCs in logs
2. Check that logs contain file hashes, IPs, or domains
3. Review service logs for "No IOCs found" messages

### "Index doesn't exist"
1. Service hasn't created the index yet (no enrichable logs found)
2. Run service and wait for first enrichment
3. Index is auto-created on first document write

---

## 📈 Next Steps: Integration with Security Workflows

Once verified, you can:

1. **Create Detection Rules** based on enrichment data:
   - Alert when `enrichments.data.threat_level: "known_bad"`
   - Alert on high abuse scores from AbuseIPDB

2. **Build Threat Hunting Queries**:
   - Search for patterns across enriched data
   - Correlate with MITRE ATT&CK techniques

3. **Automate Response**:
   - Trigger actions based on enrichment results
   - Block IPs with high abuse scores
   - Quarantine files detected by VirusTotal

---

## 💡 Pro Tips

- **Use Saved Searches**: Save your frequently used enrichment queries
- **Create Index Pattern Alerts**: Get notified when new enriched alerts appear
- **Export Data**: Use CSV export for reporting to management
- **Share Dashboards**: Share enrichment dashboard with SOC team
- **Schedule Reports**: Create scheduled PDF reports of enrichment trends
