# Threat Visualization Guide for Enriched Data

## 🎯 Quick Threat Hunting Queries

### In Discover Search Bar:

**Show Only Malicious Files:**
```
enrichments.data.detected: true
```

**Show High-Risk IPs (Abuse Score > 75):**
```
enrichments.data.abuse_confidence_score >= 75
```

**Show Known Bad Threats:**
```
enrichments.data.threat_level: "known_bad"
```

**Show Suspicious Activity:**
```
enrichments.data.threat_level: "suspicious"
```

**Show VirusTotal Detections with High Ratio:**
```
enrichments.source: "virustotal" AND enrichments.data.detected: true
```

---

## 📊 Create Threat Dashboard

### Step 1: Go to Dashboards
1. Click **☰ menu** → **Analytics** → **Dashboards**
2. Click **Create dashboard**
3. Name it: "IOC Threat Dashboard"

### Step 2: Add Visualizations

#### **Panel 1: Threat Level Distribution (Pie Chart)**
- **Type**: Pie Chart
- **Data view**: `security-alerts-enriched*`
- **Slice by**: `enrichments.data.threat_level.keyword`
- **Shows**: Distribution of known_bad, suspicious, unknown, known_good

#### **Panel 2: Malicious Files Count (Metric)**
- **Type**: Metric
- **Filter**: `enrichments.data.detected: true`
- **Metric**: Count
- **Label**: "Malicious Files Detected"

#### **Panel 3: High-Risk IPs (Data Table)**
- **Type**: Data table
- **Filter**: `enrichments.data.abuse_confidence_score >= 75`
- **Columns**: 
  - `enrichments.data.ip_address`
  - `enrichments.data.abuse_confidence_score`
  - `enrichments.data.total_reports`
  - `enrichments.data.threat_level`

#### **Panel 4: VirusTotal Detection Ratio (Bar Chart)**
- **Type**: Vertical bar chart
- **Filter**: `enrichments.source: "virustotal"`
- **X-axis**: `enrichments.data.detection_ratio.keyword`
- **Y-axis**: Count
- **Shows**: How many vendors flagged each file

#### **Panel 5: Threats Over Time (Area Chart)**
- **Type**: Area chart
- **Filter**: `enrichments.data.threat_level: "known_bad" OR enrichments.data.threat_level: "suspicious"`
- **X-axis**: `@timestamp` (Date histogram, interval: 1 hour)
- **Y-axis**: Count
- **Break down by**: `enrichments.source.keyword`

#### **Panel 6: Top Malicious Hashes (Data Table)**
- **Type**: Data table
- **Filter**: `enrichments.data.detected: true`
- **Columns**:
  - `enrichments.data.indicator` (the hash)
  - `enrichments.data.detection_ratio`
  - `enrichments.data.threat_level`
  - `source_metadata.host_name` (which host was affected)
  - `source_metadata.file_name` (what file)

---

## 🚨 Threat Level Meanings

### From VirusTotal:
- **`detected: true`** = At least one AV engine flagged it as malicious
- **`threat_level: "known_bad"`** = Confirmed malware
- **`threat_level: "unknown"`** = Not seen before or no detections

### From AbuseIPDB:
- **`abuse_confidence_score: 0-25`** = Low risk or false positive
- **`abuse_confidence_score: 26-75`** = Moderate risk, worth investigating
- **`abuse_confidence_score: 76-100`** = High risk, likely malicious

### Combined Threat Level:
Our system sets the overall `threat_level` based on the highest severity from any source:
- **`known_bad`** = Confirmed malicious by at least one source
- **`suspicious`** = Flagged but not confirmed
- **`unknown`** = No intelligence data or neutral
- **`known_good`** = Whitelisted or verified safe

---

## 🔍 Sample Queries for Common Scenarios

### Find All Malware:
```
(enrichments.data.detected: true) OR 
(enrichments.data.abuse_confidence_score >= 75) OR 
(enrichments.data.threat_level: "known_bad")
```

### Find Suspicious But Not Confirmed:
```
enrichments.data.threat_level: "suspicious" AND NOT enrichments.data.threat_level: "known_bad"
```

### Find Clean/Safe IOCs:
```
enrichments.data.threat_level: "known_good"
```

### Find Unknown IOCs (Need Investigation):
```
enrichments.data.threat_level: "unknown"
```

### Find Files with High Detection Rates:
```
enrichments.source: "virustotal" AND enrichments.data.detected: true
```
Then look at the `detection_ratio` field - anything over 5/72 is suspicious.

---

## 💡 Pro Tips

1. **Sort by Abuse Score**: In Discover, add `enrichments.data.abuse_confidence_score` as a column and sort descending to see worst IPs first

2. **Add Host Context**: Always include `source_metadata.host_name` to know which machines are affected

3. **Check Detection Ratio**: In VirusTotal results, `15/72` means 15 out of 72 AV engines detected it - higher ratio = more confident malware

4. **Cross-Reference**: If both VirusTotal AND AbuseIPDB flag the same item, it's very likely malicious

5. **Time Context**: Use the time picker to focus on recent threats (last 24 hours)

---

## 🎯 Example: Finding a Malicious File

1. **Search**: `enrichments.data.detected: true`
2. **Add columns**:
   - `enrichments.data.indicator` (the hash)
   - `enrichments.data.detection_ratio`
   - `source_metadata.file_name`
   - `source_metadata.host_name`
   - `source_metadata.process_name`
3. **Sort by**: `@timestamp` (descending) to see newest first

This shows you:
- **What** file is malicious (hash + filename)
- **Where** it was found (hostname)
- **When** it was detected (timestamp)
- **How bad** it is (detection ratio)

---

## 📧 Setting Up Alerts

### Create a Detection Rule:

1. Go to **Security** → **Alerts** → **Manage rules**
2. Click **Create new rule**
3. **Rule type**: Custom query
4. **Index patterns**: `security-alerts-enriched*`
5. **Custom query**:
   ```
   enrichments.data.threat_level: "known_bad" OR enrichments.data.detected: true OR enrichments.data.abuse_confidence_score >= 75
   ```
6. **Rule name**: "Malicious IOC Detected"
7. **Severity**: High
8. **Actions**: Send email/Slack notification

This will alert you whenever ANY malicious IOC is enriched and indexed!

---

## 🔥 Real-World Example

If you see this in your data:

```json
{
  "enrichments": [
    {
      "source": "virustotal",
      "data": {
        "detected": true,
        "detection_ratio": "42/72",
        "threat_level": "known_bad",
        "indicator": "abc123...",
        "indicator_type": "sha256"
      }
    }
  ],
  "source_metadata": {
    "host_name": "DESKTOP-COMPROMISED",
    "file_name": "malware.exe",
    "process_name": "chrome.exe"
  }
}
```

**This means:**
- ✅ **Confirmed malware** (42 out of 72 AV engines detected it!)
- ✅ **Host**: `DESKTOP-COMPROMISED` is infected
- ✅ **File**: `malware.exe` should be quarantined
- ✅ **Action needed**: Investigate and remediate immediately!
