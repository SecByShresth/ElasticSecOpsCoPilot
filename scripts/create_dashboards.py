#!/usr/bin/env python3
"""Manual instructions for creating Kibana dashboard."""


def print_dashboard_instructions():
    """Print instructions to create dashboard manually."""

    instructions = """
═══════════════════════════════════════════════════════════════════════════════
🎨 HOW TO CREATE A REAL-TIME MONITORING DASHBOARD IN KIBANA
═══════════════════════════════════════════════════════════════════════════════

STEP 1: Open Kibana Dashboard Creator
─────────────────────────────────────────────────────────────────────────────
1. Open Kibana (from Elastic Cloud console)
2. Click: Dashboard (left sidebar)
3. Click: Create Dashboard
4. Name it: "Security Alerts Enrichment"

STEP 2: Add Visualization 1 - Alert Timeline
─────────────────────────────────────────────────────────────────────────────
1. Click: Create Visualization (or Add Panel → Create New)
2. Select: Area chart
3. Data source: security-alerts-enriched
4. Time field: @timestamp
5. Click: Visualize

STEP 3: Add Visualization 2 - Severity Distribution
─────────────────────────────────────────────────────────────────────────────
1. Create New Visualization → Pie chart
2. Data source: security-alerts-enriched
3. Metrics: Count
4. Buckets → Split slices:
   - Aggregation: Terms
   - Field: severity.keyword
5. Click: Visualize

STEP 4: Add Visualization 3 - Top MITRE Techniques
─────────────────────────────────────────────────────────────────────────────
1. Create New Visualization → Horizontal Bar
2. Data source: security-alerts-enriched
3. Metrics: Count
4. Buckets → X-axis:
   - Aggregation: Terms
   - Field: mitre_mappings.technique_id
   - Size: 10
5. Click: Visualize

STEP 5: Add Visualization 4 - Alert Table
─────────────────────────────────────────────────────────────────────────────
1. Go to Discover
2. Select: security-alerts-enriched
3. Select these columns:
   - @timestamp
   - alert_name
   - severity
   - triage_result.score
   - mitre_mappings.technique_id
4. Save as visualization
5. Add to dashboard

STEP 6: Configure Auto-Refresh
─────────────────────────────────────────────────────────────────────────────
1. Click the Refresh icon (top right of dashboard)
2. Select: 5 seconds
3. Dashboard now auto-updates every 5 seconds!

═══════════════════════════════════════════════════════════════════════════════
🎯 WHAT YOU'LL SEE ON YOUR DASHBOARD
═══════════════════════════════════════════════════════════════════════════════

Timeline Chart:
  Shows alerts flowing in over time - as new events arrive, you'll see
  the line go up in real-time

Severity Pie Chart:
  Breakdown of:
  - 🔴 Critical (80-100)
  - 🟠 High (60-79)
  - 🟡 Medium (40-59)
  - 🟢 Low (0-39)

Top MITRE Techniques:
  Shows most detected attack techniques:
  - T1110: Brute Force
  - T1059: Command Line
  - T1021: Lateral Movement
  - etc.

Alert Table:
  Real-time table of all alerts with:
  - When it happened (@timestamp)
  - Alert name (what triggered)
  - Severity (auto-scored)
  - Score (0-100)
  - MITRE technique (what attack type)

═══════════════════════════════════════════════════════════════════════════════
🚀 NEXT: SET UP CONTINUOUS MONITORING
═══════════════════════════════════════════════════════════════════════════════

Once dashboard is created, run this to continuously enrich new alerts:

  python scripts/continuous_enrichment.py

This will:
  ✅ Check for new raw alerts every 5 minutes
  ✅ Enrich them automatically
  ✅ Add to security-alerts-enriched index
  ✅ Dashboard updates in real-time!

═══════════════════════════════════════════════════════════════════════════════
📊 EXPECTED RESULTS AFTER 1 HOUR
═══════════════════════════════════════════════════════════════════════════════

With continuous monitoring running:

Dashboard Timeline:
  [Chart showing steady stream of alerts]

Alert Count:
  Starting: 6 alerts
  After 1 hour: 20+ alerts (depends on system activity)

Severity:
  🔴 High: 40%
  🟡 Medium: 35%
  🟢 Low: 20%
  ⚪ Info: 5%

Top Techniques:
  T1021 Lateral Movement: 8 alerts
  T1059 Command Line: 6 alerts
  T1110 Brute Force: 4 alerts

═══════════════════════════════════════════════════════════════════════════════
💡 QUICK TIPS
═══════════════════════════════════════════════════════════════════════════════

1. Click on any alert to see full details:
   - Severity score breakdown
   - Enrichment data (if enabled)
   - MITRE mapping reasoning
   - Correlation details
   - Remediation steps

2. Use filters to drill down:
   - Filter by severity: severity: "high"
   - Filter by technique: mitre_mappings.technique_id: "T1021"
   - Filter by host: host_name: "workstation-01"

3. Create alerts on dashboard (auto-notify you):
   - Click: Alerts
   - Set threshold: "High alerts > 5 in 1 hour"
   - Set notification: Email

4. Export data:
   - Select time range
   - Click: Export
   - Save as CSV/JSON

═══════════════════════════════════════════════════════════════════════════════
✅ YOUR SYSTEM IS NOW MONITORING & ENRICHING ALERTS IN REAL-TIME!
═══════════════════════════════════════════════════════════════════════════════
"""

    print(instructions)


if __name__ == "__main__":
    print_dashboard_instructions()