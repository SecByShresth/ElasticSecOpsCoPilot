# ============================================================================
# src/triage/classifier.py - Event Classification
# ============================================================================

"""Event classification engine."""
from typing import Any
from src.models.event import SecurityEvent
from src.utils.logger import get_default_logger


class EventClassifier:
    """Classifies security events by type and threat."""

    def __init__(self):
        """Initialize classifier."""
        self.logger = get_default_logger(level="INFO")

    def classify(self, event: SecurityEvent) -> tuple[str, float]:
        """
        Classify event.

        Args:
            event: SecurityEvent to classify

        Returns:
            Tuple of (classification, confidence)
        """
        alert_name = (event.alert_name or "").lower()
        event_action = (event.event_action or "").lower()

        # Malware detection
        if any(x in alert_name for x in ["malware", "trojan", "worm", "virus"]):
            return ("malware", 0.95)

        if "ransomware" in alert_name:
            return ("ransomware", 0.95)

        # Phishing
        if "phishing" in alert_name or "spearphishing" in alert_name:
            return ("phishing", 0.90)

        # Exploitation
        if "exploit" in alert_name or "cve-" in alert_name:
            return ("exploitation", 0.90)

        # Lateral movement
        if "lateral" in alert_name or "pass the hash" in alert_name:
            return ("lateral_movement", 0.85)

        # Data exfiltration
        if any(x in alert_name for x in ["exfiltration", "data transfer", "upload"]):
            return ("data_exfiltration", 0.85)

        # Privilege escalation
        if "privilege escalation" in alert_name or "privelege" in alert_name:
            return ("privilege_escalation", 0.85)

        # Command & control
        if any(x in alert_name for x in ["command and control", "c2", "c&c"]):
            return ("command_and_control", 0.85)

        # Persistence
        if "persistence" in alert_name or "registry" in alert_name:
            return ("persistence", 0.75)

        # Authentication attacks
        if any(x in alert_name for x in ["brute force", "credential", "authentication"]):
            return ("authentication_attack", 0.80)

        # Suspicious but unclassified
        if "suspicious" in alert_name or "anomaly" in alert_name:
            return ("suspicious", 0.75)

        # Policy violation
        if any(x in alert_name for x in ["policy", "violation", "unauthorized"]):
            return ("policy_violation", 0.70)

        # Unknown
        return ("unknown", 0.50)