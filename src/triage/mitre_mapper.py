# ============================================================================
# src/triage/mitre_mapper.py - MITRE ATT&CK Mapping
# ============================================================================

"""MITRE ATT&CK technique mapping."""
import json
from typing import Any
from src.models.event import SecurityEvent, MitreMapping
from src.utils.logger import get_default_logger


class MitreMapper:
    """Maps security events to MITRE ATT&CK techniques."""

    def __init__(self, db_path: str = "config/mitre_techniques.json"):
        """
        Initialize MITRE mapper.

        Args:
            db_path: Path to MITRE database
        """
        self.logger = get_default_logger(level="INFO")
        self.techniques = self._load_mitre_db(db_path)

    def _load_mitre_db(self, db_path: str) -> dict[str, Any]:
        """Load MITRE database."""
        try:
            with open(db_path) as f:
                return json.load(f)
        except FileNotFoundError:
            self.logger.warning(f"MITRE database not found at {db_path}")
            return self._get_default_techniques()
        except Exception as e:
            self.logger.error(f"Failed to load MITRE database: {e}")
            return self._get_default_techniques()

    def map_event(self, event: SecurityEvent) -> list[MitreMapping]:
        """
        Map event to MITRE techniques.

        Args:
            event: SecurityEvent to map

        Returns:
            List of MitreMapping objects
        """
        mappings = []
        alert_name = (event.alert_name or "").lower()
        process_name = (event.process_name or "").lower()

        # T1047 - Windows Management Instrumentation
        if any(x in alert_name for x in ["wmi", "winmgmt", "wbemexec"]):
            mappings.append(MitreMapping(
                technique_id="T1047",
                technique_name="Windows Management Instrumentation",
                tactic="execution",
                confidence=0.85,
                evidence=[alert_name]
            ))

        # T1059 - Command and Scripting Interpreter
        if any(x in process_name for x in ["powershell", "cmd.exe", "bash"]):
            mappings.append(MitreMapping(
                technique_id="T1059",
                technique_name="Command and Scripting Interpreter",
                tactic="execution",
                confidence=0.90,
                evidence=[process_name]
            ))

        # T1566 - Phishing
        if "phishing" in alert_name:
            mappings.append(MitreMapping(
                technique_id="T1566",
                technique_name="Phishing",
                tactic="initial-access",
                confidence=0.85,
                evidence=[alert_name]
            ))

        # T1090 - Proxy
        if any(x in alert_name for x in ["proxy", "vpn", "tor"]):
            mappings.append(MitreMapping(
                technique_id="T1090",
                technique_name="Proxy",
                tactic="command-and-control",
                confidence=0.75,
                evidence=[alert_name]
            ))

        # T1587 - Develop Capabilities
        if "malware" in alert_name or "trojan" in alert_name:
            mappings.append(MitreMapping(
                technique_id="T1587",
                technique_name="Develop Capabilities",
                tactic="resource-development",
                confidence=0.80,
                evidence=[alert_name]
            ))

        return mappings

    def _get_default_techniques(self) -> dict[str, Any]:
        """Get default techniques when database unavailable."""
        return {
            "T1047": {"name": "Windows Management Instrumentation", "tactic": "execution"},
            "T1059": {"name": "Command and Scripting Interpreter", "tactic": "execution"},
            "T1566": {"name": "Phishing", "tactic": "initial-access"},
            "T1090": {"name": "Proxy", "tactic": "command-and-control"},
        }