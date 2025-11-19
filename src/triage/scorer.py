# ============================================================================
# src/triage/scorer.py - Severity Scoring
# ============================================================================

"""Rule-based severity scoring engine."""
from typing import Any
from src.models.event import SecurityEvent, SeverityLevel, TriageResult
from src.utils.logger import get_default_logger


class SeverityScorer:
    """Rule-based severity scoring for security events."""

    def __init__(self, thresholds: dict[str, int] | None = None):
        """
        Initialize scorer.

        Args:
            thresholds: Custom severity thresholds (default: standard)
        """
        self.thresholds = thresholds or {
            "critical": 80,
            "high": 60,
            "medium": 40,
            "low": 20,
        }
        self.logger = get_default_logger(level="INFO")

    def calculate_score(self, event: SecurityEvent) -> int:
        """
        Calculate severity score (0-100).

        Args:
            event: SecurityEvent to score

        Returns:
            Score 0-100
        """
        score = 0

        # Process execution risks
        if event.process_name:
            score += self._score_process(event.process_name)

        # Network risks
        if event.destination_port:
            score += self._score_port(event.destination_port)

        # Authentication risks
        if event.alert_name:
            alert_name_lower = event.alert_name.lower()

            if "authentication" in alert_name_lower:
                score += 25
            if "failed" in alert_name_lower or "failure" in alert_name_lower:
                score += 15
            if "privilege" in alert_name_lower or "escalation" in alert_name_lower:
                score += 30
            if "malware" in alert_name_lower:
                score += 40
            if "ransomware" in alert_name_lower:
                score += 50
            if "data exfiltration" in alert_name_lower:
                score += 35

        # File risks
        if event.file_name:
            score += self._score_file(event.file_name)

        # Process command line risks
        if event.process_command_line:
            score += self._score_command_line(event.process_command_line)

        # User risks
        if event.user_name and event.user_name == "SYSTEM":
            score += 20

        # Return capped score
        return min(100, max(0, score))

    def _score_process(self, process_name: str) -> int:
        """Score based on process name."""
        process_lower = process_name.lower()

        risky_processes = {
            "powershell": 20,
            "cmd": 15,
            "wscript": 25,
            "cscript": 25,
            "regsvcs": 30,
            "certutil": 20,
            "bitsadmin": 25,
            "psexec": 30,
            "rundll32": 20,
            "mshta": 25,
        }

        for proc, score in risky_processes.items():
            if proc in process_lower:
                return score

        return 5  # Base score for any process execution

    def _score_port(self, port: int) -> int:
        """Score based on destination port."""
        risky_ports = {
            22: 10,    # SSH
            445: 15,   # SMB
            3389: 15,  # RDP
            139: 10,   # NetBIOS
            21: 8,     # FTP
            23: 8,     # Telnet
            1433: 12,  # SQL Server
            3306: 12,  # MySQL
            5432: 12,  # PostgreSQL
        }

        return risky_ports.get(port, 0)

    def _score_file(self, file_name: str) -> int:
        """Score based on file name."""
        file_lower = file_name.lower()

        risky_extensions = {
            ".exe": 20,
            ".dll": 15,
            ".bat": 15,
            ".cmd": 15,
            ".ps1": 15,
            ".vbs": 20,
            ".js": 10,
            ".jar": 12,
            ".scr": 25,
        }

        for ext, score in risky_extensions.items():
            if file_lower.endswith(ext):
                return score

        return 0

    def _score_command_line(self, cmd_line: str) -> int:
        """Score based on command line content."""
        cmd_lower = cmd_line.lower()

        risky_patterns = {
            "whoami": 10,
            "systeminfo": 10,
            "net user": 15,
            "wmic": 12,
            "tasklist": 8,
            "ipconfig": 5,
            "ping": 3,
            "download": 20,
            "execute": 25,
            "powershell -enc": 30,
            "-noexit": 15,
            "-nologo": 10,
        }

        score = 0
        for pattern, pattern_score in risky_patterns.items():
            if pattern in cmd_lower:
                score += pattern_score

        return min(50, score)

    def get_severity(self, score: int) -> SeverityLevel:
        """
        Map score to severity level.

        Args:
            score: Severity score (0-100)

        Returns:
            SeverityLevel enum
        """
        if score >= self.thresholds["critical"]:
            return SeverityLevel.CRITICAL
        elif score >= self.thresholds["high"]:
            return SeverityLevel.HIGH
        elif score >= self.thresholds["medium"]:
            return SeverityLevel.MEDIUM
        elif score >= self.thresholds["low"]:
            return SeverityLevel.LOW
        else:
            return SeverityLevel.INFO

    def score_event(self, event: SecurityEvent) -> TriageResult:
        """
        Score and triage an event.

        Args:
            event: SecurityEvent to score

        Returns:
            TriageResult
        """
        score = self.calculate_score(event)
        severity = self.get_severity(score)
        confidence = min(1.0, score / 100.0)

        return TriageResult(
            classifier="rule_based",
            classification=severity.value,
            severity=severity,
            score=score,
            confidence=confidence,
            reasoning=self._generate_reasoning(event, score),
        )

    def _generate_reasoning(self, event: SecurityEvent, score: int) -> str:
        """Generate reasoning for score."""
        reasons = []

        if event.process_name:
            if any(x in event.process_name.lower() for x in ["powershell", "cmd"]):
                reasons.append("Execution via command interpreter")

        if event.alert_name and "failed" in event.alert_name.lower():
            reasons.append("Authentication failure detected")

        if event.process_command_line and "whoami" in event.process_command_line.lower():
            reasons.append("System reconnaissance activity")

        if score >= 80:
            reasons.append("Multiple high-risk indicators")

        return "; ".join(reasons) if reasons else "Generic security event"

