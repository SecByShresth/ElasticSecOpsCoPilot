# ============================================================================
# src/correlation/patterns.py - Pattern Definitions
# ============================================================================

"""Correlation pattern definitions."""
from src.models.correlation import (
    CorrelationPattern,
    CorrelationPatternType,
)


class PatternLibrary:
    """Library of predefined correlation patterns."""

    @staticmethod
    def get_all_patterns() -> list[CorrelationPattern]:
        """Get all available patterns."""
        return [
            PatternLibrary.failed_login_pattern(),
            PatternLibrary.lateral_movement_pattern(),
            PatternLibrary.data_exfiltration_pattern(),
            PatternLibrary.privilege_escalation_pattern(),
            PatternLibrary.malware_execution_pattern(),
        ]

    @staticmethod
    def failed_login_pattern() -> CorrelationPattern:
        """Failed login detection pattern."""
        return CorrelationPattern(
            name="multi_failed_login_detection",
            pattern_type=CorrelationPatternType.BEHAVIORAL_CHAIN,
            description="Multiple failed login attempts within time window",
            conditions=[
                "event.action:authentication-failure",
                "event.action:user-login-failed",
                "event.action:invalid-credentials",
            ],
            threshold=5,
            time_window_seconds=600,
            weight=1.0,
            enabled=True,
            tags=["authentication", "brute_force", "initial_access"],
        )

    @staticmethod
    def lateral_movement_pattern() -> CorrelationPattern:
        """Lateral movement detection pattern."""
        return CorrelationPattern(
            name="lateral_movement",
            pattern_type=CorrelationPatternType.LATERAL_MOVEMENT,
            description="Lateral movement across hosts",
            conditions=[
                "network.protocol:ssh",
                "network.protocol:rdp",
                "network.protocol:smb",
                "event.action:process-execution",
                "event.action:command-execution",
            ],
            threshold=2,
            time_window_seconds=1800,
            weight=1.2,
            enabled=True,
            tags=["lateral_movement", "execution", "command_and_control"],
        )

    @staticmethod
    def data_exfiltration_pattern() -> CorrelationPattern:
        """Data exfiltration detection pattern."""
        return CorrelationPattern(
            name="data_exfiltration_chain",
            pattern_type=CorrelationPatternType.DATA_EXFILTRATION,
            description="Data exfiltration activity detection",
            conditions=[
                "event.action:file-transfer",
                "event.action:data-transfer",
                "event.action:upload",
            ],
            threshold=1,
            time_window_seconds=3600,
            weight=1.5,
            enabled=True,
            tags=["exfiltration", "data_loss", "impact"],
        )

    @staticmethod
    def privilege_escalation_pattern() -> CorrelationPattern:
        """Privilege escalation detection pattern."""
        return CorrelationPattern(
            name="privilege_escalation_chain",
            pattern_type=CorrelationPatternType.PRIVILEGE_ESCALATION,
            description="Privilege escalation attempts",
            conditions=[
                "event.action:privilege-escalation",
                "event.action:elevation",
                "process.name:whoami",
                "process.name:systeminfo",
            ],
            threshold=2,
            time_window_seconds=900,
            weight=1.3,
            enabled=True,
            tags=["privilege_escalation", "execution", "persistence"],
        )

    @staticmethod
    def malware_execution_pattern() -> CorrelationPattern:
        """Malware execution detection pattern."""
        return CorrelationPattern(
            name="malware_execution_chain",
            pattern_type=CorrelationPatternType.MULTI_STAGE_ATTACK,
            description="Malware execution and propagation",
            conditions=[
                "alert.name:malware",
                "alert.name:trojan",
                "alert.name:ransomware",
                "process.name:powershell",
            ],
            threshold=1,
            time_window_seconds=3600,
            weight=2.0,
            enabled=True,
            tags=["malware", "execution", "impact"],
        )
