# ============================================================================
# FILE 3: src/notes/generator.py
# ============================================================================

"""SOC analyst notes generation."""
from typing import Any
from src.models.event import SecurityEvent, SOCNote
from src.utils.logger import get_default_logger


class NotesGenerator:
    """Generates SOC analyst notes with evidence and remediation."""

    def __init__(self):
        """Initialize notes generator."""
        self.logger = get_default_logger(level="INFO")

    def generate(self, event: SecurityEvent) -> SOCNote:
        """
        Generate analyst note for event.

        Args:
            event: SecurityEvent to document

        Returns:
            SOCNote object
        """
        sections: dict[str, str] = {}

        # Summary section
        sections["summary"] = self._generate_summary(event)

        # Enrichment section
        sections["enrichment"] = self._generate_enrichment(event)

        # Severity and classification
        sections["severity"] = self._generate_severity(event)

        # MITRE mapping
        sections["mitre"] = self._generate_mitre(event)

        # Evidence
        sections["evidence"] = self._generate_evidence(event)

        # Remediation
        sections["remediation"] = self._generate_remediation(event)

        # Assemble full content
        content = self._build_content(sections)

        # ✅ FIX #3: Use 'extra' parameter for logger with context data
        self.logger.info(
            "Note generated",
            extra={
                "event_id": str(event.event_id),
                "sections": len(sections)
            }
        )

        return SOCNote(
            content=content,
            sections=sections,
            references=[event.event_id, event.alert_id or "N/A"],
        )

    def _generate_summary(self, event: SecurityEvent) -> str:
        """Generate summary section."""
        lines = [
            f"Alert: {event.alert_name or 'Unknown Alert'}",
            f"Host: {event.host_name or 'Unknown'}",
            f"Rule: {event.rule_name or 'Unknown'}",
        ]

        if event.user_name:
            lines.append(f"User: {event.user_name}")

        if event.process_name:
            lines.append(f"Process: {event.process_name}")

        if event.source_ip:
            lines.append(f"Source IP: {event.source_ip}")

        return "\n".join(lines)

    def _generate_enrichment(self, event: SecurityEvent) -> str:
        """Generate enrichment summary."""
        if not event.enrichments:
            return "No enrichment data available"

        lines = ["Enrichment Data:"]

        for key, enrichments in event.enrichments.items():
            lines.append(f"  {key}:")
            for enr in enrichments:
                lines.append(f"    - {enr.source}")

        return "\n".join(lines)

    def _generate_severity(self, event: SecurityEvent) -> str:
        """Generate severity section."""
        lines = [f"Severity Level: {event.severity.value.upper()}"]

        if event.triage_result:
            lines.append(f"Score: {event.triage_result.score}/100")
            lines.append(f"Confidence: {event.triage_result.confidence:.1%}")
            lines.append(f"Reasoning: {event.triage_result.reasoning}")

        return "\n".join(lines)

    def _generate_mitre(self, event: SecurityEvent) -> str:
        """Generate MITRE ATT&CK section."""
        if not event.mitre_mappings:
            return "No MITRE mappings identified"

        lines = ["MITRE ATT&CK Mapping:"]

        for mapping in event.mitre_mappings:
            lines.append(
                f"  {mapping.technique_id} - {mapping.technique_name} "
                f"({mapping.tactic})"
            )
            if mapping.subtechnique_id:
                lines.append(
                    f"    Subtechnique: {mapping.subtechnique_id}"
                )
            lines.append(f"    Confidence: {mapping.confidence:.1%}")

        return "\n".join(lines)

    def _generate_evidence(self, event: SecurityEvent) -> str:
        """Generate evidence section."""
        lines = ["Evidence:"]

        if event.process_command_line:
            lines.append(f"  Command Line: {event.process_command_line}")

        if event.file_path:
            lines.append(f"  File: {event.file_path}")

        if event.url_full:
            lines.append(f"  URL: {event.url_full}")

        if event.domain_name:
            lines.append(f"  Domain: {event.domain_name}")

        if event.iocs:
            lines.append("  Indicators of Compromise:")
            for ioc in list(event.iocs)[:5]:
                lines.append(f"    - {ioc.type}: {ioc.value}")

        return "\n".join(lines) if len(lines) > 1 else "No specific evidence available"

    def _generate_remediation(self, event: SecurityEvent) -> str:
        """Generate remediation section."""
        steps = []

        # General steps
        steps.append("1. Isolate affected system from network if necessary")

        # Process-specific
        if event.process_name:
            steps.append(f"2. Terminate malicious process: {event.process_name}")

        # User-specific
        if event.user_name:
            steps.append(f"3. Review account activity for user: {event.user_name}")
            steps.append(f"4. Reset credentials for affected user")

        # Host-specific
        if event.host_name:
            steps.append(f"5. Scan host {event.host_name} for malware")
            steps.append(f"6. Check for lateral movement from {event.host_name}")

        # IP-specific
        if event.source_ip:
            steps.append(f"7. Block IP {event.source_ip} at firewall")

        steps.append("8. Collect forensic evidence before cleanup")
        steps.append("9. Document incident for post-incident review")

        return "\n".join(steps)

    def _build_content(self, sections: dict[str, str]) -> str:
        """Build final note content."""
        parts = []

        section_order = [
            "summary",
            "severity",
            "enrichment",
            "mitre",
            "evidence",
            "remediation",
        ]

        for section_key in section_order:
            if section_key in sections:
                parts.append(f"## {section_key.upper()}")
                parts.append(sections[section_key])
                parts.append("")

        return "\n".join(parts)