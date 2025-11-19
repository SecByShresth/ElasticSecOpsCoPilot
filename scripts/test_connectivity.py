#!/usr/bin/env python3
"""
Test script for Elastic SecOps Copilot foundation.
Validates all core components are working correctly.
Compatible with Python 3.13+

Usage:
    python scripts/test_connectivity.py
"""

import sys
import json
from pathlib import Path
from datetime import datetime

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Test imports
print("=" * 70)
print("Elastic SecOps Copilot - Foundation Test Suite")
print("=" * 70)
print()


def test_imports():
    """Test all imports work correctly."""
    print("📦 Testing imports...")
    try:
        from src import (
            SecurityEvent,
            SeverityLevel,
            EventStatus,
            IOC,
            EnrichedIOC,
            ThreatLevel,
            CorrelationCluster,
            get_config,
            get_default_logger,
            IPValidator,
            DomainValidator,
            HashValidator,
        )
        print("✅ All imports successful")
        return True
    except ImportError as e:
        print(f"❌ Import failed: {e}")
        return False


def test_models():
    """Test core model functionality."""
    print("\n📋 Testing models...")

    from src import SecurityEvent, IOC, SeverityLevel, EventStatus

    try:
        # Create event
        event = SecurityEvent(
            alert_name="Test Alert",
            rule_name="Test Rule",
            host_name="test-host",
            severity=SeverityLevel.HIGH,
        )

        # Verify fields
        assert event.event_id is not None
        assert event.severity == SeverityLevel.HIGH
        assert event.status == EventStatus.INGESTED

        # Add IOC
        ioc = IOC(type="ip", value="192.168.1.1", confidence=0.9)
        event.add_ioc(ioc)
        assert len(event.iocs) == 1

        # Add tag
        event.add_tag("malicious")
        assert "malicious" in event.tags

        # Update status
        event.add_status(EventStatus.ENRICHED)
        assert event.status == EventStatus.ENRICHED
        assert len(event.status_history) >= 1

        # Convert to dict
        event_dict = event.to_dict()
        assert event_dict["alert_name"] == "Test Alert"

        # Convert to JSON
        event_json = event.to_json()
        assert isinstance(event_json, str)

        print("✅ Model tests passed")
        return True

    except Exception as e:
        print(f"❌ Model test failed: {e}")
        return False


def test_ioc_hashability():
    """Test that IOCs are hashable and can be stored in sets."""
    print("\n🔑 Testing IOC hashability...")

    from src import IOC

    try:
        ioc1 = IOC(type="ip", value="192.168.1.1")
        ioc2 = IOC(type="ip", value="192.168.1.1")
        ioc3 = IOC(type="domain", value="example.com")

        # Test hashing
        ioc_set = {ioc1, ioc2, ioc3}
        assert len(ioc_set) == 2, "Duplicate IOCs should be deduped"

        # Test equality
        assert ioc1 == ioc2, "Same IOCs should be equal"
        assert ioc1 != ioc3, "Different IOCs should not be equal"

        print("✅ IOC hashability tests passed")
        return True

    except Exception as e:
        print(f"❌ IOC hashability test failed: {e}")
        return False


def test_validators():
    """Test validation functions."""
    print("\n✓ Testing validators...")

    from src.utils.validators import (
        IPValidator,
        DomainValidator,
        URLValidator,
        HashValidator,
        IOCValidator,
    )

    try:
        # IP validation
        assert IPValidator.is_valid_ipv4("192.168.1.1") == True
        assert IPValidator.is_valid_ipv4("256.1.1.1") == False
        assert IPValidator.is_private_ip("10.0.0.1") == True

        # Domain validation
        assert DomainValidator.is_valid_domain("example.com") == True
        assert DomainValidator.is_valid_domain("sub.example.com") == True
        assert DomainValidator.is_valid_domain("invalid..com") == False

        # URL validation
        assert URLValidator.is_valid_url("https://example.com") == True
        assert URLValidator.is_valid_url("not-a-url") == False

        # Hash validation
        assert HashValidator.is_valid_md5("5d41402abc4b2a76b9719d911017c592") == True
        assert HashValidator.is_valid_sha256(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ) == True

        # IOC validation
        is_valid, error = IOCValidator.validate_ioc("ip", "192.168.1.1")
        assert is_valid == True

        is_valid, error = IOCValidator.validate_ioc("ip", "invalid-ip")
        assert is_valid == False

        # IOC extraction
        text = "Check IPs 192.168.1.1 and 10.0.0.1 for evil.com"
        ips = IOCValidator.extract_ips(text)
        assert len(ips) == 2

        domains = IOCValidator.extract_domains(text)
        assert len(domains) >= 1

        print("✅ Validator tests passed")
        return True

    except AssertionError as e:
        print(f"❌ Validator test failed: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error in validators: {e}")
        return False


def test_logger():
    """Test logging setup."""
    print("\n📝 Testing logger...")

    try:
        from src.utils.logger import get_default_logger, LoggerConfig

        # Get default logger
        logger = get_default_logger(level="INFO")

        # Test logging
        logger.info("Test info message")
        logger.warning("Test warning message")

        # Test custom config
        config = LoggerConfig(
            name="test-logger",
            level="DEBUG",
            log_format="text",
        )
        test_logger = config.get_logger()
        test_logger.debug("Debug message")

        print("✅ Logger tests passed")
        return True

    except Exception as e:
        print(f"❌ Logger test failed: {e}")
        return False


def test_config_loader():
    """Test configuration loading."""
    print("\n⚙️  Testing config loader...")

    try:
        from src.utils.config_loader import ConfigLoader, ConfigError

        # Create test config file
        test_config_path = Path(".test_config.yaml")
        test_config_content = """
elastic:
  deployment_type: serverless
  serverless:
    api_endpoint: "https://test.serverless.us-east-1.aws.elastic.cloud"
    api_key: "test_key_123"

enrichment:
  virustotal:
    enabled: true
    api_key: "test_vt_key"
  abuseipdb:
    enabled: false

triage:
  severity_thresholds:
    critical: 80
    high: 60
"""
        test_config_path.write_text(test_config_content)

        try:
            # Load config
            config = ConfigLoader(str(test_config_path))

            # Test get methods
            deployment = config.get("elastic.deployment_type")
            assert deployment == "serverless"

            vt_enabled = config.get("enrichment.virustotal.enabled")
            assert vt_enabled == True

            abuseipdb_enabled = config.get("enrichment.abuseipdb.enabled")
            assert abuseipdb_enabled == False

            # Test default values
            missing = config.get("missing.key", "default_value")
            assert missing == "default_value"

            # Test section retrieval
            triage = config.get_section("triage")
            assert "severity_thresholds" in triage

            print("✅ Config loader tests passed")
            return True

        finally:
            # Cleanup
            if test_config_path.exists():
                test_config_path.unlink()

    except Exception as e:
        print(f"❌ Config loader test failed: {e}")
        return False


def test_elastic_alert_parsing():
    """Test parsing of Elastic alert documents."""
    print("\n🔍 Testing Elastic alert parsing...")

    from src import SecurityEvent

    try:
        # Create mock Elastic alert
        elastic_alert = {
            "_id": "test_alert_id",
            "_source": {
                "@timestamp": "2024-01-15T10:30:00Z",
                "alert": {
                    "uuid": "alert_uuid_123",
                    "title": "Suspicious Process Execution",
                    "description": "Unusual process detected",
                    "rule": {
                        "id": "rule_123",
                        "name": "Suspicious Parent Process"
                    }
                },
                "event": {
                    "action": "execution",
                    "category": ["process"],
                    "type": ["start"],
                    "module": "endpoint",
                    "dataset": "endpoint.events"
                },
                "host": {
                    "name": "WORKSTATION-01",
                    "id": "host_id_123",
                    "os": {
                        "name": "Windows"
                    },
                    "ip": ["192.168.1.100"]
                },
                "process": {
                    "pid": 1234,
                    "name": "powershell.exe",
                    "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "command_line": "powershell.exe -Command malicious code",
                    "hash": {
                        "md5": "5d41402abc4b2a76b9719d911017c592",
                        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                    },
                    "parent": {
                        "pid": 5678,
                        "name": "explorer.exe"
                    }
                },
                "user": {
                    "name": "DOMAIN\\user",
                    "id": "user_id_123",
                    "domain": "DOMAIN"
                }
            }
        }

        # Parse alert
        event = SecurityEvent.from_elastic_alert(elastic_alert)

        # Verify parsed fields
        assert event.elastic_doc_id == "test_alert_id"
        assert event.alert_name == "Suspicious Process Execution"
        assert event.rule_id == "rule_123"
        assert event.host_name == "WORKSTATION-01"
        assert event.process_name == "powershell.exe"
        assert event.process_hash_md5 == "5d41402abc4b2a76b9719d911017c592"
        assert event.user_name == "DOMAIN\\user"
        assert event.host_ip == ["192.168.1.100"]

        print("✅ Elastic alert parsing tests passed")
        return True

    except Exception as e:
        print(f"❌ Elastic alert parsing test failed: {e}")
        return False


def test_enrichment_models():
    """Test enrichment result models."""
    print("\n🌐 Testing enrichment models...")

    from src import (
        VirusTotalResult,
        AbuseIPDBResult,
        EnrichedIOC,
        ThreatLevel,
    )

    try:
        # Create enrichment results
        vt_result = VirusTotalResult(
            indicator="5d41402abc4b2a76b9719d911017c592",
            indicator_type="file",
            detected=True,
            detection_ratio="5/72",
            threat_level=ThreatLevel.KNOWN_BAD,
        )

        abuse_result = AbuseIPDBResult(
            ip_address="192.168.1.1",
            abuse_confidence_score=85.5,
            total_reports=42,
            threat_level=ThreatLevel.SUSPICIOUS,
        )

        # Create enriched IOC
        ioc = EnrichedIOC(
            type="file",
            value="5d41402abc4b2a76b9719d911017c592",
            threat_level=ThreatLevel.KNOWN_BAD,
        )

        ioc.virustotal = vt_result

        # Get threat summary
        summary = ioc.get_threat_summary()
        assert "VirusTotal" in summary

        print("✅ Enrichment model tests passed")
        return True

    except Exception as e:
        print(f"❌ Enrichment model test failed: {e}")
        return False


def test_correlation_models():
    """Test correlation models."""
    print("\n🔗 Testing correlation models...")

    from src import CorrelationCluster, CorrelationPattern, CorrelationPatternType

    try:
        # Create pattern
        pattern = CorrelationPattern(
            name="Multi Failed Login",
            pattern_type=CorrelationPatternType.BEHAVIORAL_CHAIN,
            description="Multiple failed login attempts",
            conditions=["event.action=failed_login"],
            threshold=5,
            time_window_seconds=600,
        )

        # Create cluster
        cluster = CorrelationCluster()

        # Add events
        now = datetime.utcnow()
        cluster.add_event("event_1", now)
        cluster.add_event("event_2", now)

        assert len(cluster.event_ids) == 2

        # Add indicators
        cluster.add_indicator("ip", "192.168.1.1")
        cluster.add_indicator("user", "testuser")

        assert "ip" in cluster.indicators

        # Check expiration
        assert cluster.is_expired() == False

        print("✅ Correlation model tests passed")
        return True

    except Exception as e:
        print(f"❌ Correlation model test failed: {e}")
        return False


def run_all_tests():
    """Run all tests and report results."""
    tests = [
        ("Imports", test_imports),
        ("Models", test_models),
        ("IOC Hashability", test_ioc_hashability),
        ("Validators", test_validators),
        ("Logger", test_logger),
        ("Config Loader", test_config_loader),
        ("Elastic Alert Parsing", test_elastic_alert_parsing),
        ("Enrichment Models", test_enrichment_models),
        ("Correlation Models", test_correlation_models),
    ]

    results = []

    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"\n❌ Unexpected error in {test_name}: {e}")
            results.append((test_name, False))

    # Summary
    print("\n" + "=" * 70)
    print("Test Summary")
    print("=" * 70)

    passed = sum(1 for _, result in results if result)
    total = len(results)

    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{test_name:.<50} {status}")

    print("-" * 70)
    print(f"Results: {passed}/{total} passed")
    print("=" * 70)

    return passed == total


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)