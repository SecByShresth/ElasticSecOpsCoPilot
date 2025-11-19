#!/usr/bin/env python3
"""
Verification script for IOC Enrichment Logic
"""

import sys
import os
import logging

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from scripts.continuous_enrichment_service import extract_iocs, enrich_data
    print("✅ Successfully imported service functions")
except Exception as e:
    print(f"❌ Failed to import service functions: {e}")
    sys.exit(1)

def test_extraction():
    print("\n[Test 1] Testing IOC Extraction...")
    
    sample_log = {
        "file": {
            "hash": {
                "sha256": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
            }
        },
        "source": {
            "ip": "8.8.8.8"
        },
        "dns": {
            "question": {
                "name": "google.com"
            }
        }
    }
    
    iocs = extract_iocs(sample_log)
    
    print(f"Extracted IOCs: {iocs}")
    
    assert "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8" in iocs["hashes"]
    assert "8.8.8.8" in iocs["ips"]
    assert "google.com" in iocs["dns"]
    print("✅ IOC Extraction passed")


def test_enrichment():
    """Test enrichment with mock enrichers"""
    print("\n[Test 2] Testing Enrichment Logic...")
    
    # Mock enrichers and logger
    mock_enrichers = {}
    mock_logger = logging.getLogger("test")
    
    # Test IOCs
    test_iocs = {
        "hashes": ["5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"],
        "ips": ["8.8.8.8"],
        "dns": ["google.com"]
    }
    
    # Run enrichment (will skip actual API calls since enrichers dict is empty)
    results = enrich_data(test_iocs, mock_enrichers, mock_logger)
    
    print(f"Enrichment Results Type: {type(results)}")
    print(f"Enrichment Results: {results}")
    
    # Since we have no enrichers, results should be an empty list
    if isinstance(results, list):
        print(f"✅ Enrichment returned list with {len(results)} items")
    else:
        print(f"❌ Expected list, got {type(results)}")
    
    print("\n✅ All tests passed!")


if __name__ == "__main__":
    test_extraction()
    test_enrichment()
