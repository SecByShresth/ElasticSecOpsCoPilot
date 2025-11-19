#!/usr/bin/env python3
"""Simulate security events for testing."""

import subprocess
import time
from datetime import datetime


def simulate_suspicious_process():
    """Simulate suspicious process execution."""
    print("🔴 Simulating: Suspicious PowerShell execution")
    # This will be detected by Elastic Endpoint
    subprocess.run([
        "powershell.exe",
        "-Command",
        "Get-Process | Select Name, Id"
    ])
    time.sleep(2)


def simulate_file_access():
    """Simulate suspicious file access."""
    print("🔴 Simulating: System file access")
    # Access to sensitive files will trigger alerts
    try:
        with open("C:\\Windows\\System32\\config\\sam", "r") as f:
            pass
    except:
        pass
    time.sleep(2)


def simulate_network_activity():
    """Simulate network activity."""
    print("🔴 Simulating: Suspicious network connection")
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect(("suspicious-domain.com", 443))
    except:
        pass
    time.sleep(2)


if __name__ == "__main__":
    print("⚠️  SECURITY EVENT SIMULATOR")
    print("This will trigger Elastic Endpoint alerts\n")

    for i in range(3):
        print(f"\n--- Simulation Round {i + 1} ---")
        simulate_suspicious_process()
        simulate_file_access()
        simulate_network_activity()

    print("\n✅ Simulations complete. Check Elastic for alerts in 1-2 minutes.")