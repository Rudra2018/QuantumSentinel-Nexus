#!/usr/bin/env python3
"""
Real-time Bug Bounty Scan Monitor
Monitor all active bug bounty scanning operations
"""

import time
import json
import os
import glob
from datetime import datetime

def monitor_scans():
    """Monitor bug bounty scanning progress"""
    print("🛡️ QUANTUMSENTINEL-NEXUS BUG BOUNTY SCAN MONITOR")
    print("=" * 60)

    while True:
        try:
            # Count completed scan reports
            bb_reports = glob.glob("bug_bounty_scan_BB-*.json")
            quantum_reports = glob.glob("quantum_scan_report_*.json")

            # Check if mass scan log exists
            mass_scan_log = "bug_bounty_mass_scan.log"

            current_time = datetime.now().strftime("%H:%M:%S")

            print(f"\r🔄 [{current_time}] Bug Bounty Scans - BB Reports: {len(bb_reports)} | Quantum Reports: {len(quantum_reports)}", end="")

            # Show latest activity if log exists
            if os.path.exists(mass_scan_log):
                with open(mass_scan_log, 'r') as f:
                    lines = f.readlines()
                    if lines:
                        last_line = lines[-1].strip()
                        if "completed" in last_line:
                            print(f"\n   Last: {last_line.split('INFO - ')[-1]}")

            time.sleep(5)

        except KeyboardInterrupt:
            print("\n\n🛑 Monitoring stopped")
            break
        except Exception as e:
            print(f"\n⚠️ Monitor error: {e}")
            time.sleep(5)

if __name__ == "__main__":
    monitor_scans()