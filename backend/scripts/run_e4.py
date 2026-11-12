"""Command-line runner for the E4 Alert Generation Engine.

Demonstrates E4 processing of detection results, validation, alert building,
and simulated E3 dispatch.

Usage:
    python backend/scripts/run_e4.py
    python backend/scripts/run_e4.py --help
"""

import argparse
import json
import sys
from pathlib import Path

# Add backend directory to path
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from src.engines.e4_alert_generation import E4AlertEngine


def main() -> None:
    parser = argparse.ArgumentParser(
        description="E4: Alert Generation Engine - Wireless Network Traffic Analysis and Alerting System"
    )
    parser.add_argument(
        "--simulate-batch",
        action="store_true",
        default=True,
        help="Simulate processing a batch of sample detection results from E2",
    )
    args = parser.parse_args()

    dispatched_e3_store = []

    def simulated_e3_sink(alert_dict):
        dispatched_e3_store.append(alert_dict)
        print(f"[E3 Storage Mock] Stored Alert ID: {alert_dict['alert_id']} (Severity: {alert_dict['severity']})")

    engine = E4AlertEngine(storage_sink=simulated_e3_sink)

    sample_detection_results = [
        {
            "result_id": "det-res-001",
            "log_id": "traffic-log-101",
            "rule_id": "RULE-WIFI-DEAUTH",
            "rule_name": "Deauthentication Flood Attack Detection",
            "suspicious_activity": "Deauthentication Flood",
            "rule_match_status": True,
            "observed_value": 150,
            "threshold_value": 30,
            "severity": "HIGH",
            "detection_evidence": {"frame_count": 150, "time_window_sec": 5},
            "source_mac": "00:14:22:01:23:45",
            "destination_mac": "ff:ff:ff:ff:ff:ff",
            "protocol": "802.11_MGMT",
        },
        {
            "result_id": "det-res-002",
            "log_id": "traffic-log-102",
            "rule_id": "RULE-TCP-SYN-FLOOD",
            "rule_name": "TCP SYN Flood Anomaly",
            "suspicious_activity": "SYN Flood Denial of Service",
            "rule_match_status": True,
            "observed_value": 500,
            "threshold_value": 100,
            "severity": "CRITICAL",
            "detection_evidence": {"syn_rate_pps": 500},
            "source_address": "192.168.1.150",
            "destination_address": "10.0.0.1",
            "protocol": "TCP",
        },
        {
            "result_id": "det-res-003",
            "log_id": "traffic-log-103",
            "rule_id": "RULE-NORMAL-TRAFFIC",
            "rule_match_status": False,  # Benign
            "severity": "LOW",
        },
        {
            "result_id": "det-res-001",  # Duplicate of first
            "rule_match_status": True,
            "severity": "HIGH",
        },
    ]

    print("\n[+] E4 Alert Generation Engine - Running Sample Batch...")
    alerts, summary = engine.process_batch(sample_detection_results)

    print("\n--- Alert Generation Summary ---")
    print(json.dumps(summary.to_dict(), indent=2))

    print(f"\n--- Generated Alerts Count: {len(alerts)} ---")
    for i, a in enumerate(alerts, 1):
        print(f"\n[Alert #{i}]")
        print(json.dumps(a.to_dict(), indent=2))


if __name__ == "__main__":
    main()

