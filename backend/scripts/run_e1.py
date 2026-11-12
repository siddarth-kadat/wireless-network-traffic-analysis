"""Command-line runner for the E1 Log Processing Engine.

Usage:
    python backend/scripts/run_e1.py path/to/capture.pcap [path/to/capture2.pcap ...]
    python backend/scripts/run_e1.py --help
"""

import argparse
import json
import sys
from pathlib import Path

# Add backend directory to path
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from src.engines.e1_log_processing import E1ProcessingPipeline


def main() -> None:
    parser = argparse.ArgumentParser(
        description="E1: Log Processing Engine - Wireless Network Traffic Analysis and Alerting System"
    )
    parser.add_argument(
        "pcaps",
        nargs="+",
        help="One or more PCAP or PCAPNG capture file paths to process",
    )
    parser.add_argument(
        "--workers",
        "-w",
        type=int,
        default=4,
        help="Number of concurrent workers (default: 4)",
    )
    parser.add_argument(
        "--user-id",
        "-u",
        type=str,
        default="cli-user",
        help="Submitting user identifier for batch attribution",
    )
    parser.add_argument(
        "--sample",
        action="store_true",
        help="Print a sample formatted record matching Traffic_Log entity schema",
    )

    args = parser.parse_args()

    pipeline = E1ProcessingPipeline(max_workers=args.workers)

    if len(args.pcaps) == 1:
        print(f"\n[+] Ingesting and processing single capture: {args.pcaps[0]}")
        det_out, stor_out = pipeline.process_file(args.pcaps[0], user_id=args.user_id)
        summary = det_out.summary.to_dict()
        print("\n--- Processing Summary ---")
        print(json.dumps(summary, indent=2))

        if args.sample and det_out.records:
            print("\n--- Sample Processed Record (Traffic_Log Entity Format) ---")
            print(json.dumps(det_out.records[0].to_dict(), indent=2))

    else:
        print(f"\n[+] Ingesting and processing {len(args.pcaps)} captures concurrently with {args.workers} workers...")
        results = pipeline.process_multiple_files(args.pcaps, user_id=args.user_id)
        print("\n--- Batch Processing Summaries ---")
        for det_out, _ in results:
            print(f"\nFile: {det_out.summary.file_name}")
            print(json.dumps(det_out.summary.to_dict(), indent=2))


if __name__ == "__main__":
    main()

