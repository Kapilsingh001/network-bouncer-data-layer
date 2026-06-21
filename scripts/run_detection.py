"""End-to-end runner: raw CSV -> cleaned data -> scan detection -> alerts.

Wires the Dev 1 data layer and the Dev 2 feature/detection layer together so the
whole project can be exercised with a single command, including on dirty data.

Stages:
    load -> validate -> clean (+ quality report) -> profile -> detect -> alerts

Usage:
    python scripts/run_detection.py sample_dirty.csv
    python scripts/run_detection.py sample_dirty.csv --alerts-out alerts.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys

# Make the project root importable when run as `python scripts/run_detection.py`.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.cleaning.cleaner import clean_data
from src.cleaning.data_quality import build_quality_report
from src.analyzer.profiler import profile_dataset
from src.detection.detector import RuleBasedDetector
from src.parser.csv_loader import load_csv, load_raw_csv
from src.parser.schema_validator import validate_schema


def main() -> None:
    parser = argparse.ArgumentParser(description="Network Bouncer end-to-end detection runner")
    parser.add_argument("csv", help="Path to the input CSV (may be dirty)")
    parser.add_argument("--alerts-out", default="alerts.json", help="Where to write JSON alerts")
    parser.add_argument(
        "--raw",
        action="store_true",
        help="Input is a headerless raw UNSW-NB15 file (UNSW-NB15_1..4.csv).",
    )
    args = parser.parse_args()

    # 1. Load + 2. Validate (fail fast on missing required columns / empty data)
    df = load_raw_csv(args.csv) if args.raw else load_csv(args.csv)
    validate_schema(df).raise_if_invalid()

    # 3. Clean (and show exactly what the dirt cost us)
    clean_df, stats = clean_data(df)
    print("\n=== DATA QUALITY (cleaning) ===")
    print(json.dumps(build_quality_report(stats), indent=2))

    # 4. Profile
    print("\n=== PROFILE (cleaned data) ===")
    profile = profile_dataset(clean_df)
    print(json.dumps({k: profile[k] for k in (
        "total_records", "unique_sources", "unique_destinations",
        "protocol_distribution",
    )}, indent=2))

    # 5. Detect
    detector = RuleBasedDetector()
    result = detector.detect_from_flows(clean_df)

    print("\n=== PER-HOST DETECTION ===")
    cols = [
        "srcip", "total_connections", "unique_destinations", "unique_dst_ports",
        "is_suspicious", "rule_hits", "suspicion_score",
    ]
    print(result[cols].to_string(index=False))

    # 6. Alerts (suspicious hosts only, with reasons + evidence)
    alerts = detector.alerts(result)
    with open(args.alerts_out, "w", encoding="utf-8") as fh:
        json.dump(alerts, fh, indent=2)

    print(f"\n=== ALERTS: {len(alerts)} suspicious host(s) -> {args.alerts_out} ===")
    for a in alerts:
        print(f"\n[{a['srcip']}] score={a['suspicion_score']} "
              f"categories={a['scan_categories']}")
        for reason in a["reasons"]:
            print(f"   - {reason}")


if __name__ == "__main__":
    main()
