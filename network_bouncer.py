#!/usr/bin/env python
"""Network Bouncer — detect suspicious port scanning in data-center traffic.

The single command-line entry point described in the problem statement::

    python network_bouncer.py network_log.csv

It wires the full pipeline together end to end:

    load -> validate -> clean -> per-host features -> rule-based detection
         -> classification (Normal / Suspicious) -> analyst report

and prints an analyst-friendly summary plus an optional CSV report.

Examples
--------
    python network_bouncer.py network_log.csv
    python network_bouncer.py UNSW-NB15_1.csv --raw
    python network_bouncer.py log.csv --report report.csv --sensitivity high
"""

from __future__ import annotations

import argparse
import sys

import pandas as pd

from src.analyzer.profiler import profile_dataset
from src.cleaning.cleaner import clean_data
from src.cleaning.data_quality import build_quality_report
from src.detection.config import DetectionConfig
from src.detection.detector import RuleBasedDetector
from src.detection.flow_detector import (
    FlowDetectionConfig,
    compute_flow_metrics,
    detect_flow_anomalies,
)
from src.parser.csv_loader import CSVLoadError, load_csv, load_raw_csv
from src.parser.format_detector import FLOW_MODE, HOST_MODE, detect_dataset_mode
from src.parser.schema_validator import SchemaValidationError, validate_schema
from src.scoring.enricher import enrich_detections

# Report column order (flat, analyst-friendly, CSV-friendly).
REPORT_COLUMNS = [
    "srcip",
    "classification",
    "severity_level",
    "severity_score",
    "total_connections",
    "unique_destinations",
    "unique_dst_ports",
    "unique_protocols",
    "suspicion_score",
    "outlier_score",
    "n_anomaly_indicators",
    "triggered_rules",
    "reasons",
    "anomaly_indicators",
]

# Preset sensitivity profiles -> DetectionConfig overrides. Mitigates the
# false-positive risk called out in the problem statement by letting the analyst
# tune how aggressive detection is.
SENSITIVITY_PRESETS = {
    "low": dict(min_connections=30, horizontal_min_destinations=50, min_rules_to_flag=2),
    "medium": dict(),  # library defaults
    "high": dict(min_connections=5, horizontal_min_destinations=10, min_rules_to_flag=1),
}

# Sensitivity -> how many probe indicators a single flow must show to be flagged
# in flow mode. Fewer indicators = more aggressive = more flags (and more false
# positives), mirroring the host-mode presets above.
FLOW_SENSITIVITY_PRESETS = {
    "low": 4,
    "medium": 3,
    "high": 2,
}

# Columns surfaced for each flagged flow in the flow-mode CSV report.
FLOW_REPORT_COLUMNS = [
    "proto", "service", "state", "sbytes", "dbytes", "ct_dst_src_ltm",
    "flow_classification", "flow_severity", "flow_score", "flow_reason",
    "attack_cat", "label",
]


def build_config(sensitivity: str) -> DetectionConfig:
    return DetectionConfig(**SENSITIVITY_PRESETS[sensitivity])


def run(args: argparse.Namespace) -> int:
    # --- Load -----------------------------------------------------------
    try:
        df = load_raw_csv(args.csv) if args.raw else load_csv(args.csv)
    except CSVLoadError as exc:
        print(f"[ERROR] Could not load CSV: {exc}", file=sys.stderr)
        return 2

    # --- Dispatch by dataset format -------------------------------------
    # The UNSW-NB15 ML partitions (training/testing-set.csv) have NO
    # srcip/dstip/sport/dsport, so host-based detection is impossible. Detect
    # that automatically and fall back to flow-level detection instead of
    # failing — one command works on both dataset shapes. A raw, headerless
    # capture loaded with --raw always has host identity, so force host mode.
    mode = HOST_MODE if args.raw else detect_dataset_mode(df)
    if mode == FLOW_MODE:
        print("[INFO] No source/destination host columns found "
              "(UNSW-NB15 feature set). Using flow-level detection.\n")
        return _run_flow_mode(df, args)

    # --- Validate -------------------------------------------------------
    try:
        validate_schema(df).raise_if_invalid()
    except SchemaValidationError as exc:
        print(f"[ERROR] Schema validation failed: {exc}", file=sys.stderr)
        if not args.raw:
            print("        If this is a raw, headerless UNSW-NB15 file, re-run with --raw.",
                  file=sys.stderr)
        return 3

    # --- Clean ----------------------------------------------------------
    clean_df, stats = clean_data(df)
    quality = build_quality_report(stats)
    profile = profile_dataset(clean_df)

    # --- Detect (Dev 2) -------------------------------------------------
    detector = RuleBasedDetector(config=build_config(args.sensitivity))
    result = detector.detect_from_flows(clean_df)

    # --- Enrich: statistical anomaly + severity (Dev 3) -----------------
    result = enrich_detections(result)

    # "Of interest" = rule-flagged OR a statistical outlier, so we also surface
    # anomalous hosts the rules alone did not catch.
    if result.empty:
        flagged = result
    else:
        flagged = result[(result["is_suspicious"]) | (result["severity_level"] != "None")]

    # --- Report ---------------------------------------------------------
    _print_summary(args.csv, quality, profile, result, flagged)
    _print_flagged_hosts(flagged)

    if args.report:
        _write_report(result if args.all else flagged, args.report)
        scope = "all hosts" if args.all else "flagged hosts"
        print(f"\nReport ({scope}) written to: {args.report}")

    return 0


def _run_flow_mode(df: pd.DataFrame, args: argparse.Namespace) -> int:
    """Flow-level detection path for UNSW-NB15 feature sets (no host identity).

    These files have no source IP to aggregate over, so we score each *flow* for
    probe/recon indicators (unknown service, tiny payload, low connection reuse,
    incomplete state) and validate against the ground-truth ``attack_cat`` /
    ``label`` columns when they are present.
    """
    config = FlowDetectionConfig(min_indicators=FLOW_SENSITIVITY_PRESETS[args.sensitivity])
    verdict = detect_flow_anomalies(df, config)

    flagged_mask = verdict["flow_is_suspicious"].astype(bool)
    n_total = len(verdict)
    n_flagged = int(flagged_mask.sum())

    print("=" * 60)
    print("  NETWORK BOUNCER - Flow-Level Detection Report")
    print("=" * 60)
    print(f"Input file          : {args.csv}")
    print(f"Detection mode      : flow-level (no host identity in this file)")
    print(f"Sensitivity         : {args.sensitivity}")
    print(f"Flows analysed      : {n_total:,}")
    print(f"Flagged suspicious  : {n_flagged:,}")
    print(f"Classified normal   : {n_total - n_flagged:,}")
    if n_flagged:
        sev = verdict.loc[flagged_mask, "flow_severity"].value_counts()
        tiers = "  ".join(f"{lvl}={int(sev.get(lvl, 0))}" for lvl in ("High", "Medium", "Low"))
        print(f"Severity breakdown  : {tiers}")
    print("=" * 60)

    # Ground-truth validation (only if the file carries labels).
    metrics = compute_flow_metrics(verdict)
    if metrics:
        print("\nGround-truth validation:")
        for target, m in metrics.items():
            print(f"  vs {target}: precision={m['precision']}  recall={m['recall']}  "
                  f"f1={m['f1']}  (TP={m['tp']} FP={m['fp']} FN={m['fn']} TN={m['tn']})")

    # Show a sample of the strongest flagged flows so the analyst sees evidence.
    if n_flagged:
        print("\nTop suspicious flows (by indicator count):\n")
        top = verdict[flagged_mask].sort_values("flow_score", ascending=False).head(10)
        for _, row in top.iterrows():
            truth = f" [actual: {row['attack_cat']}]" if "attack_cat" in top.columns else ""
            print(f"  proto={row.get('proto', '?')} service={row.get('service', '?')} "
                  f"state={row.get('state', '?')} | {row['flow_severity']} "
                  f"(score {int(row['flow_score'])}){truth}")
            print(f"     reason: {row['flow_reason']}")
    else:
        print("\nNo suspicious flows detected. All traffic classified Normal.")

    if args.report:
        out = verdict if args.all else verdict[flagged_mask]
        cols = [c for c in FLOW_REPORT_COLUMNS if c in out.columns]
        out[cols].to_csv(args.report, index=False)
        scope = "all flows" if args.all else "flagged flows"
        print(f"\nReport ({scope}) written to: {args.report}")

    return 0


def _print_summary(path, quality, profile, result, flagged) -> None:
    print("=" * 60)
    print("  NETWORK BOUNCER - Port-Scan Detection Report")
    print("=" * 60)
    print(f"Input file          : {path}")
    print(f"Flows analysed      : {quality['final_dataset_size']:,} "
          f"(removed {quality['total_rows_removed']:,} dirty rows)")
    print(f"Source hosts        : {profile['unique_sources']:,}")
    print(f"Destinations        : {profile['unique_destinations']:,}")
    print(f"Flagged hosts       : {len(flagged)} of {len(result)}")
    if not result.empty and "severity_level" in result.columns:
        counts = result["severity_level"].value_counts()
        tiers = "  ".join(
            f"{lvl}={int(counts.get(lvl, 0))}"
            for lvl in ("Critical", "High", "Medium", "Low")
        )
        print(f"Severity breakdown  : {tiers}")
    print("=" * 60)


def _print_flagged_hosts(flagged: pd.DataFrame) -> None:
    if flagged.empty:
        print("\nNo suspicious or anomalous activity detected. All hosts Normal.")
        return

    print("\nSuspicious Activity Detected:\n")
    for _, row in flagged.iterrows():
        print(f"Source IP          : {row['srcip']}")
        print(f"Connections        : {int(row['total_connections'])}")
        print(f"Unique Destinations: {int(row['unique_destinations'])}")
        print(f"Unique Ports       : {int(row['unique_dst_ports'])}")
        print(f"Detection Status   : {row['classification']}")
        print(f"Severity Level     : {row['severity_level']} "
              f"(score {row['severity_score']}/100)")
        # Detection reasons (rules) + statistical indicators.
        if isinstance(row.get("reasons"), list) and row["reasons"]:
            print("Detection Reasons  :")
            for reason in row["reasons"]:
                print(f"   - {reason}")
        if isinstance(row.get("anomaly_indicators"), list) and row["anomaly_indicators"]:
            print("Statistical Outlier:")
            for ind in row["anomaly_indicators"]:
                print(f"   - {ind}")
        print("-" * 60)


def _write_report(frame: pd.DataFrame, path: str) -> None:
    out = frame.copy()
    if out.empty:
        out = pd.DataFrame(columns=REPORT_COLUMNS)
    else:
        # Flatten list columns so the CSV is human-readable.
        for col in ("triggered_rules", "reasons", "anomaly_indicators"):
            if col in out.columns:
                out[col] = out[col].apply(lambda v: " | ".join(v) if isinstance(v, list) else v)
    cols = [c for c in REPORT_COLUMNS if c in out.columns]
    out[cols].to_csv(path, index=False)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Detect suspicious port scanning in network traffic logs (UNSW-NB15)."
    )
    parser.add_argument("csv", help="Path to the network traffic CSV log.")
    parser.add_argument("--raw", action="store_true",
                        help="Input is a headerless raw UNSW-NB15 file (UNSW-NB15_1..4.csv).")
    parser.add_argument("--report", metavar="PATH",
                        help="Write a CSV report to PATH.")
    parser.add_argument("--all", action="store_true",
                        help="Include all hosts (not just suspicious) in the CSV report.")
    parser.add_argument("--sensitivity", choices=("low", "medium", "high"), default="medium",
                        help="Detection sensitivity preset (default: medium).")
    args = parser.parse_args()
    sys.exit(run(args))


if __name__ == "__main__":
    main()
