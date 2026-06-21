"""Flow-level reconnaissance detection for the UNSW-NB15 *partitioned* set.

WHY THIS SCRIPT EXISTS
----------------------
The UNSW-NB15 training/testing partition (UNSW_NB15_testing-set.csv) has NO
srcip/dstip/sport/dsport — the host identities and ports were stripped for ML.
Our main, host-based detector (`network_bouncer.py`) therefore cannot run on it.

This script is an honest *adapter*: it runs RULE-BASED detection at the
FLOW level using the behavioural columns this file DOES have
(service, state, byte counts, and UNSW's connection-count `ct_*` features),
then VALIDATES the result against the ground-truth `attack_cat` / `label`.

DELIBERATE CHOICE — the `sttl` artifact is excluded
---------------------------------------------------
In UNSW-NB15, attack flows were generated from hosts with sttl ~254 while normal
traffic sits ~31/62. That makes `sttl` a near-perfect giveaway — but it is a
*capture artifact*, not real scanning behaviour, so a rule using it would NOT
generalise to a real data center. We exclude it on purpose and rely only on
behaviourally-meaningful signals. (Run with --use-ttl to see how much the
artifact would inflate the score.)

Usage:
    python scripts/detect_testing_set.py "C:/path/UNSW_NB15_testing-set.csv"
    python scripts/detect_testing_set.py file.csv --report flagged.csv --use-ttl
"""

from __future__ import annotations

import argparse
import sys

import pandas as pd


def detect(df: pd.DataFrame, use_ttl: bool) -> pd.DataFrame:
    """Apply explainable flow-level reconnaissance rules.

    A flow is flagged as recon-like when it shows the probe fingerprint:
    a connection to a port with **no recognised service**, carrying **little
    data** (a probe, not a session), with **low connection reuse** to that
    destination/source pair in the recent window.
    """
    svc = df["service"].astype(str).str.strip().str.lower()
    unknown_service = svc.isin(["-", "", "nan", "none"])
    small_payload = df["sbytes"].astype(float) < 1000          # probes are tiny
    low_reuse = df["ct_dst_src_ltm"].astype(float) <= 2         # not a sustained session

    flagged = unknown_service & small_payload & low_reuse

    # Optional, NON-generalisable artifact rule (off by default).
    if use_ttl and "sttl" in df.columns:
        flagged = flagged & (df["sttl"].astype(float) >= 200)

    out = pd.DataFrame(index=df.index)
    out["is_suspicious"] = flagged
    out["classification"] = out["is_suspicious"].map(
        {True: "Suspicious (Backdoor/Analysis)", False: "Normal"}
    )
    # Human-readable reason per flagged flow.
    reasons = []
    for u, s, r, f in zip(unknown_service, small_payload, low_reuse, flagged):
        if not f:
            reasons.append("")
            continue
        parts = []
        if u:
            parts.append("no known service")
        if s:
            parts.append("tiny payload (<1000B)")
        if r:
            parts.append("low connection reuse")
        reasons.append("; ".join(parts))
    out["reason"] = reasons
    return out


def validate(df: pd.DataFrame, verdict: pd.DataFrame) -> None:
    """Score the rules against the ground-truth labels in the file."""
    flagged = verdict["is_suspicious"]

    # Target 1: the Reconnaissance attack category specifically.
    recon = df["attack_cat"].astype(str).str.strip() == "Reconnaissance"
    _print_metrics("vs attack_cat == 'Reconnaissance'", flagged, recon)

    # Target 2: any malicious flow (binary label).
    if "label" in df.columns:
        attack = df["label"].astype(int) == 1
        _print_metrics("vs label == 1 (any attack)", flagged, attack)


def _print_metrics(title: str, pred: pd.Series, truth: pd.Series) -> None:
    tp = int((pred & truth).sum())
    fp = int((pred & ~truth).sum())
    fn = int((~pred & truth).sum())
    tn = int((~pred & ~truth).sum())
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    print(f"\n  {title}")
    print(f"    TP={tp:,}  FP={fp:,}  FN={fn:,}  TN={tn:,}")
    print(f"    Precision={prec:.2f}  Recall={rec:.2f}  F1={f1:.2f}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Flow-level recon detection on UNSW-NB15 testing set")
    parser.add_argument("csv", help="Path to UNSW_NB15_testing-set.csv")
    parser.add_argument("--report", metavar="PATH", help="Write flagged flows to a CSV")
    parser.add_argument("--use-ttl", action="store_true",
                        help="Also require sttl>=200 (the non-generalisable capture artifact).")
    args = parser.parse_args()

    df = pd.read_csv(args.csv, encoding="utf-8-sig")
    required = {"service", "state", "sbytes", "ct_dst_src_ltm", "attack_cat"}
    missing = required - set(df.columns)
    if missing:
        print(f"[ERROR] File is missing expected columns: {sorted(missing)}", file=sys.stderr)
        sys.exit(2)

    verdict = detect(df, args.use_ttl)
    n_flag = int(verdict["is_suspicious"].sum())

    print("=" * 60)
    print("  FLOW-LEVEL RECONNAISSANCE DETECTION (UNSW-NB15 testing set)")
    print("=" * 60)
    print(f"Total flows        : {len(df):,}")
    print(f"Flagged suspicious : {n_flag:,}")
    print(f"Classified normal  : {len(df) - n_flag:,}")
    print(f"TTL artifact used  : {args.use_ttl}")
    print("-" * 60)
    print("GROUND-TRUTH VALIDATION:")
    validate(df, verdict)

    if args.report:
        flagged_df = pd.concat([df, verdict], axis=1)
        flagged_df = flagged_df[flagged_df["is_suspicious"]]
        cols = ["proto", "service", "state", "sbytes", "dbytes",
                "ct_dst_src_ltm", "attack_cat", "label", "classification", "reason"]
        flagged_df[cols].to_csv(args.report, index=False)
        print(f"\nFlagged flows written to: {args.report}")

    print("\nNOTE: flow-level detection is inherently weaker than the host-based")
    print("detector in network_bouncer.py, because this file has no source-host")
    print("identity to aggregate scanning behaviour over. For strong detection,")
    print("use a raw UNSW-NB15_1..4.csv file (has srcip/dstip/ports) with --raw.")


if __name__ == "__main__":
    main()
