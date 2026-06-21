"""Report-export helpers for the dashboard (Dev 4).

Turns the enriched detection table into clean, analyst-ready CSV reports. List
and dict columns (rule reasons, anomaly indicators, z-scores) are flattened to
readable strings so the CSVs open cleanly in Excel.
"""

from __future__ import annotations

import pandas as pd

# Columns that hold Python lists/dicts and must be flattened for CSV.
_LIST_COLUMNS = (
    "triggered_rules",
    "scan_categories",
    "reasons",
    "anomaly_indicators",
    "severity_explanation",
)
_DICT_COLUMNS = ("feature_zscores",)


def flatten_for_export(df: pd.DataFrame) -> pd.DataFrame:
    """Return a copy with list/dict columns flattened to readable strings."""
    out = df.copy()
    for col in _LIST_COLUMNS:
        if col in out.columns:
            out[col] = out[col].apply(
                lambda v: " | ".join(map(str, v)) if isinstance(v, list) else ("" if v is None else v)
            )
    for col in _DICT_COLUMNS:
        if col in out.columns:
            out[col] = out[col].apply(
                lambda v: "; ".join(f"{k}={val}" for k, val in v.items())
                if isinstance(v, dict) else ("" if v is None else v)
            )
    return out


def to_csv_bytes(df: pd.DataFrame) -> bytes:
    """Encode a DataFrame as UTF-8 CSV bytes for st.download_button."""
    return flatten_for_export(df).to_csv(index=False).encode("utf-8")


def build_reports(enriched: pd.DataFrame) -> dict[str, bytes]:
    """Build the four downloadable reports as name -> CSV bytes.

    Returns
    -------
    dict
        ``detection_results``     — every host, full detail.
        ``suspicious_report``     — only rule-flagged hosts.
        ``severity_report``       — severity-focused summary.
        ``investigation_dataset`` — full enriched dataset for further analysis.
    """
    if enriched is None or enriched.empty:
        empty = pd.DataFrame()
        return {k: to_csv_bytes(empty) for k in
                ("detection_results", "suspicious_report", "severity_report", "investigation_dataset")}

    suspicious = enriched[enriched.get("is_suspicious", False) == True]  # noqa: E712

    severity_cols = [c for c in (
        "srcip", "classification", "severity_level", "severity_score",
        "suspicion_score", "outlier_score", "n_anomaly_indicators",
        "severity_explanation",
    ) if c in enriched.columns]

    return {
        "detection_results": to_csv_bytes(enriched),
        "suspicious_report": to_csv_bytes(suspicious),
        "severity_report": to_csv_bytes(enriched[severity_cols]),
        "investigation_dataset": to_csv_bytes(enriched),
    }
