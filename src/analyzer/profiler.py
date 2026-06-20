"""Dataset profiling for the Network Bouncer data layer.

Produces a compact JSON summary of a (cleaned) dataset: volumes, cardinalities
and distributions. This is the at-a-glance health check the dashboard and the
detection team use to sanity-check an upload before deeper analysis.
"""

from __future__ import annotations

import json

import pandas as pd

from src.utils.logger import get_logger

logger = get_logger(__name__)


def profile_dataset(df: pd.DataFrame, *, top_n: int = 10) -> dict:
    """Generate a profiling summary of the dataset.

    Parameters
    ----------
    df:
        The dataset to profile (typically the cleaned DataFrame).
    top_n:
        How many of the most frequent service values to include in the
        service distribution (services are high-cardinality; protocols are not
        and are reported in full).

    Returns
    -------
    dict
        JSON-serialisable profile, e.g.::

            {
                "total_records": 50000,
                "unique_sources": 400,
                "unique_destinations": 800,
                ...
            }
    """
    if df is None or df.empty:
        logger.warning("Profiling an empty dataset")
        return _empty_profile()

    profile = {
        "total_records": int(len(df)),
        "unique_sources": _nunique(df, "srcip"),
        "unique_destinations": _nunique(df, "dstip"),
        "unique_source_ports": _nunique(df, "sport"),
        "unique_destination_ports": _nunique(df, "dsport"),
        "protocol_distribution": _distribution(df, "proto"),
        "service_distribution": _distribution(df, "service", top_n=top_n),
        "state_distribution": _distribution(df, "state", top_n=top_n),
        "label_distribution": _distribution(df, "label"),
        "missing_value_stats": _missing_stats(df),
    }
    logger.info("Profiled %d records", profile["total_records"])
    return profile


def profile_to_json(df: pd.DataFrame, *, indent: int = 2, **kwargs) -> str:
    """Return the profile as a JSON string."""
    return json.dumps(profile_dataset(df, **kwargs), indent=indent)


# --------------------------------------------------------------------------- #
# Internal helpers
# --------------------------------------------------------------------------- #
def _nunique(df: pd.DataFrame, col: str) -> int:
    return int(df[col].nunique(dropna=True)) if col in df.columns else 0


def _distribution(df: pd.DataFrame, col: str, *, top_n: int | None = None) -> dict:
    """Return a value -> count mapping, optionally limited to the top N."""
    if col not in df.columns:
        return {}
    counts = df[col].value_counts(dropna=True)
    if top_n is not None:
        counts = counts.head(top_n)
    return {str(k): int(v) for k, v in counts.items()}


def _missing_stats(df: pd.DataFrame) -> dict:
    """Per-column count and percentage of missing values."""
    total = len(df)
    stats = {}
    for col in df.columns:
        missing = int(df[col].isna().sum())
        stats[col] = {
            "missing": missing,
            "missing_pct": round(missing / total * 100, 2) if total else 0.0,
        }
    return stats


def _empty_profile() -> dict:
    return {
        "total_records": 0,
        "unique_sources": 0,
        "unique_destinations": 0,
        "unique_source_ports": 0,
        "unique_destination_ports": 0,
        "protocol_distribution": {},
        "service_distribution": {},
        "state_distribution": {},
        "label_distribution": {},
        "missing_value_stats": {},
    }
