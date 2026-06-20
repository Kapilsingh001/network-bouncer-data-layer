"""Per-source-host feature aggregation for the Network Bouncer data layer.

This is the hand-off point to the detection team. ``build_host_features``
collapses the row-per-flow dataset into a row-per-source-IP feature table that
the scan detector consumes directly. Port scanning is fundamentally a
per-source behaviour (one host probing many destinations/ports), so the source
IP is the natural aggregation key.
"""

from __future__ import annotations

import pandas as pd

from src.utils.logger import get_logger

logger = get_logger(__name__)

# Output column order is fixed so downstream consumers can rely on it.
FEATURE_COLUMNS = [
    "srcip",
    "total_connections",
    "unique_destinations",
    "unique_ports",
    "unique_protocols",
    "unique_services",
]


def build_host_features(df: pd.DataFrame) -> pd.DataFrame:
    """Aggregate flows into one feature row per source IP.

    Parameters
    ----------
    df:
        A cleaned network-flow DataFrame.

    Returns
    -------
    pandas.DataFrame
        One row per ``srcip`` with the following columns:

        * ``total_connections``  — number of flows originating from the host.
        * ``unique_destinations``— distinct destination IPs contacted.
        * ``unique_ports``       — distinct destination ports targeted.
        * ``unique_protocols``   — distinct protocols used.
        * ``unique_services``    — distinct services touched.

        High ``unique_ports`` / ``unique_destinations`` relative to
        ``total_connections`` is the classic port-scan fingerprint the
        detection layer keys on.
    """
    if df is None or df.empty or "srcip" not in df.columns:
        logger.warning("build_host_features received empty or srcip-less data")
        return pd.DataFrame(columns=FEATURE_COLUMNS)

    # Build the aggregation spec dynamically so the function still works if an
    # optional column (e.g. service) is absent from a particular upload.
    agg_spec: dict[str, tuple[str, str]] = {
        "total_connections": ("srcip", "size"),
    }
    if "dstip" in df.columns:
        agg_spec["unique_destinations"] = ("dstip", "nunique")
    if "dsport" in df.columns:
        agg_spec["unique_ports"] = ("dsport", "nunique")
    if "proto" in df.columns:
        agg_spec["unique_protocols"] = ("proto", "nunique")
    if "service" in df.columns:
        agg_spec["unique_services"] = ("service", "nunique")

    # observed=True avoids exploding memory on categorical group keys.
    features = (
        df.groupby("srcip", observed=True)
        .agg(**agg_spec)
        .reset_index()
    )

    # Guarantee every advertised column exists (fill missing optionals with 0).
    for col in FEATURE_COLUMNS:
        if col not in features.columns:
            features[col] = 0

    features = features[FEATURE_COLUMNS].sort_values(
        "total_connections", ascending=False, ignore_index=True
    )

    logger.info("Built host features for %d source IP(s)", len(features))
    return features
