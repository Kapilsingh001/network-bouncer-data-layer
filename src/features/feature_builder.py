"""Per-source-host behavioural feature engineering for Network Bouncer.

The Dev 1 :func:`src.analyzer.aggregator.build_host_features` produces the raw
*counts* per source IP. This module produces the richer **behavioural feature
matrix** the detection layer actually reasons over: not just "how many ports"
but "how *concentrated* is the port targeting", "how often is each destination
reused", "how many connections never completed".

Why ratios, not just counts?
----------------------------
Raw counts scale with traffic volume, so a busy-but-benign server looks the same
as a scanner. Ratios normalise that away and isolate the *behavioural shape* of
port scanning:

* A scanner touches each port/destination roughly **once** (low reuse).
* A scanner targets **many distinct** ports/destinations relative to its volume.
* A scanner generates many **incomplete / unknown-service** flows.

These shape features are what give the strongest, volume-independent signal.

Note on protocol handling
--------------------------
This layer treats ``proto`` purely as a high-cardinality categorical and only
*counts distinct values*. It makes NO assumption about which protocols are
"valid" — every protocol present in the cleaned data is honoured (per the team
decision for the UNSW-NB15 dataset).
"""

from __future__ import annotations

import numpy as np
import pandas as pd

from src.utils.constants import DEFAULT_ESTABLISHED_STATES
from src.utils.logger import get_logger

logger = get_logger(__name__)

# Stable, documented output schema. Detection code references these names.
FEATURE_MATRIX_COLUMNS = [
    "srcip",
    # --- raw volume / cardinality ---
    "total_connections",
    "unique_destinations",
    "unique_dst_ports",
    "unique_src_ports",
    "unique_protocols",
    "unique_services",
    # --- behavioural ratios (the strong, volume-independent signals) ---
    "ports_per_destination",   # vertical-scan intensity
    "conn_per_destination",    # connection reuse (low => sweep)
    "dst_port_ratio",          # share of flows hitting a fresh port
    "dst_ratio",               # share of flows hitting a fresh destination
    "null_service_ratio",      # probing ports with no listening service
    "incomplete_ratio",        # half-open / rejected connections
]

_OPTIONAL_COLUMNS = ("dstip", "dsport", "sport", "proto", "service", "state")


def build_host_feature_matrix(
    df: pd.DataFrame,
    established_states: frozenset | set | None = None,
) -> pd.DataFrame:
    """Build the per-source-host behavioural feature matrix.

    Parameters
    ----------
    df:
        A cleaned, row-per-flow DataFrame from the Dev 1 data layer.
    established_states:
        Connection-state tokens treated as "successfully established"; everything
        else feeds the ``incomplete_ratio``. Defaults to
        :data:`src.utils.constants.DEFAULT_ESTABLISHED_STATES`.

    Returns
    -------
    pandas.DataFrame
        One row per source IP, columns = :data:`FEATURE_MATRIX_COLUMNS`,
        sorted by ``total_connections`` descending.

    Notes
    -----
    This layer is intentionally independent of the detection package so that
    feature engineering (upstream) never depends on detection policy
    (downstream). The detector passes ``config.established_states`` through.
    """
    established_states = established_states or DEFAULT_ESTABLISHED_STATES

    if df is None or df.empty or "srcip" not in df.columns:
        logger.warning("build_host_feature_matrix received empty or srcip-less data")
        return pd.DataFrame(columns=FEATURE_MATRIX_COLUMNS)

    # Assemble a minimal working frame carrying only what we aggregate over.
    work = pd.DataFrame({"srcip": df["srcip"].to_numpy()})
    for col in _OPTIONAL_COLUMNS:
        if col in df.columns:
            work[col] = df[col].to_numpy()

    # Pre-compute per-flow boolean indicators that we will sum per host.
    if "service" in work.columns:
        work["_service_missing"] = work["service"].isna().astype(int)
    if "state" in work.columns:
        established = {s.lower() for s in established_states}
        state_norm = work["state"].astype("object").map(_lower_or_none)
        # Unknown/None state counts as NOT established (i.e. incomplete).
        work["_incomplete"] = (~state_norm.isin(established)).astype(int)

    grouped = _aggregate(work)
    features = _derive_ratios(grouped)

    # Guarantee the full advertised schema even if optional columns were absent.
    for col in FEATURE_MATRIX_COLUMNS:
        if col not in features.columns:
            features[col] = 0

    features = features[FEATURE_MATRIX_COLUMNS].sort_values(
        "total_connections", ascending=False, ignore_index=True
    )
    logger.info("Built behavioural features for %d source host(s)", len(features))
    return features


# --------------------------------------------------------------------------- #
# Internal helpers
# --------------------------------------------------------------------------- #
def _aggregate(work: pd.DataFrame) -> pd.DataFrame:
    """Group flows by source IP and compute base counts."""
    agg_spec: dict[str, tuple[str, str]] = {"total_connections": ("srcip", "size")}
    if "dstip" in work.columns:
        agg_spec["unique_destinations"] = ("dstip", "nunique")
    if "dsport" in work.columns:
        agg_spec["unique_dst_ports"] = ("dsport", "nunique")
    if "sport" in work.columns:
        agg_spec["unique_src_ports"] = ("sport", "nunique")
    if "proto" in work.columns:
        agg_spec["unique_protocols"] = ("proto", "nunique")
    if "service" in work.columns:
        agg_spec["unique_services"] = ("service", "nunique")
        agg_spec["_service_missing_sum"] = ("_service_missing", "sum")
    if "_incomplete" in work.columns:
        agg_spec["_incomplete_sum"] = ("_incomplete", "sum")

    return work.groupby("srcip", observed=True).agg(**agg_spec).reset_index()


def _derive_ratios(g: pd.DataFrame) -> pd.DataFrame:
    """Compute the volume-independent behavioural ratios."""
    # Ensure base count columns exist before deriving ratios from them.
    for col in (
        "unique_destinations",
        "unique_dst_ports",
        "unique_src_ports",
        "unique_protocols",
        "unique_services",
    ):
        if col not in g.columns:
            g[col] = 0

    total = g["total_connections"]
    # Guard division: a host always has >=1 connection and >=1 destination after
    # cleaning, but stay defensive against degenerate inputs.
    dests = g["unique_destinations"].where(g["unique_destinations"] > 0)

    g["ports_per_destination"] = _safe_ratio(g["unique_dst_ports"], dests)
    g["conn_per_destination"] = _safe_ratio(total, dests)
    g["dst_port_ratio"] = _safe_ratio(g["unique_dst_ports"], total)
    g["dst_ratio"] = _safe_ratio(g["unique_destinations"], total)

    g["null_service_ratio"] = (
        _safe_ratio(g["_service_missing_sum"], total)
        if "_service_missing_sum" in g.columns
        else 0.0
    )
    g["incomplete_ratio"] = (
        _safe_ratio(g["_incomplete_sum"], total)
        if "_incomplete_sum" in g.columns
        else 0.0
    )
    return g


def _safe_ratio(numer: pd.Series, denom) -> pd.Series:
    """Element-wise division that yields 0.0 (not NaN/inf) on a zero denominator."""
    result = numer / denom
    return result.replace([np.inf, -np.inf], np.nan).fillna(0.0).round(4)


def _lower_or_none(value):
    """Lower-case a string state token; pass through non-strings as a sentinel."""
    return value.lower() if isinstance(value, str) else None
