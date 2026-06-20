"""Data cleaning for the Network Bouncer data layer.

Transforms a structurally-valid-but-dirty DataFrame into a trustworthy dataset
that downstream scan-detection can rely on. Every step is *counted* so the
data-quality report can explain exactly what was removed and why.

Cleaning pipeline (order matters)
---------------------------------
1. Normalise sentinel null tokens ("-", "na", "?" ...) to real NaN.
2. Drop rows with null source IP.
3. Drop rows with null destination IP.
4. Coerce ports to integers; drop rows with null ports.
5. Drop rows with out-of-range ports (not in 1..65535).
6. Drop rows with invalid/unknown protocol values.
7. Drop exact duplicate rows.

Why drop instead of impute?
---------------------------
For *security* analytics, a fabricated value is worse than a missing one. We
cannot invent a plausible source IP or port for a port-scan detector — doing so
would manufacture or hide attack signal. Every removal below is therefore a
deliberate, auditable drop, and the counts are surfaced in the quality report.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

import numpy as np
import pandas as pd

from src.utils.constants import (
    MAX_PORT,
    MIN_PORT,
    NULL_TOKENS,
    PORT_COLUMNS,
    VALID_PROTOCOLS,
)
from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class CleaningStats:
    """Row-level accounting for every cleaning step.

    These counts feed directly into ``quality_report.json`` so the team can see
    the provenance of the final dataset at a glance.
    """

    initial_rows: int = 0
    null_srcip_removed: int = 0
    null_dstip_removed: int = 0
    null_port_removed: int = 0
    invalid_port_removed: int = 0
    invalid_proto_removed: int = 0
    duplicate_removed: int = 0
    final_rows: int = 0

    @property
    def total_removed(self) -> int:
        return self.initial_rows - self.final_rows

    def to_dict(self) -> dict:
        data = asdict(self)
        data["total_removed"] = self.total_removed
        return data


def clean_data(df: pd.DataFrame) -> tuple[pd.DataFrame, CleaningStats]:
    """Clean a network-flow DataFrame and return it with cleaning statistics.

    Parameters
    ----------
    df:
        A DataFrame that has already passed schema validation.

    Returns
    -------
    (pandas.DataFrame, CleaningStats)
        The cleaned dataset and a structured record of what was removed.
    """
    stats = CleaningStats(initial_rows=len(df))
    logger.info("Cleaning started: %d rows", stats.initial_rows)

    # Work on a copy so the caller's DataFrame is never mutated in place.
    df = df.copy()

    # --- Step 0: normalise sentinel null tokens to real NaN -----------------
    # Network captures encode "missing" in many ways ("-", "na", "?"). Unifying
    # them to NaN means the null checks below catch every variant.
    df = _normalise_null_tokens(df)

    # --- Step 1: null source IP --------------------------------------------
    # WHY: a flow with no source cannot be attributed to a scanning host, which
    # is the single most important entity for detection. IMPACT: rows are
    # unusable for per-source aggregation, so they are dropped.
    if "srcip" in df.columns:
        before = len(df)
        df = df[df["srcip"].notna()]
        stats.null_srcip_removed = before - len(df)

    # --- Step 2: null destination IP ---------------------------------------
    # WHY: port scanning is defined by one source touching many destinations;
    # a null destination destroys the unique_destinations signal. IMPACT: drop.
    if "dstip" in df.columns:
        before = len(df)
        df = df[df["dstip"].notna()]
        stats.null_dstip_removed = before - len(df)

    # --- Step 3 & 4: coerce + null ports -----------------------------------
    # WHY: ports must be integers to be range-checked and counted. Non-numeric
    # or missing ports cannot be reasoned about. IMPACT: coerce, then drop nulls.
    df, null_ports = _coerce_ports(df)
    stats.null_port_removed = null_ports

    # --- Step 5: invalid port ranges ---------------------------------------
    # WHY: only 1..65535 are valid TCP/UDP ports; values outside that are
    # corruption or sentinels (port 0). IMPACT: keep the data-center port space
    # honest so per-port counts are meaningful.
    before = len(df)
    df = _filter_port_ranges(df)
    stats.invalid_port_removed = before - len(df)

    # --- Step 6: invalid protocol values -----------------------------------
    # WHY: an unrecognised protocol token signals a corrupt row and pollutes
    # protocol distribution. IMPACT: drop rows whose proto is not a known token.
    if "proto" in df.columns:
        before = len(df)
        df = _filter_protocols(df)
        stats.invalid_proto_removed = before - len(df)

    # --- Step 7: duplicate rows --------------------------------------------
    # WHY: exact duplicates inflate connection counts and fabricate scan
    # intensity that did not occur. IMPACT: de-duplicate to keep counts honest.
    before = len(df)
    df = df.drop_duplicates(ignore_index=True)
    stats.duplicate_removed = before - len(df)

    df = df.reset_index(drop=True)
    stats.final_rows = len(df)

    logger.info(
        "Cleaning done: %d -> %d rows (removed %d)",
        stats.initial_rows,
        stats.final_rows,
        stats.total_removed,
    )
    return df, stats


# --------------------------------------------------------------------------- #
# Internal helpers
# --------------------------------------------------------------------------- #
def _normalise_null_tokens(df: pd.DataFrame) -> pd.DataFrame:
    """Replace common 'missing' sentinel strings with real NaN.

    Applied element-wise and type-aware: only *string* cells are stripped and
    tested against the null-token set. Numeric cells in mixed-type ``object``
    columns (e.g. a ``sport`` column holding both ``1024`` and ``"-"``) are left
    untouched, so legitimate integers are never accidentally nulled.
    """
    obj_cols = df.select_dtypes(include=["object", "category"]).columns
    for col in obj_cols:
        # Categoricals must be converted before per-element edits.
        if isinstance(df[col].dtype, pd.CategoricalDtype):
            df[col] = df[col].astype("object")
        df[col] = df[col].map(_normalise_cell)
    return df


def _normalise_cell(value):
    """Strip a string cell and map null-token strings to NaN; pass others through."""
    if isinstance(value, str):
        stripped = value.strip()
        return np.nan if stripped.lower() in NULL_TOKENS else stripped
    return value


def _coerce_ports(df: pd.DataFrame) -> tuple[pd.DataFrame, int]:
    """Coerce port columns to nullable integers and drop rows with null ports.

    Supports both decimal ("80") and hex ("0x50") encodings, the latter of
    which appears in some capture exports.
    """
    before = len(df)
    for col in PORT_COLUMNS:
        if col in df.columns:
            df[col] = df[col].apply(_parse_port).astype("Int64")

    present_ports = [c for c in PORT_COLUMNS if c in df.columns]
    if present_ports:
        df = df.dropna(subset=present_ports)
    return df, before - len(df)


def _parse_port(value) -> float:
    """Parse a single port value supporting decimal and hex; NaN on failure."""
    if pd.isna(value):
        return np.nan
    if isinstance(value, (int, np.integer)):
        return int(value)
    if isinstance(value, float):
        return value
    text = str(value).strip()
    try:
        if text.lower().startswith("0x"):
            return int(text, 16)
        return int(text)
    except (ValueError, TypeError):
        return np.nan


def _filter_port_ranges(df: pd.DataFrame) -> pd.DataFrame:
    """Keep only rows whose ports fall within the valid 1..65535 range."""
    mask = pd.Series(True, index=df.index)
    for col in PORT_COLUMNS:
        if col in df.columns:
            mask &= df[col].between(MIN_PORT, MAX_PORT)
    return df[mask]


def _filter_protocols(df: pd.DataFrame) -> pd.DataFrame:
    """Keep only rows with a recognised protocol token (case-insensitive)."""
    proto = df["proto"].astype("object").str.strip().str.lower()
    return df[proto.isin(VALID_PROTOCOLS)]
