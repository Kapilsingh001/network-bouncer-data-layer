"""Flow-level reconnaissance detection (UNSW-NB15 feature/partitioned sets).

Some UNSW-NB15 exports — notably the ML training/testing partitions
(``UNSW_NB15_training-set.csv`` / ``UNSW_NB15_testing-set.csv``) — DO NOT contain
``srcip``/``dstip``/``sport``/``dsport``. The host-based detector cannot run on
those, so this module provides a fallback that detects scanning/recon at the
**flow** level using the behavioural columns these files DO have
(``service``, ``state``, byte counts, and UNSW's ``ct_*`` connection-count
features).

Each flow is scored against a small set of explainable probe indicators. When
ground-truth columns (``attack_cat`` / ``label``) are present, the result can be
validated against them.

NOTE: this is intentionally weaker than host-based detection (no host identity to
aggregate over) — but it lets the tool produce useful, validated output on files
that lack IP/port columns instead of failing.
"""

from __future__ import annotations

from dataclasses import dataclass

import pandas as pd

from src.utils.logger import get_logger

logger = get_logger(__name__)

# Per-flow verdict columns this detector appends.
FLOW_VERDICT_COLUMNS = [
    "flow_is_suspicious",
    "flow_classification",
    "flow_severity",
    "flow_score",
    "flow_reason",
]

# Connection states that indicate an incomplete / probe-like connection.
_INCOMPLETE_STATES = {"int", "req", "rst", "urn"}
_UNKNOWN_SERVICE_TOKENS = {"-", "", "nan", "none"}


@dataclass(frozen=True)
class FlowDetectionConfig:
    """Thresholds for flow-level reconnaissance detection."""

    small_bytes: int = 1000          # probes carry little data
    low_reuse: float = 2.0           # ct_dst_src_ltm: not a sustained session
    min_indicators: int = 3          # how many probe signals to flag a flow


def detect_flow_anomalies(
    df: pd.DataFrame,
    config: FlowDetectionConfig | None = None,
) -> pd.DataFrame:
    """Score each flow for recon/scan indicators and return verdict columns.

    Returns
    -------
    pandas.DataFrame
        ``df`` with :data:`FLOW_VERDICT_COLUMNS` appended.
    """
    config = config or FlowDetectionConfig()
    if df is None or df.empty:
        return df.assign(**{c: pd.Series(dtype="object") for c in FLOW_VERDICT_COLUMNS}) \
            if df is not None else pd.DataFrame(columns=FLOW_VERDICT_COLUMNS)

    n = len(df)
    indicators: list[tuple[pd.Series, str]] = []

    # 1. Connection to a port with no recognised service.
    if "service" in df.columns:
        svc = df["service"].astype(str).str.strip().str.lower()
        indicators.append((svc.isin(_UNKNOWN_SERVICE_TOKENS), "no known service"))

    # 2. Tiny payload (a probe, not a real session).
    if "sbytes" in df.columns:
        sbytes = pd.to_numeric(df["sbytes"], errors="coerce").fillna(0)
        indicators.append((sbytes < config.small_bytes, "tiny payload"))

    # 3. Low connection reuse to the same dst/src pair (UNSW ct_* feature).
    if "ct_dst_src_ltm" in df.columns:
        reuse = pd.to_numeric(df["ct_dst_src_ltm"], errors="coerce").fillna(0)
        indicators.append((reuse <= config.low_reuse, "low connection reuse"))

    # 4. Incomplete / rejected connection state.
    if "state" in df.columns:
        state = df["state"].astype(str).str.strip().str.lower()
        indicators.append((state.isin(_INCOMPLETE_STATES), "incomplete connection"))

    if not indicators:
        logger.warning("No usable flow-level indicator columns; flagging nothing.")
        return _empty_verdict(df)

    # Aggregate: score = count of triggered indicators; reason = their names.
    score = pd.Series(0, index=df.index, dtype=int)
    reason = pd.Series("", index=df.index, dtype="object")
    for mask, name in indicators:
        score = score + mask.astype(int)
        reason = reason.where(~mask, reason + (name + "; "))

    # Effective threshold: never require more indicators than are available.
    threshold = max(2, min(config.min_indicators, len(indicators)))
    flagged = score >= threshold

    out = df.copy()
    out["flow_score"] = score
    out["flow_is_suspicious"] = flagged
    out["flow_classification"] = flagged.map(
        {True: "Suspicious (Recon/Scan)", False: "Normal"}
    )
    out["flow_severity"] = score.map(_severity_for_score)
    out["flow_reason"] = reason.str.rstrip("; ")
    out.loc[~flagged, "flow_reason"] = ""

    logger.info("Flow-level detection: %d/%d flow(s) flagged", int(flagged.sum()), n)
    return out


def compute_flow_metrics(verdict_df: pd.DataFrame) -> dict:
    """Validate flow verdicts against ground-truth columns, if present."""
    if verdict_df is None or verdict_df.empty or "flow_is_suspicious" not in verdict_df:
        return {}
    pred = verdict_df["flow_is_suspicious"].astype(bool)
    metrics: dict = {}

    if "attack_cat" in verdict_df.columns:
        truth = verdict_df["attack_cat"].astype(str).str.strip().str.lower() == "reconnaissance"
        if truth.any():
            metrics["reconnaissance"] = _prf(pred, truth)

    if "label" in verdict_df.columns:
        truth = pd.to_numeric(verdict_df["label"], errors="coerce").fillna(0).astype(int) == 1
        if truth.any():
            metrics["any_attack"] = _prf(pred, truth)

    return metrics


# --------------------------------------------------------------------------- #
def _severity_for_score(score: int) -> str:
    if score >= 4:
        return "High"
    if score == 3:
        return "Medium"
    if score > 0:
        return "Low"
    return "None"


def _prf(pred: pd.Series, truth: pd.Series) -> dict:
    tp = int((pred & truth).sum())
    fp = int((pred & ~truth).sum())
    fn = int((~pred & truth).sum())
    tn = int((~pred & ~truth).sum())
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
        "n_truth": int(truth.sum()),
    }


def _empty_verdict(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    out["flow_score"] = 0
    out["flow_is_suspicious"] = False
    out["flow_classification"] = "Normal"
    out["flow_severity"] = "None"
    out["flow_reason"] = ""
    return out
