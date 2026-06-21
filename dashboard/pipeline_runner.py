"""End-to-end pipeline orchestration for the dashboard (Dev 4).

Auto-detects the uploaded file's schema and routes it to the right analysis:

* **host mode** — file has srcip/dstip/sport/dsport -> full Dev 1->2->3
  host-based port-scan detection.
* **flow mode** — file is a UNSW-NB15 feature/partitioned set (no host/port
  columns, but has proto/service/state/ct_* ) -> flow-level reconnaissance
  detection, validated against attack_cat/label when present.

All failure modes are caught and returned as a structured result so the
dashboard never shows a raw traceback.
"""

from __future__ import annotations

import io
from dataclasses import dataclass, field

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
from src.parser.schema_validator import validate_schema
from src.scoring.enricher import enrich_detections
from src.utils.constants import UNSW_RAW_COLUMNS

SENSITIVITY_PRESETS: dict[str, dict] = {
    "Low (fewer alerts)": dict(min_connections=30, horizontal_min_destinations=50, min_rules_to_flag=2),
    "Medium (balanced)": dict(),
    "High (more alerts)": dict(min_connections=5, horizontal_min_destinations=10, min_rules_to_flag=1),
}
DEFAULT_SENSITIVITY = "Medium (balanced)"

# Flow-mode equivalent: how many probe indicators a single flow must show to be
# flagged. Lower = more aggressive = more flags. Keeps the sensitivity slider
# meaningful for feature-set files (which have no host identity to aggregate).
FLOW_SENSITIVITY_INDICATORS: dict[str, int] = {
    "Low (fewer alerts)": 4,
    "Medium (balanced)": 3,
    "High (more alerts)": 2,
}

# Column sets used for schema auto-detection.
_HOST_COLUMNS = {"srcip", "dstip", "sport", "dsport"}
_FLOW_SIGNAL_COLUMNS = {"sbytes", "ct_dst_src_ltm", "attack_cat", "ct_srv_src", "rate"}


@dataclass
class AnalysisResult:
    """Everything the dashboard needs from one pipeline run."""

    ok: bool
    mode: str = "host"               # "host" | "flow"
    error: str | None = None
    warnings: list[str] = field(default_factory=list)
    raw_rows: int = 0
    # Host-mode artifacts.
    clean_df: pd.DataFrame = field(default_factory=pd.DataFrame)
    quality: dict = field(default_factory=dict)
    profile: dict = field(default_factory=dict)
    enriched: pd.DataFrame = field(default_factory=pd.DataFrame)
    # Flow-mode artifacts.
    flow_df: pd.DataFrame = field(default_factory=pd.DataFrame)
    flow_metrics: dict = field(default_factory=dict)
    flagged_flows: int = 0


def _detection_config(sensitivity: str) -> DetectionConfig:
    return DetectionConfig(**SENSITIVITY_PRESETS.get(sensitivity, {}))


def detect_schema(df: pd.DataFrame) -> str:
    """Classify a DataFrame as 'host', 'flow', or 'unknown'."""
    if df is None or df.shape[1] == 0:
        return "unknown"
    cols = {str(c).strip().lower() for c in df.columns}
    if _HOST_COLUMNS.issubset(cols):
        return "host"
    has_behaviour = "proto" in cols and ("state" in cols or "service" in cols)
    if has_behaviour and (_FLOW_SIGNAL_COLUMNS & cols):
        return "flow"
    return "unknown"


# --------------------------------------------------------------------------- #
# Host-based pipeline (Dev 1 -> 2 -> 3)
# --------------------------------------------------------------------------- #
def run_full_pipeline(df: pd.DataFrame, sensitivity: str = DEFAULT_SENSITIVITY) -> AnalysisResult:
    """Run cleaning -> detection -> scoring on a host-schema DataFrame."""
    validation = validate_schema(df)
    if not validation.is_valid:
        return AnalysisResult(ok=False, error="; ".join(validation.errors),
                              warnings=validation.warnings, raw_rows=len(df))
    try:
        clean_df, stats = clean_data(df)
        quality = build_quality_report(stats)
        profile = profile_dataset(clean_df)
        detector = RuleBasedDetector(config=_detection_config(sensitivity))
        detection = detector.detect_from_flows(clean_df)
        enriched = enrich_detections(detection)
        enriched = _attach_top_protocol(enriched, clean_df)
    except Exception as exc:  # noqa: BLE001
        return AnalysisResult(ok=False, error=f"Analysis failed: {exc}",
                              warnings=validation.warnings, raw_rows=len(df))

    return AnalysisResult(ok=True, mode="host", warnings=validation.warnings,
                          raw_rows=len(df), clean_df=clean_df, quality=quality,
                          profile=profile, enriched=enriched)


# --------------------------------------------------------------------------- #
# Flow-level pipeline (files without host/port columns)
# --------------------------------------------------------------------------- #
def run_flow_pipeline(df: pd.DataFrame, sensitivity: str = DEFAULT_SENSITIVITY) -> AnalysisResult:
    """Run flow-level reconnaissance detection on a feature-set DataFrame."""
    try:
        config = FlowDetectionConfig(
            min_indicators=FLOW_SENSITIVITY_INDICATORS.get(sensitivity, 3))
        verdict = detect_flow_anomalies(df, config)
        metrics = compute_flow_metrics(verdict)
        flagged = int(verdict["flow_is_suspicious"].sum())
        profile = _flow_profile(df)
    except Exception as exc:  # noqa: BLE001
        return AnalysisResult(ok=False, error=f"Flow analysis failed: {exc}", raw_rows=len(df))

    return AnalysisResult(ok=True, mode="flow", raw_rows=len(df), flow_df=verdict,
                          flow_metrics=metrics, flagged_flows=flagged, profile=profile)


# --------------------------------------------------------------------------- #
# Entry point: parse bytes, auto-detect schema, route.
# --------------------------------------------------------------------------- #
def run_from_bytes(
    file_bytes: bytes,
    is_raw: bool = False,
    sensitivity: str = DEFAULT_SENSITIVITY,
) -> AnalysisResult:
    """Parse uploaded CSV bytes, auto-detect the schema, and run the right pipeline."""
    # If the user explicitly forces raw, try the headerless parse first.
    if is_raw:
        raw = _try_read(file_bytes, raw=True)
        if raw is not None and detect_schema(raw) == "host":
            return run_full_pipeline(raw, sensitivity)

    # Normal path: read with a header and auto-detect.
    df = _try_read(file_bytes, raw=False)
    if df is None or df.empty:
        return AnalysisResult(ok=False, error="The uploaded file is empty or unreadable.")

    mode = detect_schema(df)
    if mode == "host":
        return run_full_pipeline(df, sensitivity)
    if mode == "flow":
        return run_flow_pipeline(df, sensitivity)

    # Last resort: maybe it is a headerless raw UNSW capture.
    raw = _try_read(file_bytes, raw=True)
    if raw is not None and detect_schema(raw) == "host":
        return run_full_pipeline(raw, sensitivity)

    return AnalysisResult(
        ok=False,
        error=("Unrecognised file format. Need either host columns "
               "(srcip, dstip, sport, dsport, proto) or a UNSW-NB15 feature set "
               "(proto, state, service, ...)."),
    )


def _try_read(file_bytes: bytes, raw: bool) -> pd.DataFrame | None:
    try:
        buffer = io.BytesIO(file_bytes)
        if raw:
            return pd.read_csv(buffer, header=None, names=UNSW_RAW_COLUMNS, skipinitialspace=True)
        return pd.read_csv(buffer, encoding="utf-8-sig", skipinitialspace=True)
    except Exception:  # noqa: BLE001
        return None


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _attach_top_protocol(enriched: pd.DataFrame, clean_df: pd.DataFrame) -> pd.DataFrame:
    """Merge each host's most common protocol onto the enriched table."""
    if enriched.empty or "proto" not in clean_df.columns or "srcip" not in clean_df.columns:
        enriched["top_protocol"] = "-"
        return enriched
    top = (
        clean_df.groupby("srcip", observed=True)["proto"]
        .agg(lambda s: s.mode().iat[0] if not s.mode().empty else "-")
        .reset_index().rename(columns={"proto": "top_protocol"})
    )
    return enriched.merge(top, on="srcip", how="left").fillna({"top_protocol": "-"})


def _flow_profile(df: pd.DataFrame) -> dict:
    """Compact profile for flow-mode (no host identity available)."""
    def dist(col: str, top: int = 12) -> dict:
        if col not in df.columns:
            return {}
        vc = df[col].astype(str).value_counts().head(top)
        return {str(k): int(v) for k, v in vc.items()}

    return {
        "total_records": int(len(df)),
        "protocol_distribution": dist("proto"),
        "state_distribution": dist("state"),
        "service_distribution": dist("service"),
        "attack_cat_distribution": dist("attack_cat"),
    }
