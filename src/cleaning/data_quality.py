"""Data-quality reporting for the Network Bouncer data layer.

Turns the :class:`src.cleaning.cleaner.CleaningStats` produced during cleaning
into a persisted ``quality_report.json`` artifact. Other team members (and
graders) can read this file to understand exactly how the raw upload was
transformed into the analysis-ready dataset.
"""

from __future__ import annotations

import json
import os
from typing import Optional

from src.cleaning.cleaner import CleaningStats
from src.utils.logger import get_logger

logger = get_logger(__name__)


def build_quality_report(stats: CleaningStats) -> dict:
    """Build a structured data-quality report from cleaning statistics.

    Returns
    -------
    dict
        JSON-serialisable summary of every removal step plus a retention rate.
    """
    initial = stats.initial_rows or 0
    retention = round(stats.final_rows / initial, 4) if initial else 0.0

    report = {
        "initial_rows": stats.initial_rows,
        "missing_rows_removed": (
            stats.null_srcip_removed
            + stats.null_dstip_removed
            + stats.null_port_removed
        ),
        "duplicate_rows_removed": stats.duplicate_removed,
        "invalid_rows_removed": (
            stats.invalid_port_removed + stats.invalid_proto_removed
        ),
        "breakdown": {
            "null_srcip_removed": stats.null_srcip_removed,
            "null_dstip_removed": stats.null_dstip_removed,
            "null_port_removed": stats.null_port_removed,
            "invalid_port_removed": stats.invalid_port_removed,
            "invalid_proto_removed": stats.invalid_proto_removed,
            "duplicate_removed": stats.duplicate_removed,
        },
        "total_rows_removed": stats.total_removed,
        "final_dataset_size": stats.final_rows,
        "retention_rate": retention,
    }
    return report


def write_quality_report(
    stats: CleaningStats,
    output_path: str = "quality_report.json",
    *,
    indent: int = 2,
) -> str:
    """Build and persist the quality report to ``output_path``.

    Returns
    -------
    str
        The path the report was written to.
    """
    report = build_quality_report(stats)
    _ensure_parent_dir(output_path)
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=indent)
    logger.info("Quality report written to %s", output_path)
    return output_path


def _ensure_parent_dir(path: str) -> None:
    parent: Optional[str] = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
