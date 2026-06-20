"""End-to-end data-layer pipeline for Network Bouncer.

A single convenience entry point that wires the six stages together:

    load -> validate -> clean -> quality-report -> profile -> features

Other team members can either call this orchestrator or import the individual
stages from their respective modules. The pipeline returns every artifact so
the detection / dashboard / reporting layers can pick what they need.
"""

from __future__ import annotations

from dataclasses import dataclass

import pandas as pd

from src.analyzer.aggregator import build_host_features
from src.analyzer.profiler import profile_dataset
from src.cleaning.cleaner import CleaningStats, clean_data
from src.cleaning.data_quality import build_quality_report, write_quality_report
from src.parser.csv_loader import load_csv
from src.parser.schema_validator import validate_schema
from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class PipelineResult:
    """All artifacts produced by a single pipeline run."""

    clean_df: pd.DataFrame
    features: pd.DataFrame
    profile: dict
    quality_report: dict
    cleaning_stats: CleaningStats


def run_pipeline(
    file_path: str,
    *,
    quality_report_path: str | None = "quality_report.json",
    chunksize: int | None = None,
) -> PipelineResult:
    """Run the full data layer over a CSV upload.

    Parameters
    ----------
    file_path:
        Path to the uploaded CSV.
    quality_report_path:
        Where to persist ``quality_report.json``. Pass ``None`` to skip writing.
    chunksize:
        Forwarded to the loader for very large files.

    Returns
    -------
    PipelineResult
        The cleaned dataset, host-feature table, profile and quality report.

    Raises
    ------
    CSVLoadError, SchemaValidationError
        On unrecoverable load or schema problems.
    """
    logger.info("=== Network Bouncer data pipeline: %s ===", file_path)

    # 1. Load
    df = load_csv(file_path, chunksize=chunksize)

    # 2. Validate (fail fast on missing required columns / empty data)
    validate_schema(df).raise_if_invalid()

    # 3. Clean
    clean_df, stats = clean_data(df)

    # 4. Quality report
    quality_report = build_quality_report(stats)
    if quality_report_path:
        write_quality_report(stats, quality_report_path)

    # 5. Profile
    profile = profile_dataset(clean_df)

    # 6. Features
    features = build_host_features(clean_df)

    logger.info("=== Pipeline complete ===")
    return PipelineResult(
        clean_df=clean_df,
        features=features,
        profile=profile,
        quality_report=quality_report,
        cleaning_stats=stats,
    )


if __name__ == "__main__":  # pragma: no cover
    import argparse
    import json

    parser = argparse.ArgumentParser(description="Network Bouncer data pipeline")
    parser.add_argument("csv", help="Path to the input CSV file")
    parser.add_argument(
        "--features-out", default="host_features.csv", help="Output path for host features"
    )
    parser.add_argument(
        "--report-out", default="quality_report.json", help="Output path for quality report"
    )
    args = parser.parse_args()

    result = run_pipeline(args.csv, quality_report_path=args.report_out)
    result.features.to_csv(args.features_out, index=False)
    print(json.dumps(result.profile, indent=2))
    print(f"\nFeatures written to {args.features_out}")
    print(f"Quality report written to {args.report_out}")
