"""Network Bouncer — Data Layer.

This package owns everything from raw CSV ingestion to a clean, validated,
feature-ready dataset. Detection, scoring, dashboard and reporting live in
sibling packages owned by other team members and consume the artifacts
produced here.

Public entry points are re-exported for convenience::

    from src import load_csv, validate_schema, clean_data, profile_dataset, build_host_features
"""

from __future__ import annotations

from src.parser.csv_loader import load_csv
from src.parser.schema_validator import validate_schema, ValidationResult
from src.cleaning.cleaner import clean_data, CleaningStats
from src.cleaning.data_quality import build_quality_report, write_quality_report
from src.analyzer.profiler import profile_dataset
from src.analyzer.aggregator import build_host_features

__all__ = [
    "load_csv",
    "validate_schema",
    "ValidationResult",
    "clean_data",
    "CleaningStats",
    "build_quality_report",
    "write_quality_report",
    "profile_dataset",
    "build_host_features",
]

__version__ = "1.0.0"
