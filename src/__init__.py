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

# --- Dev 2: feature engineering + rule-based detection ---
from src.features.feature_builder import build_host_feature_matrix
from src.detection.config import DetectionConfig
from src.detection.detector import RuleBasedDetector, detect_scanning

# --- Dev 3: statistical anomaly detection + severity classification ---
from src.scoring.config import ScoringConfig
from src.scoring.anomaly import StatisticalAnomalyDetector, detect_anomalies
from src.scoring.severity import SeverityClassifier
from src.scoring.enricher import enrich_detections

__all__ = [
    # Data layer (Dev 1)
    "load_csv",
    "validate_schema",
    "ValidationResult",
    "clean_data",
    "CleaningStats",
    "build_quality_report",
    "write_quality_report",
    "profile_dataset",
    "build_host_features",
    # Feature engineering + detection (Dev 2)
    "build_host_feature_matrix",
    "DetectionConfig",
    "RuleBasedDetector",
    "detect_scanning",
    # Statistical anomaly + severity (Dev 3)
    "ScoringConfig",
    "StatisticalAnomalyDetector",
    "detect_anomalies",
    "SeverityClassifier",
    "enrich_detections",
]

__version__ = "1.0.0"
