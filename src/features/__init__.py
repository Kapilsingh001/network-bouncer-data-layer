"""Feature engineering layer (Dev 2).

Turns row-per-flow cleaned data into a rich, row-per-source-host behavioural
feature matrix that the rule-based detector reasons over.
"""

from __future__ import annotations

from src.features.feature_builder import (
    FEATURE_MATRIX_COLUMNS,
    build_host_feature_matrix,
)

__all__ = ["build_host_feature_matrix", "FEATURE_MATRIX_COLUMNS"]
