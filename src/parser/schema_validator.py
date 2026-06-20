"""Schema validation for the Network Bouncer data layer.

Runs immediately after :func:`src.parser.csv_loader.load_csv`. Its job is to
guarantee that the DataFrame is structurally fit for the downstream cleaning,
profiling and detection stages — BEFORE any expensive processing happens.

It checks three things:

1. The dataset is non-empty.
2. All *required* columns are present.
3. Column names are recognised (unknown columns are flagged as warnings, not
   hard errors, so the pipeline stays forgiving of extra capture fields).

Validation never mutates the data; it only reports.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pandas as pd

from src.utils.constants import EXPECTED_COLUMNS, REQUIRED_COLUMNS
from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class ValidationResult:
    """Structured outcome of a schema validation pass.

    Attributes
    ----------
    is_valid:
        ``True`` only when there are no blocking errors.
    errors:
        Fatal problems that must stop the pipeline (missing required columns,
        empty dataset).
    warnings:
        Non-fatal observations (unexpected/extra columns).
    """

    is_valid: bool = True
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def add_error(self, message: str) -> None:
        self.errors.append(message)
        self.is_valid = False

    def add_warning(self, message: str) -> None:
        self.warnings.append(message)

    def raise_if_invalid(self) -> None:
        """Raise :class:`SchemaValidationError` if any blocking error exists."""
        if not self.is_valid:
            raise SchemaValidationError("; ".join(self.errors))

    def to_dict(self) -> dict:
        return {
            "is_valid": self.is_valid,
            "errors": self.errors,
            "warnings": self.warnings,
        }


class SchemaValidationError(Exception):
    """Raised when a DataFrame fails required-schema validation."""


def validate_schema(
    df: pd.DataFrame,
    *,
    required_columns: list[str] | None = None,
    expected_columns: list[str] | None = None,
) -> ValidationResult:
    """Validate the structure of a loaded dataset.

    Parameters
    ----------
    df:
        The DataFrame returned by the CSV loader.
    required_columns:
        Columns that must exist (defaults to
        :data:`src.utils.constants.REQUIRED_COLUMNS`).
    expected_columns:
        Full known schema, used to detect unexpected extra columns
        (defaults to :data:`src.utils.constants.EXPECTED_COLUMNS`).

    Returns
    -------
    ValidationResult
        A structured report. Inspect ``.is_valid``, or call
        ``.raise_if_invalid()`` to fail fast.
    """
    required = required_columns or REQUIRED_COLUMNS
    expected = expected_columns or EXPECTED_COLUMNS
    result = ValidationResult()

    # 1. Empty dataset check (no columns or no rows).
    if df is None or df.shape[1] == 0:
        result.add_error("Dataset has no columns.")
        logger.error("Schema validation failed: no columns")
        return result
    if len(df) == 0:
        result.add_error("Dataset is empty (zero rows).")

    # Normalise column names for a forgiving, case-insensitive comparison.
    actual_cols = {str(c).strip().lower() for c in df.columns}

    # 2. Missing required columns -> fatal.
    missing = [col for col in required if col.lower() not in actual_cols]
    if missing:
        result.add_error(f"Missing required column(s): {missing}")

    # 3. Unexpected columns -> warning only (extra capture fields are allowed).
    unexpected = sorted(actual_cols - {c.lower() for c in expected})
    if unexpected:
        result.add_warning(f"Unexpected column(s) present (ignored downstream): {unexpected}")

    if result.is_valid:
        logger.info("Schema validation passed (%d warning(s))", len(result.warnings))
    else:
        logger.error("Schema validation failed: %s", result.errors)

    return result
