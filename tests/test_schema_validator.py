"""Tests for src.parser.schema_validator."""

from __future__ import annotations

import pandas as pd
import pytest

from src.parser.schema_validator import (
    SchemaValidationError,
    validate_schema,
)


def test_valid_schema_passes(clean_records):
    result = validate_schema(clean_records)
    assert result.is_valid
    assert result.errors == []


def test_missing_required_column(clean_records):
    df = clean_records.drop(columns=["srcip"])
    result = validate_schema(df)
    assert not result.is_valid
    assert any("srcip" in e for e in result.errors)


def test_empty_dataframe_rows():
    df = pd.DataFrame(columns=["srcip", "dstip", "sport", "dsport", "proto"])
    result = validate_schema(df)
    assert not result.is_valid
    assert any("empty" in e.lower() for e in result.errors)


def test_no_columns():
    result = validate_schema(pd.DataFrame())
    assert not result.is_valid


def test_unexpected_column_is_warning(clean_records):
    df = clean_records.copy()
    df["extra_field"] = 1
    result = validate_schema(df)
    assert result.is_valid  # extra columns are non-fatal
    assert any("extra_field" in w for w in result.warnings)


def test_case_insensitive_columns(clean_records):
    df = clean_records.rename(columns={"srcip": "SrcIP", "dstip": "DSTIP"})
    result = validate_schema(df)
    assert result.is_valid


def test_raise_if_invalid(clean_records):
    df = clean_records.drop(columns=["proto"])
    with pytest.raises(SchemaValidationError):
        validate_schema(df).raise_if_invalid()
