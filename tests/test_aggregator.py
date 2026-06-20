"""Tests for src.analyzer.aggregator and profiler."""

from __future__ import annotations

import pandas as pd

from src.analyzer.aggregator import FEATURE_COLUMNS, build_host_features
from src.analyzer.profiler import profile_dataset


def test_host_features_one_row_per_source(clean_records):
    features = build_host_features(clean_records)
    assert list(features.columns) == FEATURE_COLUMNS
    # 10.0.0.1 and 10.0.0.2 are the two distinct sources.
    assert set(features["srcip"]) == {"10.0.0.1", "10.0.0.2"}


def test_host_feature_counts(clean_records):
    features = build_host_features(clean_records).set_index("srcip")
    # 10.0.0.1 has 3 flows to 3 distinct destinations and 3 distinct ports.
    assert features.loc["10.0.0.1", "total_connections"] == 3
    assert features.loc["10.0.0.1", "unique_destinations"] == 3
    assert features.loc["10.0.0.1", "unique_ports"] == 3
    assert features.loc["10.0.0.1", "unique_protocols"] == 1


def test_host_features_empty_input():
    features = build_host_features(pd.DataFrame())
    assert features.empty
    assert list(features.columns) == FEATURE_COLUMNS


def test_host_features_missing_optional_column(clean_records):
    df = clean_records.drop(columns=["service"])
    features = build_host_features(df)
    # unique_services still present, filled with 0.
    assert (features["unique_services"] == 0).all()


def test_profile_basic_counts(clean_records):
    profile = profile_dataset(clean_records)
    assert profile["total_records"] == 4
    assert profile["unique_sources"] == 2
    assert profile["unique_destinations"] == 4
    assert profile["protocol_distribution"]["tcp"] == 3


def test_profile_empty():
    profile = profile_dataset(pd.DataFrame())
    assert profile["total_records"] == 0
    assert profile["unique_sources"] == 0
