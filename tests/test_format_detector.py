"""Tests for dataset-format auto-detection (host vs flow dispatch)."""

from __future__ import annotations

import pandas as pd

from src.parser.format_detector import (
    FLOW_MODE,
    HOST_MODE,
    detect_dataset_mode,
)


def test_raw_capture_columns_are_host_mode():
    """A file with srcip/dstip routes to the host-based detector."""
    df = pd.DataFrame({
        "srcip": ["10.0.0.1"],
        "dstip": ["10.0.0.2"],
        "sport": [1234],
        "dsport": [80],
        "proto": ["tcp"],
    })
    assert detect_dataset_mode(df) == HOST_MODE


def test_unsw_feature_set_is_flow_mode():
    """The ML testing-set (no IP/port columns) routes to flow-level detection."""
    df = pd.DataFrame({
        "id": [1],
        "proto": ["tcp"],
        "service": ["-"],
        "state": ["FIN"],
        "sbytes": [258],
        "ct_dst_src_ltm": [1],
        "attack_cat": ["Normal"],
        "label": [0],
    })
    assert detect_dataset_mode(df) == FLOW_MODE


def test_detection_is_case_insensitive():
    """Column matching tolerates capitalisation and surrounding whitespace."""
    df = pd.DataFrame(columns=[" SrcIP ", "DSTIP", "proto"])
    assert detect_dataset_mode(df) == HOST_MODE


def test_missing_destination_falls_back_to_flow_mode():
    """Source without destination is not enough for host aggregation."""
    df = pd.DataFrame({"srcip": ["10.0.0.1"], "proto": ["tcp"]})
    assert detect_dataset_mode(df) == FLOW_MODE


def test_empty_frame_defaults_to_flow_mode():
    """A column-less frame degrades gracefully instead of raising."""
    assert detect_dataset_mode(pd.DataFrame()) == FLOW_MODE
