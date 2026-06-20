"""Shared pytest fixtures for the Network Bouncer data-layer tests."""

from __future__ import annotations

import pandas as pd
import pytest


@pytest.fixture
def clean_records() -> pd.DataFrame:
    """A small, fully-valid dataset."""
    return pd.DataFrame(
        {
            "srcip": ["10.0.0.1", "10.0.0.1", "10.0.0.2", "10.0.0.1"],
            "dstip": ["10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8"],
            "sport": [1024, 1025, 2048, 1026],
            "dsport": [80, 443, 22, 8080],
            "proto": ["tcp", "tcp", "udp", "tcp"],
            "service": ["http", "https", "dns", "http"],
            "state": ["FIN", "FIN", "CON", "FIN"],
            "label": [0, 0, 1, 0],
        }
    )


@pytest.fixture
def dirty_records() -> pd.DataFrame:
    """A dataset containing every category of defect the cleaner handles."""
    # One distinct defect per row (rows 1-5), plus an exact duplicate (row 6):
    #   0 valid | 1 null src | 2 null dst | 3 null port | 4 invalid port |
    #   5 invalid proto | 6 duplicate-of-0
    return pd.DataFrame(
        {
            "srcip": ["10.0.0.1", None, "10.0.0.2", "10.0.0.5", "10.0.0.3", "10.0.0.6", "10.0.0.1"],
            "dstip": ["10.0.0.5", "10.0.0.6", None, "10.0.0.9", "10.0.0.7", "10.0.0.8", "10.0.0.5"],
            "sport": [1024, 1025, 2048, "-", 70000, 1100, 1024],
            "dsport": [80, 443, 22, 53, 80, 443, 80],
            "proto": ["tcp", "tcp", "udp", "udp", "tcp", "bogus", "tcp"],
            "service": ["http", "https", "dns", "dns", "http", "https", "http"],
            "state": ["FIN", "FIN", "CON", "CON", "FIN", "FIN", "FIN"],
            "label": [0, 0, 1, 1, 0, 0, 0],
        }
    )


@pytest.fixture
def csv_file(tmp_path, clean_records) -> str:
    """Write the clean dataset to a temp CSV and return its path."""
    path = tmp_path / "sample.csv"
    clean_records.to_csv(path, index=False)
    return str(path)
