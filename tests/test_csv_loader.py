"""Tests for src.parser.csv_loader."""

from __future__ import annotations

import pytest

from src.parser.csv_loader import CSVLoadError, load_csv, load_raw_csv
from src.utils.constants import UNSW_RAW_COLUMNS


def test_load_valid_csv(csv_file):
    df = load_csv(csv_file)
    assert len(df) == 4
    assert "srcip" in df.columns


def test_load_csv_chunked(csv_file):
    df = load_csv(csv_file, chunksize=2)
    assert len(df) == 4


def test_missing_file_raises():
    with pytest.raises(CSVLoadError, match="File not found"):
        load_csv("does_not_exist_12345.csv")


def test_directory_path_raises(tmp_path):
    with pytest.raises(CSVLoadError, match="not a file"):
        load_csv(str(tmp_path))


def test_empty_file_raises(tmp_path):
    empty = tmp_path / "empty.csv"
    empty.write_text("")
    with pytest.raises(CSVLoadError, match="empty"):
        load_csv(str(empty))


def test_header_only_raises(tmp_path):
    header_only = tmp_path / "header.csv"
    header_only.write_text("srcip,dstip,sport,dsport,proto\n")
    with pytest.raises(CSVLoadError, match="zero rows"):
        load_csv(str(header_only))


def test_usecols_subset(csv_file):
    df = load_csv(csv_file, usecols=["srcip", "dstip"])
    assert list(df.columns) == ["srcip", "dstip"]


def test_load_raw_headerless_unsw(tmp_path):
    # A headerless raw UNSW-NB15-style row (49 columns).
    row = ["59.166.0.5", "1390", "149.171.126.6", "53", "udp", "CON"] + ["0"] * 43
    assert len(row) == len(UNSW_RAW_COLUMNS)
    row[13] = "dns"          # service column
    row[47] = "-"            # attack_cat
    row[48] = "0"            # label
    raw = tmp_path / "raw.csv"
    raw.write_text(",".join(row) + "\n")

    df = load_raw_csv(str(raw))
    assert list(df.columns) == UNSW_RAW_COLUMNS
    assert df.iloc[0]["srcip"] == "59.166.0.5"
    assert df.iloc[0]["dsport"] == 53
    assert df.iloc[0]["proto"] == "udp"
