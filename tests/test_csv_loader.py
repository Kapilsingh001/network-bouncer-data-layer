"""Tests for src.parser.csv_loader."""

from __future__ import annotations

import pytest

from src.parser.csv_loader import CSVLoadError, load_csv


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
