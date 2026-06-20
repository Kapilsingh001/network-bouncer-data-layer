"""Tests for src.cleaning.cleaner and data_quality."""

from __future__ import annotations

import json

from src.cleaning.cleaner import clean_data
from src.cleaning.data_quality import build_quality_report, write_quality_report


def test_clean_removes_all_defects(dirty_records):
    clean_df, stats = clean_data(dirty_records)

    # Defect rows expected to be removed:
    #   - row with null srcip
    #   - row with null dstip
    #   - row with port 70000 (out of range)
    #   - row with sport "-" (null)
    #   - row with proto "bogus" (invalid)
    #   - one exact duplicate (row 0 repeated at index 4)
    assert stats.null_srcip_removed == 1
    assert stats.null_dstip_removed == 1
    assert stats.null_port_removed == 1
    assert stats.invalid_port_removed == 1
    assert stats.invalid_proto_removed == 1
    assert stats.duplicate_removed == 1
    assert stats.final_rows == 1
    assert len(clean_df) == 1


def test_clean_keeps_valid_rows(clean_records):
    clean_df, stats = clean_data(clean_records)
    assert stats.final_rows == len(clean_records)
    assert stats.total_removed == 0


def test_clean_does_not_mutate_input(dirty_records):
    before = len(dirty_records)
    clean_data(dirty_records)
    assert len(dirty_records) == before


def test_ports_coerced_to_int(clean_records):
    clean_df, _ = clean_data(clean_records)
    assert str(clean_df["dsport"].dtype) in ("Int64", "int64")


def test_quality_report_contents(dirty_records):
    _, stats = clean_data(dirty_records)
    report = build_quality_report(stats)
    assert report["final_dataset_size"] == 1
    assert report["duplicate_rows_removed"] == 1
    assert report["missing_rows_removed"] == 3   # null src + null dst + null port
    assert report["invalid_rows_removed"] == 2   # invalid port + invalid proto
    assert 0.0 <= report["retention_rate"] <= 1.0


def test_write_quality_report(tmp_path, dirty_records):
    _, stats = clean_data(dirty_records)
    out = tmp_path / "quality_report.json"
    write_quality_report(stats, str(out))
    data = json.loads(out.read_text())
    assert data["final_dataset_size"] == 1
