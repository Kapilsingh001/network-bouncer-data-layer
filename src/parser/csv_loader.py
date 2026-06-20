"""CSV ingestion for the Network Bouncer data layer.

Responsible solely for getting bytes off disk and into a well-typed pandas
DataFrame, with robust error handling. It does NOT validate the schema or clean
the data — those are separate, single-responsibility stages.

Design goals
------------
* Efficient for large datasets  -> categorical dtypes + optional chunked reads.
* Fail loud, fail early         -> explicit, typed exceptions.
* Predictable output            -> always a pandas.DataFrame (or a raise).
"""

from __future__ import annotations

import os
from typing import Iterable, Optional

import pandas as pd
from pandas.errors import EmptyDataError, ParserError

from src.utils.logger import get_logger

logger = get_logger(__name__)

# Reading IP/proto/service/state as categoricals keeps memory flat even on
# multi-million-row captures, because the underlying values repeat heavily.
_DEFAULT_DTYPES = {
    "srcip": "category",
    "dstip": "category",
    "proto": "category",
    "service": "category",
    "state": "category",
}

# Ports are read as strings first so that malformed values ("-", "0x1f") do not
# crash the parser; the cleaner coerces them to integers later with full
# control over what counts as invalid.
_STRING_COLUMNS = ("sport", "dsport")


class CSVLoadError(Exception):
    """Raised when a CSV file cannot be located, read, or parsed."""


def load_csv(
    file_path: str,
    *,
    chunksize: Optional[int] = None,
    usecols: Optional[Iterable[str]] = None,
    encoding: str = "utf-8",
) -> pd.DataFrame:
    """Load a CSV file into a pandas DataFrame.

    Parameters
    ----------
    file_path:
        Absolute or relative path to the CSV file.
    chunksize:
        If provided, the file is read in chunks of this many rows and
        concatenated. Use this for very large files to bound peak memory.
    usecols:
        Optional subset of columns to read. Reading only what you need is the
        single biggest speed/memory win on wide files.
    encoding:
        Text encoding of the file (defaults to UTF-8).

    Returns
    -------
    pandas.DataFrame
        The parsed dataset.

    Raises
    ------
    CSVLoadError
        If the file does not exist, is not a file, is empty, or cannot be
        parsed as CSV.
    """
    logger.info("Loading CSV: %s", file_path)

    # 1. Validate existence and that it is a regular file.
    if not os.path.exists(file_path):
        raise CSVLoadError(f"File not found: {file_path!r}")
    if not os.path.isfile(file_path):
        raise CSVLoadError(f"Path is not a file: {file_path!r}")
    if os.path.getsize(file_path) == 0:
        raise CSVLoadError(f"File is empty (0 bytes): {file_path!r}")

    read_kwargs = dict(
        dtype=_resolve_dtypes(usecols),
        usecols=list(usecols) if usecols else None,
        encoding=encoding,
        # Quietly tolerate occasional malformed rows instead of aborting the
        # whole load; the data-quality stage accounts for what was dropped.
        on_bad_lines="warn",
        skipinitialspace=True,
    )

    try:
        if chunksize:
            logger.info("Reading in chunks of %d rows", chunksize)
            frames = [chunk for chunk in pd.read_csv(file_path, chunksize=chunksize, **read_kwargs)]
            df = pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()
        else:
            df = pd.read_csv(file_path, **read_kwargs)
    except EmptyDataError as exc:
        raise CSVLoadError(f"CSV contains no data: {file_path!r}") from exc
    except ParserError as exc:
        raise CSVLoadError(f"Malformed CSV, could not parse: {file_path!r} ({exc})") from exc
    except UnicodeDecodeError as exc:
        raise CSVLoadError(
            f"Encoding error reading {file_path!r} with encoding={encoding!r}: {exc}"
        ) from exc
    except ValueError as exc:
        # e.g. usecols referencing a column that does not exist.
        raise CSVLoadError(f"Could not read {file_path!r}: {exc}") from exc

    if df.empty:
        raise CSVLoadError(f"CSV parsed to zero rows: {file_path!r}")

    logger.info("Loaded %d rows x %d columns", len(df), df.shape[1])
    return df


def _resolve_dtypes(usecols: Optional[Iterable[str]]) -> dict:
    """Return the dtype map restricted to whatever columns are being read."""
    if usecols is None:
        return dict(_DEFAULT_DTYPES)
    wanted = set(usecols)
    return {col: dtype for col, dtype in _DEFAULT_DTYPES.items() if col in wanted}
