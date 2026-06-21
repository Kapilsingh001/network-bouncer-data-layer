"""Dataset-format detection for the Network Bouncer entry point.

The UNSW-NB15 dataset ships in two very different shapes, and the right
detector depends on which one you have:

* **Host/flow capture** (raw ``UNSW-NB15_1..4.csv``) — carries per-connection
  identity: ``srcip``/``dstip``/``sport``/``dsport``. This lets us aggregate
  behaviour *per source host* and run the strong, host-based port-scan detector.

* **ML feature partition** (``UNSW_NB15_training-set.csv`` /
  ``UNSW_NB15_testing-set.csv``) — the IP and port columns were stripped out and
  replaced with engineered flow features (``service``, ``state``, byte counts,
  and UNSW's ``ct_*`` connection-count columns). Host identity is simply not
  present, so host-based detection is impossible; we fall back to flow-level
  detection instead.

Rather than make the user know which file they have (and pass the right flag or
run the right script), :func:`detect_dataset_mode` inspects the columns and lets
``network_bouncer.py`` dispatch automatically.
"""

from __future__ import annotations

import pandas as pd

# Detection modes returned by :func:`detect_dataset_mode`.
HOST_MODE = "host"
FLOW_MODE = "flow"

# Columns that prove per-connection host identity is available. Without a source
# AND destination we cannot attribute scanning behaviour to a machine, which is
# the whole premise of host-based detection.
_HOST_IDENTITY_COLUMNS = {"srcip", "dstip"}


def detect_dataset_mode(df: pd.DataFrame) -> str:
    """Classify a loaded DataFrame as host-capable or flow-only.

    Parameters
    ----------
    df:
        The DataFrame returned by the CSV loader (column names as read).

    Returns
    -------
    str
        :data:`HOST_MODE` when source/destination identity is present (run the
        host-based detector), otherwise :data:`FLOW_MODE` (run the flow-level
        fallback). A column-less / ``None`` frame defaults to flow mode so the
        caller degrades gracefully instead of crashing.
    """
    if df is None or df.shape[1] == 0:
        return FLOW_MODE

    cols = {str(c).strip().lower() for c in df.columns}
    if _HOST_IDENTITY_COLUMNS.issubset(cols):
        return HOST_MODE
    return FLOW_MODE
