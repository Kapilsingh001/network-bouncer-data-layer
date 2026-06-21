"""Generate a synthetic RAW UNSW-NB15 capture file (headerless, 49 columns).

Mirrors the real UNSW-NB15_1..4.csv layout: no header row, columns in the
official order, with genuine srcip/sport/dstip/dsport/proto/state/service so the
scan detector has real hosts and ports to analyse.

Contains:
  * horizontal scanner (one src -> many dsts)
  * vertical scanner   (one src -> many ports on one dst)
  * block scanner      (many ports x many dsts, uncommon protocols)
  * benign web + dns hosts
  * deliberate dirt    (null src, bad port, null proto, duplicate)

Usage:
    python scripts/make_raw_sample.py            # -> raw_unsw_sample.csv
    python scripts/make_raw_sample.py out.csv
"""

from __future__ import annotations

import os
import sys

import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.utils.constants import UNSW_RAW_COLUMNS  # noqa: E402


def flow(srcip, sport, dstip, dsport, proto, state, service, label, attack_cat="-"):
    """Build one 49-field record with sensible defaults for the stat columns."""
    row = {col: 0 for col in UNSW_RAW_COLUMNS}
    row.update(
        srcip=srcip, sport=sport, dstip=dstip, dsport=dsport, proto=proto,
        state=state, service=service, label=label, attack_cat=attack_cat,
    )
    return row


def build_rows() -> list[dict]:
    rows: list[dict] = []

    # Horizontal scanner: 60 destinations, same port, single touch each.
    for i in range(60):
        rows.append(flow("59.166.0.5", 40000 + i, f"149.171.126.{i}", 80,
                         "tcp", "INT", "-", 1, "Reconnaissance"))

    # Vertical scanner: one host, 50 distinct ports.
    for p in range(50):
        rows.append(flow("175.45.176.1", 50000 + p, "149.171.126.10", 1000 + p,
                         "tcp", "REQ", "-", 1, "Reconnaissance"))

    # Block scanner: 20 hosts x 20 ports, uncommon protocols (no whitelist!).
    protos = ["ospf", "unas", "sctp", "gre"]
    for d in range(20):
        for p in range(20):
            rows.append(flow("175.45.176.2", 41000 + p, f"149.171.126.{d}", 2000 + p,
                             protos[p % len(protos)], "INT", "-", 1, "Reconnaissance"))

    # Benign web client: repeated completed HTTPS to one server.
    for i in range(40):
        rows.append(flow("10.40.85.1", 33000 + i, "10.40.182.3", 443,
                         "tcp", "FIN", "http", 0))

    # Benign DNS client: repeated completed DNS lookups.
    for i in range(30):
        rows.append(flow("10.40.85.2", 34000 + i, "10.40.182.4", 53,
                         "udp", "CON", "dns", 0))

    # Deliberate dirt.
    rows.append(flow(None, 1234, "149.171.126.1", 80, "tcp", "FIN", "http", 0))   # null src
    rows.append(flow("10.40.85.9", 1234, "10.40.182.3", 70000, "tcp", "FIN", "http", 0))  # bad port
    rows.append(flow("10.40.85.10", 1234, "10.40.182.3", 80, None, "FIN", "http", 0))     # null proto
    rows.append(flow("59.166.0.5", 40000, "149.171.126.0", 80, "tcp", "INT", "-", 1))     # duplicate

    return rows


def main() -> None:
    out = sys.argv[1] if len(sys.argv) > 1 else "raw_unsw_sample.csv"
    df = pd.DataFrame(build_rows(), columns=UNSW_RAW_COLUMNS)
    # header=False -> faithful raw UNSW-NB15 format.
    df.to_csv(out, index=False, header=False)
    print(f"Wrote {len(df)} headerless rows ({len(UNSW_RAW_COLUMNS)} cols) -> {out}")


if __name__ == "__main__":
    main()
