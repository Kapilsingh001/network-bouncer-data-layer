"""Generate a messy sample CSV to exercise the whole pipeline.

Produces a dataset containing:
  * a horizontal scanner   (one source -> many destinations)
  * a vertical scanner     (one source -> many ports on one host)
  * a block scanner        (many ports x many hosts)
  * two benign hosts       (a web server client, a DB client)
  * deliberate DIRT        (null IPs, null/blank ports, out-of-range ports,
                            null protocols, sentinel "-" tokens, duplicates)

Usage:
    python scripts/make_sample_data.py            # writes sample_dirty.csv
    python scripts/make_sample_data.py out.csv
"""

from __future__ import annotations

import sys

import pandas as pd

COLUMNS = ["srcip", "dstip", "sport", "dsport", "proto", "service", "state", "label"]


def build_rows() -> list[tuple]:
    rows: list[tuple] = []

    # --- Horizontal scanner: 60 hosts, same port, one flow each -------------
    for i in range(60):
        rows.append(("10.0.0.10", f"192.168.1.{i}", 40000 + i, 80, "tcp", "-", "INT", 1))

    # --- Vertical scanner: one host, 50 distinct ports ----------------------
    for p in range(50):
        rows.append(("10.0.0.20", "192.168.5.5", 50000 + p, 1000 + p, "tcp", "-", "REQ", 1))

    # --- Block scanner: 20 hosts x 20 ports, uncommon protocol --------------
    for d in range(20):
        for p in range(20):
            rows.append(("10.0.0.30", f"172.16.0.{d}", 41000 + p, 2000 + p, "ospf", "-", "INT", 1))

    # --- Benign web client: repeated completed HTTPS to one server ----------
    for i in range(40):
        rows.append(("10.0.0.100", "192.168.9.9", 33000 + i, 443, "tcp", "https", "FIN", 0))

    # --- Benign DB client: repeated completed SQL to one server -------------
    for i in range(30):
        rows.append(("10.0.0.101", "192.168.9.10", 34000 + i, 3306, "tcp", "sql", "CON", 0))

    # --- Deliberate dirt ----------------------------------------------------
    rows.append((None, "192.168.1.1", 1234, 80, "tcp", "http", "FIN", 0))      # null src
    rows.append(("10.0.0.200", None, 1234, 80, "tcp", "http", "FIN", 0))       # null dst
    rows.append(("10.0.0.201", "192.168.1.2", "-", 80, "tcp", "http", "FIN", 0))  # null port
    rows.append(("10.0.0.202", "192.168.1.3", 1234, 70000, "tcp", "http", "FIN", 0))  # bad port
    rows.append(("10.0.0.203", "192.168.1.4", 1234, 80, None, "http", "FIN", 0))   # null proto
    rows.append(("10.0.0.10", "192.168.1.0", 40000, 80, "tcp", "-", "INT", 1))  # duplicate of row 0

    return rows


def main() -> None:
    out = sys.argv[1] if len(sys.argv) > 1 else "sample_dirty.csv"
    df = pd.DataFrame(build_rows(), columns=COLUMNS)
    df.to_csv(out, index=False)
    print(f"Wrote {len(df)} rows (including deliberate dirt) -> {out}")


if __name__ == "__main__":
    main()
