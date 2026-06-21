"""Generate a population-style sample CSV to showcase the Dev 3 layer.

Creates many quiet/benign hosts plus a few scanners, so the statistical
anomaly detector has a real population baseline to measure outliers against
(unlike the tiny raw sample, which has too few hosts for z-scores).

Usage:
    python scripts/make_population_sample.py            # -> population_sample.csv
    python scripts/make_population_sample.py out.csv
"""

from __future__ import annotations

import sys

import pandas as pd

COLUMNS = ["srcip", "dstip", "sport", "dsport", "proto", "service", "state", "label"]


def build_rows() -> list[tuple]:
    rows: list[tuple] = []

    # 25 benign hosts: each chats with one server on one service, completed.
    for h in range(25):
        ip = f"10.10.0.{h}"
        svc, port = ("https", 443) if h % 2 == 0 else ("dns", 53)
        for c in range(8):
            rows.append((ip, "10.20.0.5", 30000 + c, port, "tcp", svc, "FIN", 0))

    # Block scanner: 25 hosts x 25 ports, uncommon protocol, no service.
    for d in range(25):
        for p in range(25):
            rows.append(("175.45.176.2", f"172.16.0.{d}", 40000 + p, 2000 + p,
                         "ospf", "-", "INT", 1))

    # Horizontal scanner: one source sweeps 60 destinations.
    for d in range(60):
        rows.append(("59.166.0.5", f"149.171.126.{d}", 41000 + d, 80,
                     "tcp", "-", "INT", 1))

    # Vertical scanner: one source probes 50 ports on a single host.
    for p in range(50):
        rows.append(("175.45.176.1", "149.171.126.10", 50000 + p, 1000 + p,
                     "tcp", "-", "REQ", 1))

    return rows


def main() -> None:
    out = sys.argv[1] if len(sys.argv) > 1 else "population_sample.csv"
    pd.DataFrame(build_rows(), columns=COLUMNS).to_csv(out, index=False)
    print(f"Wrote sample with 25 benign hosts + 3 scanners -> {out}")


if __name__ == "__main__":
    main()
