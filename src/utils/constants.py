"""Shared constants for the Network Bouncer data layer.

Centralising the schema definition here means the loader, validator, cleaner,
profiler and aggregator all agree on column names and valid value ranges.
Change it in one place and the whole pipeline stays consistent.
"""

from __future__ import annotations

# Full set of columns we expect in the source dataset.
EXPECTED_COLUMNS: list[str] = [
    "srcip",
    "dstip",
    "sport",
    "dsport",
    "proto",
    "service",
    "state",
    "label",
]

# Columns that MUST be present for the downstream detection logic to work.
# Without these, scan detection is impossible, so their absence is fatal.
REQUIRED_COLUMNS: list[str] = [
    "srcip",
    "dstip",
    "sport",
    "dsport",
    "proto",
]

# Port columns share the same valid range.
PORT_COLUMNS: list[str] = ["sport", "dsport"]

# Valid TCP/UDP port range. Port 0 is reserved and never a legitimate
# connection endpoint, so the valid range is 1..65535 inclusive.
MIN_PORT: int = 1
MAX_PORT: int = 65535

# Known L4/L7 protocol tokens seen in data-center capture datasets
# (e.g. UNSW-NB15). Anything outside this set is treated as invalid/unknown.
VALID_PROTOCOLS: set[str] = {
    "tcp",
    "udp",
    "icmp",
    "igmp",
    "arp",
    "ospf",
    "sctp",
    "gre",
    "esp",
    "ipv6",
    "rtp",
    "unas",
}

# Sentinel tokens that frequently appear in network captures to mean
# "no value" and should be treated as nulls during cleaning.
NULL_TOKENS: set[str] = {"", "-", "na", "n/a", "nan", "none", "null", "?"}

# Connection states considered "successfully established". Anything else counts
# as an incomplete connection (half-open / rejected) during feature engineering.
# Lower-cased for comparison. NOTE: constrains connection STATE only, never
# protocol type.
DEFAULT_ESTABLISHED_STATES: frozenset = frozenset({"fin", "con"})

# Column order of the RAW UNSW-NB15 capture files (UNSW-NB15_1..4.csv), which
# ship WITHOUT a header row. Assigning these names lets the loader read the raw
# files directly. Order matches the official NUSW-NB15_features.csv.
UNSW_RAW_COLUMNS: list[str] = [
    "srcip", "sport", "dstip", "dsport", "proto", "state", "dur", "sbytes",
    "dbytes", "sttl", "dttl", "sloss", "dloss", "service", "sload", "dload",
    "spkts", "dpkts", "swin", "dwin", "stcpb", "dtcpb", "smeansz", "dmeansz",
    "trans_depth", "res_bdy_len", "sjit", "djit", "stime", "ltime", "sintpkt",
    "dintpkt", "tcprtt", "synack", "ackdat", "is_sm_ips_ports", "ct_state_ttl",
    "ct_flw_http_mthd", "is_ftp_login", "ct_ftp_cmd", "ct_srv_src", "ct_srv_dst",
    "ct_dst_ltm", "ct_src_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm",
    "ct_dst_src_ltm", "attack_cat", "label",
]
