"""Detection configuration for the Network Bouncer rule engine.

All tunable thresholds live here in one immutable, well-documented place so the
detection logic itself stays declarative and the SOC analyst can tune sensitivity
without touching code. Treat this as the "detection policy" — in a real SOC tool
it would be loaded from a YAML/UI policy file.

Design note
-----------
Thresholds are deliberately conservative defaults chosen for data-center east-west
traffic. Every scan rule is gated by ``min_connections`` so low-volume, ordinary
hosts are never flagged on ratio noise alone.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from src.utils.constants import DEFAULT_ESTABLISHED_STATES


@dataclass(frozen=True)
class DetectionConfig:
    """Immutable threshold policy for the rule-based detector.

    Attributes
    ----------
    min_connections:
        Volume floor. A host must originate at least this many flows before any
        scan rule can fire. Prevents flagging a host that briefly touched a few
        ports as a "scanner".
    horizontal_min_destinations:
        Distinct destination IPs that constitute a horizontal sweep (one source
        probing many hosts).
    vertical_min_ports:
        Distinct destination ports that constitute a vertical scan (one source
        probing many ports).
    vertical_max_destinations:
        A vertical scan is concentrated: many ports aimed at *few* hosts.
    block_min_destinations / block_min_ports:
        A block scan hits many ports across many hosts simultaneously.
    high_port_ratio:
        unique_dst_ports / total_connections. Near 1.0 means almost every flow
        targets a brand-new port — the signature of a sweeping scanner that does
        not reuse connections.
    low_conn_per_destination:
        total_connections / unique_destinations. Near 1.0 means each destination
        is touched roughly once — classic sweep behaviour.
    null_service_ratio_threshold:
        Fraction of flows whose service is unknown/unassigned. Scanners hit many
        ports with no listening service, so this runs high for recon.
    incomplete_ratio_threshold:
        Fraction of flows that did not reach an established state. Scans generate
        many half-open / rejected connections.
    established_states:
        Connection states considered "successfully established". Everything else
        counts toward the incomplete ratio. Lower-cased for comparison.
        NOTE: this constrains *connection state* only — never protocol type.
    min_rules_to_flag:
        How many independent rules must fire before a host is marked suspicious.
        1 = high sensitivity; raise to reduce false positives.
    """

    min_connections: int = 10

    # Horizontal (network sweep)
    horizontal_min_destinations: int = 20

    # Vertical (port sweep on a host)
    vertical_min_ports: int = 20
    vertical_max_destinations: int = 5

    # Block (ports x hosts)
    block_min_destinations: int = 15
    block_min_ports: int = 15

    # Ratio-based behavioural signals
    high_port_ratio: float = 0.8
    low_conn_per_destination: float = 1.5
    null_service_ratio_threshold: float = 0.5
    incomplete_ratio_threshold: float = 0.7

    established_states: frozenset = field(default_factory=lambda: DEFAULT_ESTABLISHED_STATES)

    min_rules_to_flag: int = 1

    # --- Classification & severity (output policy) -------------------------
    # Classification labels mirror the problem statement's required output:
    # a host is either "Normal" or "Suspicious (Backdoor/Analysis)".
    normal_label: str = "Normal"
    suspicious_label: str = "Suspicious (Backdoor/Analysis)"

    # Severity tiers (Low/Medium/High) derived from the suspicion score, so an
    # analyst can triage the highest-risk hosts first. Tunable to trade off
    # sensitivity vs. false positives.
    severity_medium_score: float = 3.0
    severity_high_score: float = 6.0
