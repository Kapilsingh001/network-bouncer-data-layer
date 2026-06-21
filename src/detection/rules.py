"""Rule definitions for the Network Bouncer rule-based detector.

Each rule is a small, transparent, independently-testable predicate over a
single host's feature row. A rule answers one question — "does this host exhibit
behaviour X?" — and, when it fires, returns a human-readable *indicator* string
explaining exactly why. This is what makes the detector explainable: every alert
traces back to the concrete numbers that triggered it.

Detection taxonomy
------------------
* ``horizontal`` — one source touching many destinations (network sweep).
* ``vertical``   — one source touching many ports on few hosts (port sweep).
* ``block``      — many ports across many hosts (block scan).
* ``behavioural``— shape signals: low connection reuse, unknown services,
                   incomplete connections.

Rules are intentionally allowed to overlap. Multiple independent indicators
firing on the same host *increases confidence*, which the detector reflects in
its rule-hit count and suspicion score.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

import pandas as pd

from src.detection.config import DetectionConfig

# A predicate inspects a feature row and returns (triggered, indicator_text).
Predicate = Callable[[pd.Series, DetectionConfig], "tuple[bool, str]"]


@dataclass(frozen=True)
class RuleResult:
    """Outcome of evaluating one rule against one host."""

    rule: str
    category: str
    triggered: bool
    weight: float
    indicator: str


@dataclass(frozen=True)
class Rule:
    """A named, weighted detection rule.

    Parameters
    ----------
    name:
        Unique, stable rule identifier (used in alerts).
    category:
        One of the detection-taxonomy buckets.
    weight:
        Contribution to the host's suspicion score when this rule fires.
        Relative weights only — formal severity scoring is owned downstream.
    predicate:
        ``(row, config) -> (triggered, indicator_text)``.
    description:
        Human-readable statement of what the rule detects.
    """

    name: str
    category: str
    weight: float
    predicate: Predicate
    description: str

    def evaluate(self, row: pd.Series, config: DetectionConfig) -> RuleResult:
        triggered, indicator = self.predicate(row, config)
        return RuleResult(
            rule=self.name,
            category=self.category,
            triggered=bool(triggered),
            weight=self.weight if triggered else 0.0,
            indicator=indicator,
        )


# --------------------------------------------------------------------------- #
# Predicate implementations
#
# Every scan rule is gated on ``min_connections`` so that low-volume, ordinary
# hosts cannot trip a rule on ratio noise alone.
# --------------------------------------------------------------------------- #
def _has_volume(row: pd.Series, config: DetectionConfig) -> bool:
    return row["total_connections"] >= config.min_connections


def _horizontal_scan(row, config):
    triggered = _has_volume(row, config) and (
        row["unique_destinations"] >= config.horizontal_min_destinations
    )
    return triggered, (
        f"contacted {int(row['unique_destinations'])} distinct destinations "
        f"(>= {config.horizontal_min_destinations})"
    )


def _vertical_scan(row, config):
    triggered = (
        _has_volume(row, config)
        and row["unique_dst_ports"] >= config.vertical_min_ports
        and row["unique_destinations"] <= config.vertical_max_destinations
    )
    return triggered, (
        f"probed {int(row['unique_dst_ports'])} ports across only "
        f"{int(row['unique_destinations'])} host(s) "
        f"(>= {config.vertical_min_ports} ports on <= {config.vertical_max_destinations} hosts)"
    )


def _block_scan(row, config):
    triggered = (
        _has_volume(row, config)
        and row["unique_destinations"] >= config.block_min_destinations
        and row["unique_dst_ports"] >= config.block_min_ports
    )
    return triggered, (
        f"swept {int(row['unique_dst_ports'])} ports across "
        f"{int(row['unique_destinations'])} hosts "
        f"(block scan: >= {config.block_min_ports} ports x >= {config.block_min_destinations} hosts)"
    )


def _high_port_diversity(row, config):
    triggered = _has_volume(row, config) and (
        row["dst_port_ratio"] >= config.high_port_ratio
    )
    return triggered, (
        f"{row['dst_port_ratio']:.0%} of flows targeted a fresh port "
        f"(>= {config.high_port_ratio:.0%}) - minimal connection reuse"
    )


def _low_connection_reuse(row, config):
    triggered = (
        _has_volume(row, config)
        and row["unique_destinations"] >= config.horizontal_min_destinations
        and 0 < row["conn_per_destination"] <= config.low_conn_per_destination
    )
    return triggered, (
        f"only {row['conn_per_destination']:.2f} connections per destination "
        f"across {int(row['unique_destinations'])} hosts (<= {config.low_conn_per_destination}) "
        f"- each host touched ~once"
    )


def _unknown_service_probing(row, config):
    triggered = _has_volume(row, config) and (
        row["null_service_ratio"] >= config.null_service_ratio_threshold
    )
    return triggered, (
        f"{row['null_service_ratio']:.0%} of flows hit ports with no known service "
        f"(>= {config.null_service_ratio_threshold:.0%})"
    )


def _incomplete_connections(row, config):
    triggered = _has_volume(row, config) and (
        row["incomplete_ratio"] >= config.incomplete_ratio_threshold
    )
    return triggered, (
        f"{row['incomplete_ratio']:.0%} of connections never established "
        f"(>= {config.incomplete_ratio_threshold:.0%}) - half-open / rejected"
    )


# --------------------------------------------------------------------------- #
# The default rule set. Ordered roughly strongest-signal first.
# --------------------------------------------------------------------------- #
DEFAULT_RULES: list[Rule] = [
    Rule(
        name="block_scan",
        category="block",
        weight=3.0,
        predicate=_block_scan,
        description="Many ports probed across many destinations simultaneously.",
    ),
    Rule(
        name="horizontal_scan",
        category="horizontal",
        weight=2.0,
        predicate=_horizontal_scan,
        description="A single source contacting an unusually high number of hosts.",
    ),
    Rule(
        name="vertical_scan",
        category="vertical",
        weight=2.0,
        predicate=_vertical_scan,
        description="Many distinct ports probed on a small number of hosts.",
    ),
    Rule(
        name="high_port_diversity",
        category="behavioural",
        weight=1.5,
        predicate=_high_port_diversity,
        description="Almost every flow targets a new port (scanner low-reuse signature).",
    ),
    Rule(
        name="low_connection_reuse",
        category="behavioural",
        weight=1.0,
        predicate=_low_connection_reuse,
        description="Each destination is contacted roughly once — sweep behaviour.",
    ),
    Rule(
        name="unknown_service_probing",
        category="behavioural",
        weight=1.0,
        predicate=_unknown_service_probing,
        description="High share of flows to ports with no listening service.",
    ),
    Rule(
        name="incomplete_connections",
        category="behavioural",
        weight=1.0,
        predicate=_incomplete_connections,
        description="High share of half-open / rejected connections.",
    ),
]
