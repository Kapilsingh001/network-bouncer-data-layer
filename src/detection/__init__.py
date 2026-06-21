"""Rule-based port-scan detection layer (Dev 2).

Consumes the cleaned flow data from the Dev 1 data layer, derives per-host
behavioural features, and applies a transparent, explainable rule engine to flag
hosts exhibiting scanning / reconnaissance behaviour.
"""

from __future__ import annotations

from src.detection.config import DetectionConfig
from src.detection.detector import (
    HostVerdict,
    RuleBasedDetector,
    detect_scanning,
)
from src.detection.rules import DEFAULT_RULES, Rule, RuleResult

__all__ = [
    "DetectionConfig",
    "RuleBasedDetector",
    "HostVerdict",
    "detect_scanning",
    "DEFAULT_RULES",
    "Rule",
    "RuleResult",
]
